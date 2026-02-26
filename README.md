# dvwa_final.py
STEC 4500, Impossible not included
================================================================================
DVWA AI-ASSISTED VULNERABILITY ASSESSMENT SCRIPT
================================================================================
Programmed By: Gavin Pandha

DESCRIPTION
-----------
An advanced, automated penetration testing tool designed to assess the Damn 
Vulnerable Web Application (DVWA) using a combination of traditional security 
tools (Nmap, SQLMap), web automation (Selenium), and local AI analysis (Ollama).

This tool provides a Gradio-based graphical interface to orchestrate end-to-end 
vulnerability scanning, source code analysis, and payload generation in a 
controlled laboratory environment.



LEGAL & LAB SAFETY WARNING
--------------------------
CAUTION: This script is strictly for educational, research, and authorized 
laboratory use only. Do NOT scan external networks, production systems, or 
any real-world targets without explicit, written permission. CSRF tests 
may temporarily alter configurations within your DVWA instance.

CORE FEATURES
-------------
* Automated Reconnaissance: Runs Nmap version scanning and dynamically 
  cross-references detected services with NVD for CVEs.
* Intelligent Source Code Analysis: Connects via SSH to pull raw PHP source 
  code for specific vulnerabilities (SQLi, XSS, CSRF).
* AI-Powered Exploitation: Uses Ollama LLM (qwen3-coder:30b) to analyze code, 
  map to OWASP/MITRE, and generate tailored payloads.
* Automated Payload Testing: Uses Python requests and authenticated sessions 
  to validate AI-generated payloads against the target.
* SQLMap Integration: Executes backend SQLMap scans for comprehensive 
  database enumeration.
* Comprehensive Reporting: Generates timestamped reports containing executive 
  summaries, threat analysis, and test results.

ENVIRONMENT REQUIREMENTS
------------------------
Requires a dual-machine setup: Host Machine (Python) and Target VM (Kali).

TECH STACK OVERVIEW:
- Python 3.10+ (Host)
- Ollama LLM Engine (Host)
- Selenium + Chrome (Host)
- Kali Linux (Target VM)
- DVWA (Target App)
- Nmap & SQLMap (Target VM)

SETUP & PREREQUISITES
---------------------
1. Host Machine Setup:
   - Create venv: python -m venv venv
   - Install deps: pip install gradio paramiko requests beautifulsoup4 selenium webdriver-manager
   - Start Ollama: ollama serve
   - Pull model: ollama pull qwen3-coder:30b

2. Target VM (Kali Linux) Setup:
   - Tools: sudo apt update && sudo apt install -y nmap sqlmap
   - SSH: sudo systemctl enable ssh && sudo systemctl start ssh
   - Web: sudo systemctl start apache2 && sudo systemctl start mysql
   - Path: Ensure DVWA is at /var/www/html/DVWA

3. SSH Key Authentication:
   - Generate key pair on host.
   - Copy public key to Kali: ~/.ssh/authorized_keys
   - Permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
   - Verify: Ensure passwordless SSH works.

CONFIGURATION VARIABLES
-----------------------
Modify DEFAULT_CONFIG in dvwa_final.py:

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

USAGE
-----
Run the script to launch the Gradio GUI:
> python dvwa_final.py

Follow the GUI prompts to select targets and security levels. Reports are 
saved automatically upon completion.

TROUBLESHOOTING
---------------
- Verify manual SSH connectivity to Kali.
- Ensure 'nmap' is reachable on the Kali machine.
- Verify browser access to http://<KALI_IP>/DVWA.
- Confirm Ollama is running (ollama run qwen3-coder:30b).
- If Selenium fails, update Google Chrome and restart the script.

================================================================================
