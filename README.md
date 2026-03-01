# SMART-HUNTER (auto_PenTest)

SMART-HUNTER is an automated, Machine Learning-guided web vulnerability and penetration testing tool. It combines deep site reconnaissance, ML-driven vulnerability prediction, and active exploitation to provide a comprehensive security assessment of web applications and network services.

## Features

- **Machine Learning Vulnerability Prediction (`main.py`)**: 
  - Extracts HTTP/S reconnaissance features from a target URL.
  - Predicts the probability of SQL Injection, Cross-Site Scripting (XSS), and Command Injection using a trained Random Forest model.
  - Generates targeted vulnerability attacks based on the ML risk assessment.

- **Comprehensive URL Vulnerability Scanning (`URL_checkIfhaveVun.py`)**:
  - Incorporates built-in payloads for error-based SQLi, time-based SQLi, XSS, and Command Injection.
  - Integrates seamlessly with popular external security tools:
    - **SQLMap** for advanced SQL injection detection and exploitation.
    - **Dalfox** for fast and efficient XSS parameter scanning.
    - **Commix** for deep command injection execution.
  
- **Automated Network Penetration Testing (`mchine.py`)**:
  - Leverages **Nmap** for quick service and port discovery on a given host.
  - Integrates with **Metasploit** (via `pymetasploit3`) to intelligently search, select, and launch exploits based on the exact detected software versions and open ports.

- **Deep Web Reconnaissance & Fuzzing (`url_connection.py`)**:
  - Crawls URLs to collect headers, cookies, redirect chains, and input forms.
  - Performs intelligent WAF detection.
  - Conducts directory and file fuzzing utilizing **ffuf**.

- **Interactive Command Injection Shell (`App.py`)**:
  - A specific utility to brute force command injection vulnerabilities within forms and URL parameters.
  - Capable of spawning an interactive command-line reverse shell upon successful exploitation.

## Requirements

Ensure the required system binaries are installed and accessible in your system `PATH`:

- System Tools: `curl`, `nmap`
- Security Tools: `ffuf`, `sqlmap`, `dalfox`, `commix`, `metasploit-framework` (run `msfrpcd` to enable `mchine.py`)

Install the required Python dependencies:

```bash
pip install -r requirements.txt
```

*(Key modules required: `pandas`, `numpy`, `scikit-learn`, `httpx`, `requests`, `bs4`, `pymetasploit3`, `python-nmap`)*

## Usage

### 1. Smart Web Vulnerability Scanner
To start the ML-guided vulnerability scanner against a target URL:
```bash
python main.py
```
*You will be prompted to enter the target URL or IP address. The ML model (`vulnerability_model.pkl`) will be trained automatically on first run if it does not yet exist.*

### 2. Network Exploit Automator
To scan network infrastructure and fire automatic Metasploit exploits:
```bash
python mchine.py
```
*Ensure the Metasploit RPC daemon (`msfrpcd`) is running before launching this module.*

### 3. Command Injection Hunter & Shell
To quickly target a URL specifically for command injection and get an interactive shell upon compromise:
```bash
python App.py
```

## Structure
- `main.py`: Entry point for the ML-guided scanner.
- `App.py`: Targeted command injection scanner and interactive shell client.
- `URL_checkIfhaveVun.py`: Core logic for initiating vulnerability payload testing (XSS, SQLi, CMDi).
- `url_connection.py`: Handles HTTP/S requests, site enumeration, WAF detection, and fuzzing execution.
- `mchine.py`: The network scanning and automated Metasploit exploitation module.
- `vulnerability_model.pkl`: The serialized Random Forest model used for making probability-based security risk assessments.

## Disclaimer
This tool is intended for ethical hacking, security research, and authorized penetration testing only. Do not use this tool against targets without prior mutual consent. The authors and contributors are not responsible for any misuse, damage, or legal consequences caused by this software.
