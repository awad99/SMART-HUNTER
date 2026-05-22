<div align="center">

# 🎯 SMART-HUNTER

**An Automated, Machine Learning-Guided Web Vulnerability & Penetration Testing Framework**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*SMART-HUNTER combines deep site reconnaissance, dual-phase machine learning vulnerability prediction, and active exploitation to provide a comprehensive security assessment of web applications and network services.*

</div>

---

## 🌟 Overview

SMART-HUNTER is designed for security researchers and penetration testers who need an intelligent, automated workflow. It doesn't just blindly send payloads; it analyzes the target structure, predicts likely vulnerabilities using trained ML models, and orchestrates specialized scanners (like SQLMap, Dalfox, and Commix) to confirm and exploit findings.

## 🚀 Key Features

### 🧠 Dual-Phase Machine Learning Prediction
- **Phase 1 (Pre-Recon):** Initial risk assessment based purely on URL structures and parameters.
- **Phase 2 (Post-Testing):** Refined vulnerability prediction utilizing live reconnaissance features, WAF detection, and active scan results.

### 🛡️ Advanced Vulnerability Scanning
Built-in and integrated scanners targeting critical web vulnerabilities:
- **SQL Injection (SQLi):** Comprehensive checks including Error-based, Boolean-based, Time-based, UNION-based, and **Out-of-Band (OOB) DNS Exfiltration** (with native *Interactsh* and *Burp Collaborator* support).
- **Cross-Site Scripting (XSS):** Reflected, Stored, and DOM-based XSS scanning.
- **Remote Code Execution (RCE):** Command injection checks via native payloads and Commix.
- **Insecure Direct Object Reference (IDOR):** Automated enumeration and authorization bypass testing.
- **Path Traversal:** Advanced directory traversal crawling and LFI/RFI scanning.

### 🔌 Seamless Tool Integration (WSL Compatible)
SMART-HUNTER natively wraps industry-standard tools, automatically handling Windows Subsystem for Linux (WSL) path translations for Windows users:
- **SQLMap** for advanced SQL injection.
- **Dalfox** for fast XSS scanning.
- **Commix** for OS command injection.
- **Metasploit Framework** (`pymetasploit3`) for network vulnerability exploitation.
- **Nmap** for service discovery.
- **FFuF** for rapid directory and parameter fuzzing.

### 🕵️ Scalable Reconnaissance
- Intelligent crawling and form extraction.
- Automatic session/cookie extraction and CSRF token handling.
- WAF (Web Application Firewall) identification.

---

## 📂 Architecture

The project has been refactored into a highly modular architecture:

```text
SMART-HUNTER/
├── main.py                    # Main orchestrator entry point
├── UI/                        # User Interfaces & Scan Launchers
│   ├── FullScan.py            # Comprehensive pipeline scanner
│   ├── sqli_scan.py           # Standalone SQLi scanner
│   └── ...                    # Other standalone modules
├── Logic/                     # Core Business Logic
│   ├── vulnerability_scan/    # Active scanners (SQLi, XSS, RCE, IDOR, Path)
│   └── Recon/                 # Reconnaissance & Network tools
├── Data/                      # Storage
│   ├── Machine_Learning/      # ML models, training logic, and datasets
│   ├── Payloads/              # Canonical JSON and TXT payload dictionaries
│   └── Queries/               # Database interaction scripts
└── README.md                  
```

---

## 🛠️ Requirements & Installation

### System Dependencies
Ensure the following tools are installed (if running on Windows, these should be accessible via WSL):
- `curl`, `bash`
- `nmap`
- `ffuf`, `sqlmap`, `dalfox`, `commix`
- `metasploit-framework`
- `interactsh-client` *(Optional: highly recommended for automated OOB SQLi testing)*

### Python Setup
Clone the repository and install the dependencies:

```bash
git clone https://github.com/awad99/SMART-HUNTER.git
cd SMART-HUNTER
pip install -r requirements.txt
```

---

## 💻 Usage

SMART-HUNTER provides both a unified pipeline and standalone modules for targeted testing.

### 1. Smart Web Vulnerability Scanner (Full Pipeline)
Run the complete ML-guided scanner against a target URL or IP. This module will automatically handle recon, parameter discovery, ML prediction, and active scanning.

```bash
python main.py
# or
python UI/FullScan.py
```
*The tool will prompt for the target URL. By default, it will automatically attempt to extract session cookies and perform OOB SQLi testing via Interactsh.*

### 2. Standalone Targeted Scanners
If you only want to test for specific vulnerabilities, use the standalone UI modules.

**Example: Standalone SQLi Scanner**
```bash
python UI/sqli_scan.py "https://target.com/page.php?id=1" --oob --interactsh
```
**Flags:**
- `--cookie`: Provide a session cookie (e.g., `"TrackingId=xyz; session=abc"`)
- `--thorough`: Force SQLMap to run even if the built-in scanner already confirms a vulnerability.
- `--oob`: Enable Out-of-Band (DNS exfiltration) SQLi scanning.
- `--interactsh`: Automatically launch the `interactsh-client` to detect OOB callbacks.
- `--collaborator <domain>`: Use a manual callback domain (e.g., your Burp Collaborator payload URL) instead of Interactsh.

### 3. Network Exploit Automator
To scan network infrastructure and automatically launch Metasploit exploits:
```bash
python UI/machine.py
```
*(Note: Ensure `msfrpcd` is running locally before launching this module).*

---

## ⚠️ Disclaimer

**SMART-HUNTER is intended for ethical hacking, security research, and authorized penetration testing only.** 

Do not use this tool against targets, networks, or applications without prior, explicit, and mutual consent from the owner. The authors and contributors are not responsible for any misuse, damage, or legal consequences caused by this software. Use it responsibly!

---

<div align="center">
<i>Built with by awad99 and datawithakram</i>
</div>
