# SMART-HUNTER 

SMART-HUNTER is an automated, Machine Learning-guided web vulnerability and penetration testing tool. It combines deep site reconnaissance, dual-phase ML-driven vulnerability prediction, and active exploitation to provide a comprehensive security assessment of web applications and network services.

## Architecture

The project has been refactored into a modular architecture for better maintainability and performance:

- **`main.py`**: The central orchestrator that manages the scan lifecycle.
- **`Machine_Learning/`**: AI model architecture, training, and vulnerability prediction.
    - `Ai_model.py`: Core ML model training logic and dataset management.
    - `prediction.py`: Dual-phase prediction system (Phase 1: Pre-Recon, Phase 2: Post-Testing).
- **`Recon/`**:
    - `url_connection.py`: Deep site reconnaissance, header analysis, and WAF detection.
- **`vulnerability_scan/`**:
    - `URL_checkIfhaveVun.py`: Integration with Dalfox, SQLMap, and Commix (WSL-compatible).
    - `path_Analyze.py`: Advanced path traversal crawling and scanning.
- **`Data/`**: Centralized storage for datasets, results, and logs.

## Features

- **Dual-Phase ML Prediction**:
  - **Phase 1 (Pre-Recon)**: Initial risk assessment based on URL structure.
  - **Phase 2 (Post-Testing)**: Refined prediction using live reconnaissance features and scan results.
- **Advanced Vulnerability Scanning**:
  - Built-in checkers for SQLi, XSS, and RCE.
  - Seamless integration with **SQLMap**, **Dalfox**, and **Commix** using automated WSL path translation for Windows users.
- **Automated Network Pentesting**:
  - **Nmap** integration for service discovery.
  - **Metasploit** (via `pymetasploit3`) for automated exploitation of detected services.
- **Scalable Reconnaissance**:
  - Intelligent crawling, form extraction, and WAF identification.
  - Directory fuzzing via **ffuf**.

## Requirements

Ensure the required system binaries are installed (mapped via WSL for Windows):

- System Tools: `curl`, `nmap`, `bash`
- Security Tools: `ffuf`, `sqlmap`, `dalfox`, `commix`, `metasploit-framework`

Install Python dependencies:

```bash
pip install -r requrement.txt
```

## Usage

### 1. Smart Web Vulnerability Scanner
To start the ML-guided vulnerability scanner:
```bash
python main.py
```
*The tool will automatically extract cookies (if any), perform dual-phase ML prediction, and orchestrate the scanning modules.*

### 2. Network Exploit Automator
To scan network infrastructure and launch Metasploit exploits:
```bash
python mchine.py
```
*Ensure `msfrpcd` is running before launching this module.*

## Disclaimer
This tool is intended for ethical hacking, security research, and authorized penetration testing only. Do not use this tool against targets without prior mutual consent. The authors and contributors are not responsible for any misuse, damage, or legal consequences caused by this software.
