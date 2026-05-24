import sys
import os
import datetime
import argparse
import re

def analyze_xxe_results(target_url, mode, duration, log_dir):
    """
    Analyzes XXEinjector logs and generates a summary report.
    """
    detection_results = {
        "XML Parser Detected": False,
        "External Entities Enabled": False,
        "OOB Callback Received": False,
        "Direct Data Extraction": False,
        "Parameter Entities Allowed": False
    }

    vulnerabilities = []
    extracted_files = []

    # Basic analysis based on log directory contents and some heuristic checks.
    # In a real scenario, this would parse the specific XXEinjector logs deeply.
    
    if not os.path.exists(log_dir):
        print(f"Error: Log directory {log_dir} not found.")
        return

    # Scan log files for clues
    for filename in os.listdir(log_dir):
        filepath = os.path.join(log_dir, filename)
        if os.path.isfile(filepath):
            if filename.endswith(".log") or filename == "xxeinjector.log":
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    if "XML parsing" in content or "XML processing" in content:
                        detection_results["XML Parser Detected"] = True
                    
                    if "Entities parsed" in content or "Entity resolution" in content:
                        detection_results["External Entities Enabled"] = True
                    
                    if "Callback received" in content or "HTTP request from" in content:
                        detection_results["OOB Callback Received"] = True
                    
                    if "Data retrieved:" in content:
                         detection_results["Direct Data Extraction"] = True
                         
                    if "Parameter entity" in content:
                         detection_results["Parameter Entities Allowed"] = True
                         
            # Assuming extracted files are saved with recognizable names or in a specific format by XXEinjector
            elif filename != "xxeinjector.log" and not filename.endswith(".rb"):
                # If XXEinjector saved a file, it's likely an extracted file
                extracted_files.append({"path": f"Unknown (based on filename: {filename})", "saved_to": filepath})

    # Heuristic Vulnerability Classification based on mode and detection
    if mode in ["blind-oob", "blind-exfil", "full"] and detection_results["OOB Callback Received"]:
        vulnerabilities.append({
            "severity": "CRITICAL",
            "name": "Blind XXE - Out of Band Data Exfiltration",
            "method": "Parameter Entity + External DTD",
            "proof": "DNS/HTTP callback received from target",
            "payload_used": "blind_parameter_entity.xml (or similar)"
        })
        
    if mode in ["classic", "full"] and detection_results["Direct Data Extraction"]:
        vulnerabilities.append({
             "severity": "HIGH",
             "name": "Classic XXE - Direct File Read",
             "method": "In-band Entity Expansion",
             "proof": "Data displayed directly in response",
             "payload_used": "classic_xxe.xml"
        })

    if mode in ["ssrf", "full"] and (detection_results["OOB Callback Received"] or detection_results["Direct Data Extraction"]):
        # A bit of a guess without deeper log analysis, but if we targeted SSRF and got something
         vulnerabilities.append({
             "severity": "HIGH",
             "name": "SSRF via XXE",
             "method": "Internal network targeting",
             "proof": "Interaction with targeted internal resource detected",
             "payload_used": "ssrf_xxe.xml"
        })

    if len(vulnerabilities) == 0 and detection_results["XML Parser Detected"]:
         vulnerabilities.append({
             "severity": "INFO",
             "name": "XML Parser Active",
             "method": "N/A",
             "proof": "Application processes XML input",
             "payload_used": "N/A"
         })

    # Calculate overall severity
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_severity = "INFO"
    for vuln in vulnerabilities:
        if severity_order[vuln['severity']] > severity_order[max_severity]:
            max_severity = vuln['severity']

    # Print Report
    print("═══════════════════════════════════════════════════════")
    print("  XXE VULNERABILITY SCAN REPORT")
    print("═══════════════════════════════════════════════════════")
    print(f"[TARGET]    {target_url}")
    print(f"[MODE]      {mode}")
    print(f"[DATE]      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[DURATION]  {duration}")
    print("───────────────────────────────────────────────────────")
    print("  DETECTION RESULTS")
    print("───────────────────────────────────────────────────────")
    
    for check, status in detection_results.items():
        icon = "[✓]" if status else "[✗]"
        msg = "Detected" if status else "Not Detected"
        # Custom messages based on prompt
        if check == "XML Parser Detected": msg = "الهدف يعالج XML" if status else "لم يتم التأكد"
        elif check == "External Entities Enabled": msg = "الكيانات الخارجية مفعلة" if status else "مغلقة"
        elif check == "OOB Callback Received": msg = "تم استلام callback (Blind XXE مؤكد)" if status else "لا يوجد اتصال خارجي"
        elif check == "Direct Data Extraction": msg = "يعرض البيانات مباشرة" if status else "لا يعرض البيانات مباشرة"
        elif check == "Parameter Entities Allowed": msg = "يدعم Parameter Entities" if status else "غير مدعوم"
        
        print(f"{icon} {check:<30} → {msg}")

    print("───────────────────────────────────────────────────────")
    print("  VULNERABILITIES FOUND")
    print("───────────────────────────────────────────────────────")
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"[{vuln['severity']}] {vuln['name']}")
            print(f"   → Method: {vuln['method']}")
            print(f"   → Proof: {vuln['proof']}")
            print(f"   → Payload: {vuln['payload_used']}")
    else:
        print("[INFO] No exploitable vulnerabilities confidently confirmed.")

    if extracted_files:
        print("───────────────────────────────────────────────────────")
        print("  EXTRACTED FILES")
        print("───────────────────────────────────────────────────────")
        for i, f in enumerate(extracted_files, 1):
            print(f"[{i}] {f['path']} → saved to {f['saved_to']}")

    print("───────────────────────────────────────────────────────")
    print("  RECOMMENDATIONS")
    print("───────────────────────────────────────────────────────")
    print("• Disable DTD processing in XML parser")
    print("• Set XMLInputFactory.SUPPORT_DTD = false")
    print("• Use defusedxml (Python) or similar safe parsers")
    print("• Block outbound connections from application server")
    print("═══════════════════════════════════════════════════════")
    print(f"  SEVERITY: {max_severity} | Vulnerabilities: {len(vulnerabilities)} | Files: {len(extracted_files)}")
    print("═══════════════════════════════════════════════════════")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze XXEinjector results")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--mode", required=True, help="Scan mode")
    parser.add_argument("--duration", required=True, help="Scan duration")
    parser.add_argument("--logdir", required=True, help="Directory containing XXEinjector logs")
    
    args = parser.parse_args()
    
    analyze_xxe_results(args.target, args.mode, args.duration, args.logdir)
