#!/usr/bin/env python3
"""
Data Structure Analyzer for Penetration Testing Results
Analyzes folder structure and files to understand the data organization
"""

import os
import json
import csv
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

# Base path
BASE_PATH = os.path.join(os.getcwd(), "Data")

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text, color=Colors.RESET):
    """Print colored text"""
    print(f"{color}{text}{Colors.RESET}")

def analyze_file(file_path):
    """Analyze a single file and return its properties"""
    properties = {
        "path": file_path,
        "name": os.path.basename(file_path),
        "extension": os.path.splitext(file_path)[1].lower(),
        "size_kb": os.path.getsize(file_path) / 1024,
        "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
    }
    
    # Try to read content based on extension
    try:
        if properties["extension"] == ".csv":
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                properties["columns"] = reader.fieldnames
                properties["row_count"] = sum(1 for _ in reader)
                # Get sample data
                f.seek(0)
                reader = csv.DictReader(f)
                properties["sample"] = [row for i, row in enumerate(reader) if i < 3]
                
        elif properties["extension"] == ".json":
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    properties["keys"] = list(data.keys())
                    properties["type"] = "object"
                    # Get sample of nested structure
                    for key, value in list(data.items())[:3]:
                        if isinstance(value, list):
                            properties[f"{key}_count"] = len(value)
                            if len(value) > 0:
                                properties[f"{key}_sample"] = value[:2]
                        elif isinstance(value, dict):
                            properties[f"{key}_keys"] = list(value.keys())[:5]
                elif isinstance(data, list):
                    properties["type"] = "array"
                    properties["count"] = len(data)
                    properties["sample"] = data[:3]
                    
        elif properties["extension"] == ".txt":
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                properties["line_count"] = len(lines)
                # Get first 10 lines for sample
                properties["preview"] = [line.strip() for line in lines[:10] if line.strip()]
                # Detect if it contains URLs
                url_lines = [line for line in lines if 'http://' in line or 'https://' in line]
                if url_lines:
                    properties["has_urls"] = len(url_lines)
                    properties["url_sample"] = url_lines[:3]
                    
    except Exception as e:
        properties["error"] = str(e)
    
    return properties

def analyze_folder_structure(base_path):
    """Recursively analyze folder structure"""
    structure = {
        "folders": {},
        "files": [],
        "total_size_kb": 0,
        "file_types": Counter(),
        "patterns": {
            "vuln_scan_folders": [],
            "parameter_files": [],
            "payload_files": [],
            "report_files": [],
            "wordlist_files": [],
            "domain_files": [],
            "security_files": []
        }
    }
    
    for root, dirs, files in os.walk(base_path):
        rel_path = os.path.relpath(root, base_path)
        if rel_path == '.':
            rel_path = 'root'
            
        # Initialize folder entry
        folder_info = {
            "path": root,
            "relative_path": rel_path,
            "files": [],
            "subdirs": dirs,
            "total_files": len(files),
            "total_size_kb": 0
        }
        
        # Analyze each file
        for file in files:
            file_path = os.path.join(root, file)
            file_info = analyze_file(file_path)
            folder_info["files"].append(file_info)
            folder_info["total_size_kb"] += file_info["size_kb"]
            structure["total_size_kb"] += file_info["size_kb"]
            structure["file_types"][file_info["extension"]] += 1
            
            # Pattern matching for specific file types
            file_lower = file.lower()
            if "vuln_scan" in root and "vuln_scan" in file_lower:
                structure["patterns"]["vuln_scan_folders"].append(file_path)
            if "parameter" in file_lower or "param" in file_lower:
                structure["patterns"]["parameter_files"].append(file_path)
            if "payload" in file_lower:
                structure["patterns"]["payload_files"].append(file_path)
            if "report" in file_lower:
                structure["patterns"]["report_files"].append(file_path)
            if "wordlist" in file_lower or "wordlist" in root:
                structure["patterns"]["wordlist_files"].append(file_path)
            if "domain" in file_lower or "subdomain" in file_lower:
                structure["patterns"]["domain_files"].append(file_path)
            if "security" in root or "header" in file_lower:
                structure["patterns"]["security_files"].append(file_path)
        
        structure["folders"][rel_path] = folder_info
    
    return structure

def find_target_urls(structure):
    """Find potential target URLs across all files"""
    targets = []
    
    # Check for specific target files
    target_files = [
        "train.txt", "target.txt", "urls.txt", 
        "fuzzing_Target.txt", "master_vulnerability_data.csv"
    ]
    
    for folder_name, folder_info in structure["folders"].items():
        for file_info in folder_info["files"]:
            file_name = file_info["name"].lower()
            
            # Check for target files
            if any(tf in file_name for tf in target_files):
                if file_info["extension"] == ".csv":
                    # Extract URLs from CSV
                    if "sample" in file_info and file_info["sample"]:
                        for row in file_info["sample"]:
                            if "url" in row:
                                targets.append({
                                    "source": file_info["path"],
                                    "url": row["url"],
                                    "type": "csv"
                                })
                elif file_info["extension"] == ".txt":
                    if "url_sample" in file_info:
                        for url in file_info["url_sample"]:
                            targets.append({
                                "source": file_info["path"],
                                "url": url.strip(),
                                "type": "text"
                            })
    
    return targets

def generate_report(structure, targets):
    """Generate a comprehensive analysis report"""
    report = {
        "summary": {
            "total_folders": len(structure["folders"]),
            "total_files": sum(len(f["files"]) for f in structure["folders"].values()),
            "total_size_mb": structure["total_size_kb"] / 1024,
            "file_types": dict(structure["file_types"]),
            "vuln_scan_folders": len(structure["patterns"]["vuln_scan_folders"]),
            "parameter_files": len(structure["patterns"]["parameter_files"]),
            "payload_files": len(structure["patterns"]["payload_files"]),
            "report_files": len(structure["patterns"]["report_files"]),
            "targets_found": len(targets)
        },
        "folder_hierarchy": {},
        "critical_files": [],
        "database_mapping": {},
        "recommendations": []
    }
    
    # Build folder hierarchy
    for rel_path, folder_info in structure["folders"].items():
        if rel_path != "root":
            report["folder_hierarchy"][rel_path] = {
                "files_count": len(folder_info["files"]),
                "size_kb": folder_info["total_size_kb"],
                "file_names": [f["name"] for f in folder_info["files"][:10]]
            }
    
    # Identify critical files for database upload
    critical_patterns = {
        "recon_data": ["request_headers.txt", "response_headers.txt"],
        "vulnerabilities": ["master_vulnerability_data.csv", "blind_sqli_report", "sqli_report"],
        "features": ["master_vulnerability_data.csv"],
        "parameters": ["Parameters"],
        "network_scans": ["nmap", "masscan"],
        "domains": ["discovered_urls.txt", "subdomains.txt"]
    }
    
    for folder_name, folder_info in structure["folders"].items():
        for file_info in folder_info["files"]:
            file_path = file_info["path"]
            file_name = file_info["name"]
            
            # Check each pattern
            for category, patterns in critical_patterns.items():
                for pattern in patterns:
                    if pattern in file_name or pattern in folder_name:
                        report["critical_files"].append({
                            "category": category,
                            "file": file_path,
                            "type": file_info["extension"],
                            "size_kb": file_info["size_kb"],
                            "details": file_info.get("columns", file_info.get("keys", file_info.get("line_count", "N/A")))
                        })
                        break
    
    # Generate database mapping suggestions
    report["database_mapping"] = {
        "targets": {
            "source": "URLs from train.txt, fuzzing_Target.txt, or CSV files",
            "found_in": [t["source"] for t in targets[:3]],
            "sample_urls": [t["url"] for t in targets[:5]]
        },
        "scans": {
            "source": "Folder names like vuln_scan_YYYYMMDD_HHMMSS",
            "folders": structure["patterns"]["vuln_scan_folders"][:5]
        },
        "recon_data": {
            "source": "request_headers.txt files",
            "files": [f["file"] for f in report["critical_files"] if f["category"] == "recon_data"]
        },
        "vulnerabilities": {
            "source": "CSV files, SQLi reports, parameter files",
            "files": [f["file"] for f in report["critical_files"] if f["category"] == "vulnerabilities"]
        },
        "features": {
            "source": "CSV files with boolean columns",
            "files": [f["file"] for f in report["critical_files"] if f["category"] == "features"]
        },
        "network_scans": {
            "source": "Nmap/Masscan output files",
            "files": [f["file"] for f in report["critical_files"] if f["category"] == "network_scans"]
        }
    }
    
    # Generate recommendations
    if not report["critical_files"]:
        report["recommendations"].append("No critical files found. Check if scan results are in the correct location.")
    
    if not targets:
        report["recommendations"].append("No target URLs found. Ensure train.txt or target.txt exists.")
    
    if not structure["patterns"]["vuln_scan_folders"]:
        report["recommendations"].append("No vuln_scan folders found. Expected pattern: vuln_scan_YYYYMMDD_HHMMSS")
    
    if report["summary"]["parameter_files"] > 0:
        report["recommendations"].append(f"Found {report['summary']['parameter_files']} parameter files. These should be uploaded to vulnerabilities table as potential vulnerabilities.")
    
    if report["summary"]["payload_files"] > 0:
        report["recommendations"].append(f"Found {report['summary']['payload_files']} payload files. These can be used as payload data in vulnerabilities.")
    
    # Add specific mapping recommendations based on actual files
    for folder_name, folder_info in structure["folders"].items():
        if "Parameters" in folder_name:
            report["recommendations"].append(f"Parameters folder found at '{folder_name}'. Files in this folder should be mapped to vulnerabilities with tool_used='param_discovery'.")
        
        if "Payloads" in folder_name:
            report["recommendations"].append(f"Payloads folder found at '{folder_name}'. These contain testing payloads.")
        
        if "domains" in folder_name:
            report["recommendations"].append(f"Domains folder found at '{folder_name}'. discovered_urls.txt and subdomains.txt should be used for features extraction.")
    
    return report

def print_report(report):
    """Print the analysis report in a readable format"""
    print_colored("\n" + "="*80, Colors.BOLD)
    print_colored("DATA STRUCTURE ANALYSIS REPORT", Colors.BOLD)
    print_colored("="*80, Colors.BOLD)
    
    # Summary
    print_colored("\nًں“ٹ SUMMARY", Colors.GREEN)
    print_colored(f"  Total Folders: {report['summary']['total_folders']}", Colors.CYAN)
    print_colored(f"  Total Files: {report['summary']['total_files']}", Colors.CYAN)
    print_colored(f"  Total Size: {report['summary']['total_size_mb']:.2f} MB", Colors.CYAN)
    print_colored(f"  File Types: {report['summary']['file_types']}", Colors.CYAN)
    print_colored(f"  Vuln Scan Folders: {report['summary']['vuln_scan_folders']}", Colors.CYAN)
    print_colored(f"  Parameter Files: {report['summary']['parameter_files']}", Colors.CYAN)
    print_colored(f"  Payload Files: {report['summary']['payload_files']}", Colors.CYAN)
    print_colored(f"  Report Files: {report['summary']['report_files']}", Colors.CYAN)
    print_colored(f"  Targets Found: {report['summary']['targets_found']}", Colors.CYAN)
    
    # Folder Hierarchy
    if report["folder_hierarchy"]:
        print_colored("\nًں“پ FOLDER HIERARCHY", Colors.GREEN)
        for path, info in list(report["folder_hierarchy"].items())[:10]:
            print_colored(f"  {path}/", Colors.BLUE)
            print_colored(f"    Files: {info['files_count']}, Size: {info['size_kb']:.2f} KB", Colors.CYAN)
            if info['file_names']:
                print_colored(f"    First files: {', '.join(info['file_names'][:5])}", Colors.CYAN)
    
    # Targets Found
    if report["database_mapping"]["targets"]["sample_urls"]:
        print_colored("\nًںژ¯ TARGETS FOUND", Colors.GREEN)
        for i, url in enumerate(report["database_mapping"]["targets"]["sample_urls"][:5], 1):
            print_colored(f"  {i}. {url}", Colors.CYAN)
        print_colored(f"  Source files: {report['database_mapping']['targets']['found_in']}", Colors.CYAN)
    
    # Critical Files
    if report["critical_files"]:
        print_colored("\nâڑ ï¸ڈ  CRITICAL FILES (For Database Upload)", Colors.GREEN)
        categories = defaultdict(list)
        for item in report["critical_files"]:
            categories[item["category"]].append(item)
        
        for category, files in categories.items():
            print_colored(f"\n  [{category.upper()}]", Colors.YELLOW)
            for file in files[:5]:
                print_colored(f"    â€¢ {os.path.basename(file['file'])}", Colors.CYAN)
                print_colored(f"      Size: {file['size_kb']:.2f} KB | Type: {file['type']}", Colors.CYAN)
                if file['details']:
                    print_colored(f"      Details: {file['details']}", Colors.CYAN)
    
    # Database Mapping
    print_colored("\nًں—„ï¸ڈ  DATABASE MAPPING SUGGESTIONS", Colors.GREEN)
    for table, mapping in report["database_mapping"].items():
        print_colored(f"\n  â†’ {table}:", Colors.YELLOW)
        print_colored(f"    Source: {mapping['source']}", Colors.CYAN)
        if mapping.get('files') and mapping['files']:
            print_colored(f"    Files found: {len(mapping['files'])}", Colors.CYAN)
    
    # Recommendations
    if report["recommendations"]:
        print_colored("\nًں’، RECOMMENDATIONS", Colors.GREEN)
        for i, rec in enumerate(report["recommendations"], 1):
            print_colored(f"  {i}. {rec}", Colors.CYAN)
    
    print_colored("\n" + "="*80, Colors.BOLD)
    print_colored("Analysis Complete", Colors.BOLD)
    print_colored("="*80, Colors.BOLD)

def save_report_to_file(report, filename="data_analysis_report.json"):
    """Save the report to a JSON file"""
    output_path = os.path.join(os.getcwd(), filename)
    
    # Convert non-serializable objects
    def serialize(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=serialize)
    
    print_colored(f"\nًں“„ Full report saved to: {output_path}", Colors.GREEN)
    return output_path

def main():
    """Main function"""
    print_colored("\nًں”چ Starting Data Structure Analysis...", Colors.BOLD)
    
    # Check if Data directory exists
    if not os.path.exists(BASE_PATH):
        print_colored(f"\nâ‌Œ Error: Data directory not found at {BASE_PATH}", Colors.RED)
        print_colored("Please make sure you're running this script from the correct directory.", Colors.YELLOW)
        return
    
    print_colored(f"ًں“‚ Analyzing: {BASE_PATH}", Colors.BLUE)
    
    # Analyze structure
    structure = analyze_folder_structure(BASE_PATH)
    
    # Find targets
    targets = find_target_urls(structure)
    
    # Generate report
    report = generate_report(structure, targets)
    
    # Print report
    print_report(report)
    
    # Save report to file
    report_file = save_report_to_file(report)
    
    print_colored(f"\nâœ… Analysis complete!", Colors.GREEN)
    print_colored(f"Please share the file '{report_file}' so I can understand your data structure perfectly.", Colors.YELLOW)

if __name__ == "__main__":
    main()