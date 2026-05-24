import os
import csv
import glob
import re
import uuid

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(BASE_DIR, 'Data', 'Datasets', 'Datasets_for_Model_NLP', 'vulnerability', 'vulnerability_response.csv')
TEMP_PATH = os.path.join(BASE_DIR, 'Data', 'Datasets', 'Datasets_for_Model_NLP', 'vulnerability', 'vulnerability_response_temp.csv')

# Optional: Directory for XXE results if they exist locally
XXE_RESULTS_DIR = os.path.join(BASE_DIR, 'xxe_results')

def is_xxe_vulnerable(text):
    text_lower = text.lower()
    if re.search(r'(root:|nobody:|daemon:|www-data:|sshd:|nologin|/bin/bash|/bin/sh)', text_lower): return 1
    if re.search(r'(xml|parse|syntax|unexpected|element|tag|sax|dom|javax\.xml|lxml|simplexml|domdocument)', text_lower) and 'error' in text_lower: return 1
    if 'xxe_entity_resolved_ok' in text_lower or 'ct_switch_ok' in text_lower: return 1
    if re.search(r'(iam|security-credentials|accesskeyid|secretaccesskey)', text_lower): return 1
    return 0

def update_dataset():
    if not os.path.exists(DATASET_PATH):
        print(f"[-] Dataset {DATASET_PATH} not found.")
        return

    # Phase 1: Add 'xxe' column if not exists
    with open(DATASET_PATH, 'r', encoding='utf-8', errors='ignore') as infile:
        reader = csv.reader(infile)
        header = next(reader, None)
        if not header: return

        has_xxe = 'xxe' in header
        if not has_xxe:
            header.append('xxe')

        with open(TEMP_PATH, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(header)
            
            for row in reader:
                if not row: continue
                if not has_xxe:
                    row.append('0')
                writer.writerow(row)
                
    os.replace(TEMP_PATH, DATASET_PATH)
    print("[+] Added 'xxe' column with default value 0 to dataset.")

    # Phase 2: Append XXE scanner results
    search_pattern = os.path.join(XXE_RESULTS_DIR, 'scan_*', 'response_*.txt')
    response_files = glob.glob(search_pattern)
    
    if not response_files:
        print("[-] No XXE scanner responses found to import.")
        return

    added_count = 0
    with open(DATASET_PATH, 'a', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        for filepath in response_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as rf:
                    content = rf.read()
                    if not content.strip(): 
                        continue
                    
                    xxe_flag = is_xxe_vulnerable(content)
                    
                    # Create a row matching the header length
                    # Status_Code,Response_Time_ms,Response_Headers_Text,Response_Body_Snippet,Error_Signatures_Text,Label_Is_Vulnerable,Label_Vuln_Type,Scan_ID,Trace_ID,Baseline_Trace_ID,Source_Module,Response_Header_Raw_Ordered_Text,Response_Header_Canonical_Text,Response_Header_Semantic_Text,Response_Security_Headers_Text,Set_Cookie_Semantic_Text,Label_Source,xxe
                    
                    row = [''] * len(header)
                    
                    try:
                        row[header.index('Status_Code')] = '200'
                    except: pass
                    try:
                        row[header.index('Response_Time_ms')] = '0'
                    except: pass
                    try:
                        row[header.index('Response_Body_Snippet')] = content[:1000]
                    except: pass
                    try:
                        row[header.index('Label_Is_Vulnerable')] = str(xxe_flag)
                    except: pass
                    try:
                        row[header.index('Label_Vuln_Type')] = 'xxe'
                    except: pass
                    try:
                        row[header.index('Trace_ID')] = str(uuid.uuid4().hex)
                    except: pass
                    try:
                        row[header.index('Source_Module')] = 'xxe_scanner'
                    except: pass
                    try:
                        row[header.index('xxe')] = str(xxe_flag)
                    except: pass
                    
                    writer.writerow(row)
                    added_count += 1
            except Exception as e:
                pass
                
    print(f"[+] Successfully added {added_count} XXE responses to the dataset.")

if __name__ == '__main__':
    update_dataset()
