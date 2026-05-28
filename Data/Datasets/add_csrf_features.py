import os

directory = r"C:\Users\awad\Downloads\SMART-HUNTER-main\SMART-HUNTER-main\Data\Datasets"

count = 0
for root, _, files in os.walk(directory):
    for filename in files:
        if filename.endswith(".csv"):
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                if not lines:
                    continue
                    
                header = lines[0].rstrip('\n')
                
                if "total_vulnerabilities" in header:
                    header_parts = header.split(',')
                    to_append_header = []
                    to_append_data = []
                    
                    if "has_xxe" not in header_parts:
                        to_append_header.append("has_xxe")
                        to_append_data.append("0")
                        
                    if "has_csrf" not in header_parts:
                        to_append_header.append("has_csrf")
                        to_append_data.append("0")
                    
                    if to_append_header:
                        lines[0] = header + "," + ",".join(to_append_header) + "\n"
                        for i in range(1, len(lines)):
                            line = lines[i].rstrip('\n')
                            if line:
                                lines[i] = line + "," + ",".join(to_append_data) + "\n"
                            else:
                                lines[i] = "\n"
                        
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.writelines(lines)
                        count += 1
            except Exception as e:
                print(f"Error processing {filepath}: {e}")

print(f"Successfully updated {count} CSV files with new features.")
