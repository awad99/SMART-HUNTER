import os
import re

def extract_paths_from_analysis(analysis_file_path):
    """Read response analysis file and extract paths with parameters from FORMS ANALYSIS"""
    paths_with_params = []
    
    try:
        with open(analysis_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract base URL from the file
        base_url_match = re.search(r'Target URL:\s*(https?://[^\s]+)', content)
        if base_url_match:
            base_url = base_url_match.group(1)
        else:
            print("[-] Could not find base URL in analysis file")
            return []
        
        # Extract forms section
        forms_section = re.search(r'FORMS ANALYSIS:.*?(?=BUTTONS ANALYSIS:|\Z)', content, re.DOTALL)
        if forms_section:
            forms_text = forms_section.group(0)
            
            # Extract each form's inputs
            form_blocks = re.findall(r'Form \d+:.*?(?=Form \d+:|\Z)', forms_text, re.DOTALL)
            
            for form_block in form_blocks:
                # Extract inputs from form
                inputs_match = re.search(r'Inputs:\s*\[([^\]]+)\]', form_block)
                if inputs_match:
                    inputs_str = inputs_match.group(1)
                    # Clean and extract parameter names
                    params = [param.strip().strip("'") for param in inputs_str.split(',')]
                    
                    # Generate URL with parameters
                    if params:
                        param_string = "&".join([f"{param}=" for param in params])
                        path_with_params = f"{base_url}?{param_string}"
                        paths_with_params.append(path_with_params)
        
        print(f"[+] Extracted {len(paths_with_params)} paths with parameters:")
        for path in paths_with_params:
            print(f"    {path}")
        
        return paths_with_params
        
    except FileNotFoundError:
        print(f"[-] Analysis file not found: {analysis_file_path}")
        return []
    except Exception as e:
        print(f"[-] Error reading analysis file: {e}")
        return []

def get_paths_with_parameters():
    """Get paths with parameters from analysis file"""
    # You'll need to specify the correct path to your analysis file
    analysis_file = "response_analysis.txt"  # Update this path if needed
    return extract_paths_from_analysis(analysis_file)

# Usage
if __name__ == "__main__":
    paths = get_paths_with_parameters()
    print("Final paths:", paths)