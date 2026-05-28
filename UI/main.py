import sys
import os
import subprocess


def _configure_utf8_stdio():
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_configure_utf8_stdio()

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "Data"))

import FullScan 
import Mulit_Scan 
import xss_scan, sqli_scan, rce_scan, idor_scan, xxe_scan, csrf_scan


def display_banner():
    print(FullScan.msg)

def helpOption():
    print("\n--- Help Menu ---")
    print("1. FULL Scan: Run the complete vulnerability scan (FullScan.py) on a single target.")
    print("2. Scan One Vulnerability: Target a specific vulnerability type manually.")
    print("3. Scan Multi Target: Run automated scans on multiple URLs (from train.txt).")
    print("4. Help: Display this message.")
    print("5. Exit: Close the application.")
    print("-----------------\n")

def ScanOneVunlibilti():
    print("\n--- Select Vulnerability to Scan ---")
    print("1. XSS")
    print("2. SQLi")
    print("3. RCE")
    print("4. IDOR")
    print("5. XXE")
    print("6. CSRF")
    print("7. Back to Main Menu")
    choice = input("Select an option (1-7): ").strip()
    
    if choice == '1':
        print("[*] Running XSS Scan...")
        xss_scan.main()  
    elif choice == '2':
        print("[*] Running SQLi Scan...")
        sqli_scan.main()
    elif choice == '3':
        print("[*] Running RCE Scan...")
        rce_scan.main()
    elif choice == '4':
        print("[*] Running IDOR Scan...")
        idor_scan.main()
    elif choice == '5':
        print("[*] Running XXE Scan...")
        xxe_scan.main()
    elif choice == '6':
        print("[*] Running CSRF Scan...")
        csrf_scan.main()
    elif choice == '7':
        return
    else:
        print("[-] Invalid Choice.")

def start_database_service():
    print("[*] Starting PostgreSQL Database...")
    try:
        script_path = os.path.join(root, "Logic", "Recon", "script", "run_database.sh")
        if os.name == 'nt':
            subprocess.run(["wsl", "bash", script_path.replace("\\", "/")])
        else:
            subprocess.run(["bash", script_path])
    except Exception as e:
        print(f"[-] Could not start database: {e}")

def connect_database():
    try:
        script_path = os.path.join(root, "Logic", "Recon", "script", "run_database.sh")
        if os.name == 'nt':
            os.system(f'wsl bash "{script_path.replace(chr(92), "/")}" connect')
        else:
            os.system(f'bash "{script_path}" connect')
    except Exception as e:
        print(f"[-] Could not connect to database: {e}")

def DatabaseSettings():
    while True:
        print("\n--- Database Settings ---")
        print("1. Start Database (Run run_database.sh)")
        print("2. Setup / Initialize Database (Run setup_db.py)")
        print("3. Test Database Connection")
        print("4. Go to Database (Run psql)")
        print("5. Back to Main Menu")
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            start_database_service()
        elif choice == '2':
            print("[*] Running Database Setup...")
            try:
                # pyrefly: ignore [missing-import]
                import setup_db
                success = setup_db.setup()
                if success:
                    print("[+] Database successfully initialized!")
                else:
                    print("[-] Database setup failed.")
            except Exception as e:
                print(f"[-] Error running setup: {e}")
        elif choice == '3':
            print("[*] Testing Database Connection...")
            try:
                from Logic.Recon.database_manager import DatabaseManager
                db = DatabaseManager()
                if db.connect():
                    print("[+] Connection Successful!")
                    db.close()
                else:
                    print("[-] Connection Failed. Please check your settings.")
            except Exception as e:
                print(f"[-] Connection Error: {e}")
        elif choice == '4':
            connect_database()
        elif choice == '5':
            break
        else:
            print("[-] Invalid Choice.")

def MainOptions():
    while True:
        print("\n" + "="*40)
        print("       SMART-HUNTER MAIN MENU")
        print("="*40)
        print("1) FULL scan")
        print("2) Scan One Vulnerability")
        print("3) Scan multi target")
        print("4) Database Settings")
        print("5) Help")
        print("6) Exit")

        print("="*40)
        
        option = input("Enter option (1-6): ").strip()

        if option == '1':
            FullScan.main()
        elif option == '2':
            ScanOneVunlibilti()
        elif option == '3':
            Mulit_Scan.main()
        elif option == '4':
            DatabaseSettings()
        elif option == '5':
            helpOption()
        elif option == '6':
            print("Exiting tool... Goodbye!")
            sys.exit(0)
        else:
            print("[-] Invalid option. Please enter a number between 1 and 6.")

def main():
    display_banner()
    
    # --- Cloud Asset Sync ---
    try:
        from Logic.hf_integration import sync_assets
        sync_assets()
    except Exception as e:
        print(f"[*] Cloud Sync Skipped: {e}")
    # ------------------------

    start_database_service()
    try:
        MainOptions()
    except KeyboardInterrupt:
        print("\nExiting tool... Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()
