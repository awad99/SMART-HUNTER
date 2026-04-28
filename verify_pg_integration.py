import sys
import os

# Add Logic/Recon to path
root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(root, "Logic", "Recon"))

try:
    from database_manager import DatabaseManager
    print("[*] DatabaseManager imported successfully.")
except ImportError as e:
    print(f"[-] Failed to import DatabaseManager: {e}")
    sys.exit(1)

def verify():
    # 1. Test Connection
    print("[*] Testing Postgres connection (localhost:5432, user:postgres)...")
    db = DatabaseManager()
    if not db.connect():
        print("[-] Could not connect to PostgreSQL. Please ensure:")
        print("    1. PostgreSQL is running on localhost:5432")
        print("    2. The database 'smart_hunter' exists (Run setup_db.py first)")
        print("    3. User 'postgres' and password '2002' are correct")
        return

    print("[+] Connection successful!")

    # 2. Test Scan Initialization
    test_scan_id = "test_recon_" + os.urandom(4).hex()
    print(f"[*] Testing scan initialization (ID: {test_scan_id})...")
    try:
        db.create_scan(test_scan_id, "http://example.com", user_agent="TestAgent")
        print(f"[+] Scan record created successfully!")
    except Exception as e:
        print(f"[-] Scan creation failed: {e}")
        return

    # 3. Test Feature Insertion
    print("[*] Testing feature insertion...")
    mock_features = {
        'scan_id': test_scan_id,
        'target_url': "http://example.com/test",
        'is_redirect_response': False,
        'url_length': 25,
        'has_https': False,
        'status_code': 200,
        'response_size': 1024,
        'has_waf': False,
        'is_vulnerable': False
    }
    try:
        db.add_features(mock_features)
        print("[+] Feature data inserted successfully!")
    except Exception as e:
        print(f"[-] Feature insertion failed: {e}")

    # Clean up test scan? (Keep it so user can see it in DB)
    print(f"\n[!] Verification complete! Check your DB for scan_id: {test_scan_id}")
    db.close()

if __name__ == "__main__":
    verify()
