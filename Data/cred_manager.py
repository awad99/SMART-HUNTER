"""
Credential Manager for SMART-HUNTER

Stores and retrieves credentials per-domain in a JSON file.
File location: Data/Credentials/saved_creds.json

Structure:
{
    "example.com": [
        {"username": "admin", "password": "pass123", "login_url": "/login", "added": "2026-05-26 23:00:00", "last_success": "2026-05-26 23:01:00"}
    ],
    ...
}
"""
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDS_DIR = os.path.join(BASE_DIR, "Credentials")
CREDS_FILE = os.path.join(CREDS_DIR, "saved_creds.json")


def _ensure_creds_dir():
    os.makedirs(CREDS_DIR, exist_ok=True)


def load_all_creds():
    """Load all saved credentials from the JSON file."""
    _ensure_creds_dir()
    if not os.path.exists(CREDS_FILE):
        return {}
    try:
        with open(CREDS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_all_creds(data):
    """Write the full credential dictionary to disk."""
    _ensure_creds_dir()
    with open(CREDS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_creds_for_domain(domain):
    """
    Return a list of credential dicts for the given domain.
    Each dict has: username, password, login_url, added, last_success
    """
    all_creds = load_all_creds()
    return all_creds.get(domain, [])


def save_cred(domain, username, password, login_url=''):
    """
    Save a new credential for a domain. Avoids duplicates.
    Returns True if a new credential was saved, False if it already existed.
    """
    all_creds = load_all_creds()

    if domain not in all_creds:
        all_creds[domain] = []

    # Check for duplicate
    for entry in all_creds[domain]:
        if entry['username'] == username and entry['password'] == password:
            return False

    all_creds[domain].append({
        'username': username,
        'password': password,
        'login_url': login_url,
        'added': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_success': '',
    })

    _save_all_creds(all_creds)
    print(f"    [+] Credential saved for {domain}: {username}")
    return True


def mark_cred_success(domain, username, password):
    """Update the last_success timestamp for a credential."""
    all_creds = load_all_creds()
    if domain not in all_creds:
        return

    for entry in all_creds[domain]:
        if entry['username'] == username and entry['password'] == password:
            entry['last_success'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            break

    _save_all_creds(all_creds)


def delete_cred(domain, username):
    """Remove a credential for a domain by username."""
    all_creds = load_all_creds()
    if domain not in all_creds:
        return False

    original_len = len(all_creds[domain])
    all_creds[domain] = [e for e in all_creds[domain] if e['username'] != username]

    if len(all_creds[domain]) < original_len:
        if not all_creds[domain]:
            del all_creds[domain]
        _save_all_creds(all_creds)
        return True
    return False


def list_domains():
    """Return list of all domains that have saved credentials."""
    return list(load_all_creds().keys())


def prompt_for_credentials(domain, module_name="Global"):
    """
    Interactive prompt: ask the user if they want to provide credentials.
    Returns list of (username, password) tuples. Can be empty.
    """
    creds = []
    title = f"{module_name} Authentication"
    text = f"  {title} — Credentials for {domain}  "
    width = len(text)
    print(f"\n    ┌{'─' * width}┐")
    print(f"    │{text}│")
    print(f"    └{'─' * width}┘")

    # Show saved creds first
    saved = get_creds_for_domain(domain)
    if saved:
        print(f"    [*] Found {len(saved)} saved credential(s) for this domain:")
        for i, entry in enumerate(saved, 1):
            last = entry.get('last_success', 'never')
            print(f"        {i}. {entry['username']} (last success: {last or 'never'})")

    try:
        answer = input("\n    [?] Do you want to add credentials? (y/N/skip): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = 'n'

    if answer in ('y', 'yes'):
        print("    [*] Enter credentials (empty username to stop):")
        while True:
            try:
                username = input("        Username: ").strip()
                if not username:
                    break
                password = input("        Password: ").strip()
                if not password:
                    print("        [-] Password cannot be empty, skipping.")
                    continue
                creds.append((username, password))
                # Save immediately
                save_cred(domain, username, password)
                more = input("        Add another? (y/N): ").strip().lower()
                if more not in ('y', 'yes'):
                    break
            except (EOFError, KeyboardInterrupt):
                break

    return creds
