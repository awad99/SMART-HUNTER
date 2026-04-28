import subprocess
import os
import sys

# Add the project root and necessary subdirectories to sys.path to allow importing from top-level packages
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(root, "Data")
TARGET_FILE = os.path.join(DATA_DIR, "targets.txt")
FULLSCAN_PATH = os.path.join(UI_DIR, "FullScan.py")

if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "Recon", "vulnerability_scan"))


def read_target_urls():
    print("\n[*] MULTI-TARGET SCANNER")
    print("[*] Enter target URLs (one per line).")
    print("[*] Press Enter twice or leave blank and press Enter to finish.")
    urls = []
    while True:
        try:
            line = input("> ").strip()
            if not line:
                break
            if line.startswith("http"):
                urls.append(line)
                print(f"    [+] Added: {line}")
            else:
                print(f"    [-] Invalid URL (must start with http/https): {line}")
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n    [-] Input cancelled.")
            sys.exit(0)

    # Save URLs to Data/target.txt
    if urls:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TARGET_FILE, "w") as f:
            for url in urls:
                f.write(url + "\n")
        print(f"    [+] Saved {len(urls)} URL(s) to {TARGET_FILE}")

    return urls

def generate_auto_input(url):
    input_sequence = [url]
    for _ in range(50):
        input_sequence.extend(["y", "all", "y"])
    return "\n".join(input_sequence) + "\n"

def run_scanner_for_target(url, idx, total_count):
    print(f"{'='*60}")
    print(f"[*] [{idx}/{total_count}] Executing FullScan.py for target: {url}")
    print(f"{'='*60}")
    
    input_data = generate_auto_input(url)
    
    try:
        subprocess.run(
            [sys.executable, FULLSCAN_PATH],
            input=input_data,
            text=True,
            cwd=UI_DIR
        )
    except Exception as e:
        print(f"[-] Error occurred while running FullScan.py for {url}: {e}")
        
    print(f"\n[*] Finished with target: {url}\n")

def main():
    urls = read_target_urls()
    
    if not urls:
        print("[-] No valid URLs provided. Exiting.")
        return
    
    print(f"\n[*] Starting automated scans for {len(urls)} target(s)...\n")

    for idx, url in enumerate(urls, 1):
        run_scanner_for_target(url, idx, len(urls))

if __name__ == "__main__":
    main()
