import glob, os, time
import Recon.url_connection as url_connection
from Mchine_Learning.Ai_model import VulnerabilityCheckerTraining, MODEL_FILE

def get_historical_urls():
    urls = set()
    files = glob.glob(os.path.join(os.path.dirname(__file__), 'Data', 'vuln_scan_*', 'target_urls.txt'))
    for f in files:
        try:
            with open(f, 'r') as file:
                for line in file:
                    parts = line.strip().split('|')
                    if len(parts) >= 2:
                        urls.add(parts[1])
        except Exception as e:
            print(f"[-] Error reading {f}: {e}")
    return list(urls)

def main():
    urls = get_historical_urls()
    print(f"[*] Found {len(urls)} historical URLs to process into the ML dataset")
    print(f"[*] This will significantly improve model accuracy with real-world target data.\n")
    
    success = 0
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] Processing: {url}")
        try:
            if url_connection.MainRecon(url, cookie=None):
                success += 1
            time.sleep(0.5)
        except Exception as e:
            print(f"[-] Failed to process {url}: {e}")
            
    print(f"\n[*] Finished processing {len(urls)} URLs. Successfully reconned: {success}")
    
    print("\n[*] Retraining ML Model with new data...")
    trainer = VulnerabilityCheckerTraining()
    trainer.train_model()
    trainer.save_model()
    print("[+] Done!")

if __name__ == "__main__":
    main()
