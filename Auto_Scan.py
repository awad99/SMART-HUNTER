import subprocess
import os
import sys

def main():
    train_file = "train.txt"
    
    if not os.path.exists(train_file):
        print(f"[-] {train_file} not found in the current directory.")
        return
        
    with open(train_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    if not urls:
        print(f"[-] No URLs found in {train_file}.")
        return

    print(f"[*] Found {len(urls)} URLs in {train_file}. Starting automated scans...\n")

    for idx, url in enumerate(urls, 1):
        print(f"{'='*60}")
        print(f"[*] [{idx}/{len(urls)}] Executing main.py for target: {url}")
        print(f"{'='*60}")
        
        # Prepare the input to feed to main.py
        # 1. The target URL
        # 2. A sequence of 'y' and 'all' to handle any fuzzing/tool prompts
        input_sequence = [url]
        for _ in range(50):
            input_sequence.append("y")
            input_sequence.append("all")
            input_sequence.append("y")
            
        input_data = "\n".join(input_sequence) + "\n"
        
        try:
            # We use sys.executable to ensure we use the same Python interpreter
            subprocess.run(
                [sys.executable, "main.py"],
                input=input_data,
                text=True
            )
        except Exception as e:
            print(f"[-] Error occurred while running main.py for {url}: {e}")
            
        print(f"\n[*] Finished with target: {url}\n")

if __name__ == "__main__":
    main()
