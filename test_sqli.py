import subprocess
import time

def run_sqli():
    print("Testing SQLi Scanner on Lab...")
    process = subprocess.Popen(
        ['python', 'main.py'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='replace'
    )

    inputs = [
        "2\n",  # Scan One Vulnerability
        "2\n",  # SQLi
        "https://0a5500a1036311f480dc80d1003e00c5.web-security-academy.net/\n",  # URL
        "\n"    # empty cookie
    ]

    for inp in inputs:
        process.stdin.write(inp)
        process.stdin.flush()
        time.sleep(1)

    out, _ = process.communicate()
    print(out[-2000:])  # print last 2000 chars

run_sqli()
