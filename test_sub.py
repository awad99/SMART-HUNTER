import subprocess
import sys

cmd = [sys.executable, "-c", "from xsrfprobe import xsrfprobe; import sys; sys.argv[0]='xsrfprobe'; xsrfprobe.startEngine()", "-u", "http://example.com"]
print("Command:", cmd)
try:
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("Return code:", res.returncode)
    print("Stdout:", res.stdout[:500])
    print("Stderr:", res.stderr[:500])
except Exception as e:
    print("Exception:", repr(e))
