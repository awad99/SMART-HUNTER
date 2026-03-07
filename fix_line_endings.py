import os

script_dir = r"c:\Users\awad\Downloads\pyarmor\auto_PenTest\script"
fixed_files = []
for filename in os.listdir(script_dir):
    if filename.endswith(".sh"):
        filepath = os.path.join(script_dir, filename)
        with open(filepath, "rb") as f:
            content = f.read()
        
        # Replace all \r\n with \n, then any remaining \r with \n
        new_content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        
        if new_content != content:
            with open(filepath, "wb") as f:
                f.write(new_content)
            fixed_files.append(filename)

if fixed_files:
    print(f"Fixed line endings in: {', '.join(fixed_files)}")
else:
    print("No files needed fixing.")
