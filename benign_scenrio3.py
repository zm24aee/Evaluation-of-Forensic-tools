import os
import random
import string
import time

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters, k=length))

output_dir="C:\\Forensic\\Scripts\\test_files"
os.makedirs(output_dir, exist_ok=True)
print("[*] Creating files — simulating normal file activity...")
for i in range(10):
    filename = os.path.join(output_dir, f"file_{random_string()}.txt")
    content  = random_string(200)
    with open(filename, "w") as f:
        f.write(content)
    print(f"[+] Created: {filename}")
    time.sleep(2)
print("[+] File activity complete — capture RAM now!")
