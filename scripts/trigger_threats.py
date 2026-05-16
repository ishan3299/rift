import mmap
import os
import socket
import time

def trigger_rwx():
    print("[+] Triggering RWX memory allocation...")
    # PROT_READ (1) | PROT_WRITE (2) | PROT_EXEC (4) = 7
    buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    buf.write(b"\x90" * 4096) # NOP sled

def trigger_suspicious_tool():
    print("[+] Triggering suspicious tool execution (nc)...")
    os.system("nc -h > /dev/null 2>&1")

def trigger_reverse_shell_sim():
    print("[+] Triggering reverse shell simulation...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 4444))
    except:
        pass
    # Even if connect fails, the syscall was made. Now exec a shell.
    os.system("sh -c 'echo rift_test'")

if __name__ == "__main__":
    trigger_rwx()
    trigger_suspicious_tool()
    trigger_reverse_shell_sim()
