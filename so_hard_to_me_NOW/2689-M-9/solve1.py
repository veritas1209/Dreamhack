import subprocess
import os

def analyze_loader():
    print("[*] Disassembling ld_hacked.bin...")
    
    # ld_hacked.bin 파일이 있는지 확인
    if not os.path.exists("ld_hacked.bin"):
        print("[-] ld_hacked.bin not found.")
        return

    # objdump 실행 (x86-64)
    # 0x36371 주변을 봅니다. (사용자 제보 위치)
    # 조금 넓게 잡아서 문맥을 파악합니다.
    cmd = "objdump -D -M intel --start-address=0x36300 --stop-address=0x36400 ld_hacked.bin"
    
    try:
        output = subprocess.check_output(cmd, shell=True).decode('utf-8')
        print(output)
    except Exception as e:
        print(f"[-] Disassembly failed: {e}")

analyze_loader()