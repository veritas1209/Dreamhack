import re
import base64
import hashlib
import struct
import math
from pwn import *

def solve_discrete_log():
    print("[*] 1. 바이너리에서 순열 배열(g, y) 추출 중...")
    elf = ELF('./curl')
    
    # 기드라에서 확인된 베이스 주소
    addr_g = 0x39e820
    addr_y = 0x39e020
    
    g_data = elf.read(addr_g, 2048)
    y_data = elf.read(addr_y, 2048)
    
    # 2바이트(Short) 단위로 1024개 파싱
    g = [struct.unpack('<H', g_data[i:i+2])[0] for i in range(0, 2048, 2)]
    y = [struct.unpack('<H', y_data[i:i+2])[0] for i in range(0, 2048, 2)]
    
    print("[*] 2. 순열 사이클 분석 및 이산 대수(Discrete Log) 계산 중...")
    remainders = []
    moduli = []
    visited = [False] * 1024
    
    for i in range(1024):
        if not visited[i]:
            cycle = []
            curr = i
            while not visited[curr]:
                visited[curr] = True
                cycle.append(curr)
                curr = g[curr]
            
            L = len(cycle)
            if L > 1:
                # y[i] = g^x[i] 이므로, g를 몇 번 타야 y[i]가 나오는지 찾습니다.
                target = y[i]
                curr = i
                steps = 0
                while curr != target and steps < L:
                    curr = g[curr]
                    steps += 1
                
                if steps < L:
                    remainders.append(steps)
                    moduli.append(L)
    
    print("[*] 3. 중국인의 나머지 정리(CRT)로 마스터 키 도출 중...")
    x = 0
    m = 1
    for r, mod in zip(remainders, moduli):
        while x % mod != r:
            x += m
        m = (m * mod) // math.gcd(m, mod)
        
    print(f"[+] Found Private Key (x) = {x}")
    print(f"[+] Group Order (M) = {m}\n")
    return x, m

def generate_license(user_name, exp_date, x, M):
    magic = bytes.fromhex("0d52ea4d0c55524c")
    user_padded = user_name.encode().ljust(32, b'\x00')
    exp_padded = exp_date.encode().ljust(16, b'\x00')
    
    # C언어 로직에 맞춰 널 바이트(\x00)를 포함해 MD5 계산
    payload_bytes = f"{user_name}|{exp_date}".encode() + b'\x00'
    md5_hash = hashlib.md5(payload_bytes).digest()
    md5_int = int.from_bytes(md5_hash, 'big')
    
    # 수학적 마법: Signature = MD5 * modinv(x, M) % M
    inv_x = pow(x, -1, M)
    sig_int = (md5_int * inv_x) % M
    
    # 16바이트 패딩 (Big Endian)
    signature = sig_int.to_bytes(16, 'big')
    
    final_data = magic + user_padded + exp_padded + signature
    return base64.b64encode(final_data).decode().rstrip('=')

def exploit():
    # 1. 로컬 바이너리에서 비밀키(x) 해킹
    x, M = solve_discrete_log()
    
    # 2. 드림핵 서버 연결
    host = "host8.dreamhack.games"
    port = 9194
    
    print(f"[*] Connecting to {host}:{port}...")
    r = remote(host, port)
    
    for i in range(1, 101):
        print(f"[*] Round [{i}/100]")
        recv_data = r.recvuntil(b"Generate please !\n").decode()
        
        match = re.search(r'name is "(.*?)", I would like to use license by "(.*?)".', recv_data)
        if not match:
            print("[!] 파싱 에러 발생!")
            break
            
        target_user = match.group(1)
        target_exp = match.group(2)
        
        # 3. 마스터 키로 100번 연속 서명 위조
        lic = generate_license(target_user, target_exp, x, M)
        r.sendline(lic.encode())
        
    print("\n[+] 100회 검증 돌파 완료! 플래그를 확인하세요:")
    r.interactive()

if __name__ == "__main__":
    exploit()