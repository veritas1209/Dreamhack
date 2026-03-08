from __future__ import annotations
import struct
import os
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5

# --- 문제의 상수 및 클래스 ---
P = [101, 103, 107, 109, 113, 127, 131, 137]
Q = 0x1337C0FFEE

def _u64(x):
    return x & 0xFFFFFFFFFFFFFFFF

@dataclass
class KM:
    k: bytes
    iv: bytes

class AESCipher:
    def __init__(self, t):
        self.t = int(t)
        self.km = self._km(self.t)
    
    @staticmethod
    def _seed(t: int):
        s = sum(P) * 0x1337
        x = _u64((t * 0xC0FFEE) ^ (s + Q))
        x ^= _u64((x << 13) | (x >> (64 - 13)))
        x = _u64(x + 0x9E3779B97F4A7C15)
        return x
    
    @classmethod
    def _km(cls, t):
        seed = cls._seed(t)
        h = SHA256.new()
        h.update(struct.pack("<Q", seed))
        h.update(b"3A91BC4F")
        k = h.digest()[:16]
        m = MD5.new()
        m.update(struct.pack("<Q", seed))
        m.update(k)
        iv = m.digest()
        return KM(k=k, iv=iv)

def solve():
    in_path = "challenge.enc"
    out_filename = "restored.exe" # 윈도우 실행 파일로 저장
    
    if not os.path.exists(in_path):
        print(f"Error: '{in_path}' 파일을 찾을 수 없습니다.")
        return

    print("[*] 파일을 읽는 중...")
    with open(in_path, "rb") as f:
        data = f.read()
    
    # 1. 암호화된 시간(t) 추출 및 복구
    encoded_t_bytes = data[5:13]
    encoded_t_int = struct.unpack("<Q", encoded_t_bytes)[0]
    mask = 0xA5A5A5A5A5A5A5A5
    recovered_t = encoded_t_int ^ mask
    print(f"[+] 복구된 타임스탬프: {recovered_t}")
    
    # 2. Key와 IV 재생성
    solver_aes = AESCipher(recovered_t)
    
    # 3. 복호화 수행
    # 헤더(29바이트) 건너뛰기
    ciphertext = data[29:]
    cipher = AES.new(solver_aes.km.k, AES.MODE_CBC, iv=solver_aes.km.iv)
    decrypted_data = cipher.decrypt(ciphertext)
    
    # 4. 패딩 제거
    try:
        pad_len = decrypted_data[-1]
        if pad_len > 16: # 패딩이 잘못되었을 경우 안전장치
             plaintext = decrypted_data
             print("[!] 경고: 패딩 값이 비정상적입니다. 원본 그대로 저장합니다.")
        else:
            plaintext = decrypted_data[:-pad_len]
    except:
        plaintext = decrypted_data

    # 5. 실행 파일로 저장
    with open(out_filename, "wb") as f:
        f.write(plaintext)
    
    print(f"\n[Success] '{out_filename}' 파일이 생성되었습니다!")
    print(f"이제 터미널에서 .\\{out_filename} 명령어를 입력해 실행해보세요.")

if __name__ == "__main__":
    solve()