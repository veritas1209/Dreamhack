from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# [DEBUG] 획득한 암호문과 비밀번호 세팅
enc_hex = "4b77d9567ee95dd091ca51b5bd6400f79ea9c9731f78512b22693f5392b16f82a7dbfdf48f3e7dd5ece03c14c5535b952cdf4f8716061ed2743f50ac244d2086"
key_hex = "140ee2689fd25e8e5e9a3edd52462ae3"

enc_data = bytes.fromhex(enc_hex)
key = bytes.fromhex(key_hex) # 16진수 문자열을 바이트로 변환

print(f"[DEBUG] 복호화 시작...")
print(f"[DEBUG] Key 바이트: {key.hex()}")

# AES-ECB 모드부터 시도 (가장 단순한 형태)
try:
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(enc_data) + decryptor.finalize()
    
    print("\n[!] 복호화 결과 (ASCII):")
    print(decrypted.decode('utf-8', errors='ignore'))
except Exception as e:
    print(f"[DEBUG] 오류 발생: {e}")