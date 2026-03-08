from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random

# 1. 알아낸 PNG Magic Number
d = b'\x89PNG'
s = int.from_bytes(d[:4], 'big')

# 2. 난수 시드(Seed) 설정
seed_value = (s ^ 0x5a5a5a5a) ^ (~s & 0xffffffff) ^ ((s << 13) & 0xffffffff) ^ ((s >> 7) & 0xff) * 0x1010101
random.seed(seed_value)

# 3. Key 복원 과정 (수정됨: 루프 안에서 매번 난수 생성)
key = bytes(
    (random.getrandbits(128) >> (i * 8)) & 255 ^ (s >> (i * 3) & 0xff) ^ ((s << (i % 5)) & 0xff)
    for i in range(15, -1, -1)
)

# 4. IV 복원 과정
iv_prefix = bytes([
    d[0],
    ((d[2] ^ d[3]) * 57 + 131) & 255,
    ((d[3] << 3) ^ (d[2] >> 5) ^ 0b10101010) & 255,
    *((((v := d[i]) >> (v % 7) | v << (8 - v % 7)) & 255) for i in (2, 3))
])
iv = iv_prefix + b'\x00' * (16 - len(iv_prefix))

print(f"[*] 올바른 Key: {key.hex()}")
print(f"[*] 올바른 IV:  {iv.hex()}")

# 5. 복호화 진행
input_filename = 'flag.png'
output_filename = 'decrypted_flag.png'

try:
    with open(input_filename, 'rb') as f:
        encrypted_data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), 16)

    with open(output_filename, 'wb') as f:
        f.write(decrypted_data)
        
    print(f"[+] 성공적으로 복호화되었습니다! '{output_filename}' 파일을 확인해 보세요.")
except ValueError as e:
    print(f"[-] 복호화 실패: {e}")
except Exception as e:
    print(f"[-] 에러 발생: {e}")