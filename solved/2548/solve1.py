import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. 문제에서 주어진 암호화된 이모지 문자열 (B1N4RY{} 안의 내용만)
emoji_cipher = "🍭🥘🍕🍕🌯🍝🍕🍝🍲🍕🍫🍭🌯🥘🍫🍬🍜🥗🍩🍫🍬🍲🍕🍊🍬🍫🍲🍭🍊🥗🍭🍩🍔🥘🍭🌯🍛🍛🍛🍫🍟🥗🍜🍬🍕🍟🌯🍕🍟🍝🥘🍟🍕🍫🥘🍛🍊🥗🍬🍔🌯🍩🍬🍜"

# 2. 문제에서 주어진 매핑 테이블 (Reverse Lookup을 위해 딕셔너리로 변환)
# ("🍬", 0x0) -> '🍬': '0'
emoji_map = {
    "🍬": "0", "🌭": "1", "🍔": "2", "🍟": "3",
    "🌯": "4", "🍕": "5", "🍝": "6", "🍜": "7",
    "🥗": "8", "🍲": "9", "🍛": "A", "🥘": "B",
    "🍫": "C", "🍭": "D", "🍊": "E", "🍩": "F"
}

# 3. 이모지 -> 16진수 문자열 변환
hex_string = ""
for char in emoji_cipher:
    hex_string += emoji_map[char]

print(f"[*] Recovered Hex: {hex_string}")

# 4. Hex String -> Bytes 변환
encrypted_bytes = bytes.fromhex(hex_string)

# 5. Key와 IV 생성 (문제에 주어진 함수 그대로 사용)
def generate_key_iv(seed, length=16):
    random.seed(seed)
    # Python 3의 random 구현을 따름
    raw = "".join(chr(random.randint(0, 255)) for _ in range(length))
    
    key = raw.encode("latin1")
    iv  = raw.encode("latin1")
    return key, iv

# 시드값은 이모지 "🌱"
seed = "🌱"
key, iv = generate_key_iv(seed)

print(f"[*] Generated Key: {key.hex()}")
print(f"[*] Generated IV : {iv.hex()}")

# 6. AES 복호화
try:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_bytes)
    
    # 패딩 제거 (PKCS7) 및 디코딩
    # 패딩이 꼬였을 경우를 대비해 일단 raw값도 출력하고 unpad 시도
    print(f"[*] Raw Decrypted: {decrypted}")
    
    plaintext = unpad(decrypted, AES.block_size).decode('utf-8')
    print("\n🎉 FLAG FOUND 🎉")
    print(f"B1N4RY{{{plaintext}}}")
    
except Exception as e:
    print(f"\n[!] Error: {e}")