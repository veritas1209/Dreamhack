# 암호화된 바이트 배열 (flag.c에서 추출)
encrypted_bytes = [
    0x0f, 0x25, 0x3e, 0x05, 0x53, 0x7f, 0x0f, 0x56, 0x34, 0x01, 0x5a, 0x0b, 
    0x63, 0x4c, 0x01, 0x54, 0x01, 0x5b, 0x0c, 0x56, 0x7c, 0x41, 0x01, 0x41, 
    0x00, 0x04, 0x17, 0x60, 0x04, 0x2e, 0x5d, 0x0a, 0x58, 0x2a, 0x5f, 0x55, 
    0x28, 0x55, 0x0b, 0x08, 0x6e, 0x2e, 0x7a, 0x41, 0x4e, 0x70, 0x79, 0x60, 
    0x3e, 0x51, 0x4d, 0x76, 0x72, 0x03, 0x24, 0x36, 0x57, 0x02, 0x7c, 0x2b, 
    0x76, 0x06, 0x0c, 0x60, 0x3c, 0x56, 0x40, 0x4c
]

# XOR 연산에 사용될 키 문자열 (flag.c에서 추출)
key_string = "KmE51Fn4P999Uy1a2l43Ix3s84tX6H98hHm7Jcn9VHJtvIHXXgyFD1EWg7KICgjUZ5s1"

print("="*60)
print("[DEBUG] 1. Data Verification")
print("="*60)
print(f"[*] Length of Encrypted Bytes : {len(encrypted_bytes)}")
print(f"[*] Length of Key String      : {len(key_string)}")
print("-" * 60)

# 길이가 맞는지 확인
if len(encrypted_bytes) != len(key_string):
    print("[ERROR] 배열과 키 문자열의 길이가 다릅니다!")
    exit(1)

print("\n[DEBUG] 2. Decrypting Data (XOR Operation)...")
flag_chars = []

for i in range(len(encrypted_bytes)):
    # 바이트 값과 키 문자열의 i번째 문자의 아스키 코드를 XOR 연산
    decrypted_char_code = encrypted_bytes[i] ^ ord(key_string[i])
    decrypted_char = chr(decrypted_char_code)
    flag_chars.append(decrypted_char)
    
    # 디버깅을 위해 처음 5자리만 변환 과정 출력
    if i < 5:
        print(f"    - Index {i:02d}: {hex(encrypted_bytes[i])} ^ '{key_string[i]}'({hex(ord(key_string[i]))}) -> '{decrypted_char}'")

if len(encrypted_bytes) > 5:
    print("    - ... (생략)")

# 배열에 담긴 문자들을 하나의 문자열로 합침
final_flag = "".join(flag_chars)

print("\n" + "="*60)
print("[SUCCESS] The Final Flag is:")
print("="*60)
print(final_flag)
print("============================================================")