from Crypto.Util.number import long_to_bytes
import gmpy2

# 문제에서 주어진 값들
e = 5
enc1_int = 25889043021335548821260878832004378483521260681242675042883194031946048423533693101234288009087668042920762024679407711250775447692855635834947612028253548739678779
enc2_int = 332075826660041992234163956636404156206918624

# [Step 1] RSA Small Message Attack
# m^e < N 이므로 모듈러 연산 없이 단순히 e제곱근을 구하면 됨
# gmpy2.iroot(n, k)는 (n의 k제곱근, 정확한 정수인지 여부)를 반환
key_int, exact = gmpy2.iroot(enc2_int, e)

if exact:
    print("[+] Key recovered successfully!")
else:
    print("[-] Failed to recover key exactly.")
    exit()

key = long_to_bytes(key_int)
print(f"[+] Recovered Key (hex): {key.hex()}")

# [Step 2] Vigenere Decryption
# enc1을 바이트로 변환
enc1_bytes = long_to_bytes(enc1_int)
flag = b""

# 비즈네르 역연산: (Cipher - Key) % 256
for i in range(len(enc1_bytes)):
    dec_char = (enc1_bytes[i] - key[i % len(key)]) % 256
    flag += bytes([dec_char])

print(f"\n[FLAG] {flag.decode()}")