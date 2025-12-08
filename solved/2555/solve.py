import base64

# 암호화된 데이터
encrypted = "xBmqfPcZ0tsfZ3mULhMD30IBUai16RZOVEvqtoqCFF9qQ/b="

# Step 1: 뒤집힌 Base64 디코딩 (prob3 역연산)
def untruck(data):
    STD_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    MY_TABLE = STD_TABLE[::-1]
    
    # 뒤집힌 테이블을 원래대로 되돌리기
    trans_table = str.maketrans(MY_TABLE, STD_TABLE)
    decoded_str = data.translate(trans_table)
    return base64.b64decode(decoded_str)

# Step 2: XOR 해독 (prob2 역연산)
def unbox(data):
    KEY = b"DELICIOUS"
    res = []
    for i, b in enumerate(data):
        k = KEY[i % len(KEY)]
        res.append(b ^ k ^ (i & 0xFF))
    return bytes(res)

# Step 3: Affine cipher 해독 (prob1 역연산)
def unwrap(data):
    # (b * 13 + 37) % 256 = c
    # b * 13 ≡ c - 37 (mod 256)
    # b ≡ (c - 37) * 13^(-1) (mod 256)
    # 13의 modular inverse는 197 (13 * 197 ≡ 1 (mod 256))
    inv_13 = 197
    return bytes([((b - 37) * inv_13) % 256 for b in data])

# 해독 실행
print("=" * 50)
print("감귤 포장하기 CTF 풀이")
print("=" * 50)

print("\n[1단계] 뒤집힌 Base64 디코딩...")
step1 = untruck(encrypted)
print(f"결과: {step1.hex()}")

print("\n[2단계] XOR 해독...")
step2 = unbox(step1)
print(f"결과: {step2.hex()}")

print("\n[3단계] Affine cipher 해독...")
flag = unwrap(step2)

print("\n" + "=" * 50)
print("🎉 FLAG 발견!")
print("=" * 50)
try:
    print(f"FLAG: {flag.decode('utf-8')}")
except:
    print(f"FLAG (hex): {flag.hex()}")
    print(f"FLAG (raw): {flag}")