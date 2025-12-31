import sys

# --- 문제에서 주어진 변수 및 S-box ---
v20 = 100
v26 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
       0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
       0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
       0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
       0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
       0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
       0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
       0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
       0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
       0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
       0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
       0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
       0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
       0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
       0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
       0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

# --- 1. 역산 S-Box 생성 ---
inv_v26 = [0] * 256
for i, x in enumerate(v26):
    inv_v26[x] = i

# --- 2. 복호화에 필요한 역함수 정의 ---

def inv_v23(s):
    # v23: s[i][0] = v26[s[i][0]]
    for i in range(2):
        s[i][0] = inv_v26[s[i][0]]

def inv_v22(s):
    # v22: s[i][1] = v26[s[i][1]]
    for i in range(2):
        s[i][1] = inv_v26[s[i][1]]

# v1(Swap)은 자기 자신이 역함수
def v1(s):
    s[0][0], s[1][0] = s[1][0], s[0][0]

# v2(Swap)는 자기 자신이 역함수
def v2(s):
    s[0][1], s[1][1] = s[1][1], s[0][1]

# v3(XOR)는 자기 자신이 역함수
def v3(v25):
    v25[0] = v25[0] ^ v25[1]

def v3s(state):
    for i in range(2):
        v25 = []
        for j in range(2): v25.append(state[i][j])
        v3(v25)
        for j in range(2): state[i][j] = v25[j]

# v4, v5 (XOR)도 자기 자신이 역함수 (단, 올바른 키 상태가 필요함)
def v4(s, k):
    for i in range(2):
        for j in range(2):
            s[i][j] ^= k[k[k[k[i*2+j]%4]%4]%4]

def v5(s, k):
    for i in range(2):
        s[i][1] ^= k[k[k[k[i*2+1]%4]%4]%4]

# --- 3. 키 스케줄 함수 (암호화와 동일하게 사용하여 상태 저장) ---
def v6(k):
    for i in range(4):
        for j in range(2*v20):
            # pow(base, exp, mod)
            idx = ((((k[i] << 4) ^ k[i]) << 4) ^ k[i]) % 256
            base = v26[v26[v26[idx]]]
            exp = pow(k[i], k[i])
            term1 = pow(base, exp, 256)
            term2 = pow(v26[k[i]], v26[k[i]])
            k[i] = pow(term1, term2, 256)

def v7(k):
    for i in range(4):
        k[i] = v26[k[i]]

# --- 4. 헬퍼 함수 ---
def v8(text):
    return [list(text[i:i+2]) for i in range(0, len(text), 2)]

def v9(v17):
    return bytes(sum(v17, []))

def v12(v13, v14=4):
    return [v13[i:i+4] for i in range(0, len(v13), v14)]

def unpad(s):
    return s[:-s[-1]]

# --- 5. 복호화 핵심 함수 ---
def decrypt_block(block_bytes, initial_key):
    # 1. 키 상태 미리 계산 (Forward Key Schedule)
    # 복호화 시에는 키가 역순으로 필요하거나 특정 시점의 키가 필요하므로
    # 암호화 시 변하는 키의 상태들을 리스트에 저장합니다.
    
    k = list(initial_key)
    round_keys = []
    
    # [상태 0] 초기 키 (Loop 시작 전 v4 용)
    round_keys.append(list(k))
    
    for _ in range(v20): # 100 라운드
        v6(k) # 키 업데이트
        # [상태 1..100] 루프 내부 v4 용
        round_keys.append(list(k))
        
    v7(k) # 마지막 키 업데이트
    # [상태 101] 마지막 v5 용
    round_keys.append(list(k))
    
    # 2. 복호화 시작
    s = v8(block_bytes) # 2x2 행렬로 변환
    
    # (1) Post-processing 역산
    # Enc: v22 -> v2 -> v5
    # Dec: v5 -> v2 -> inv_v22
    
    # v5 역산 (마지막 키 상태 사용)
    v5(s, round_keys[-1]) 
    
    # v2 역산 (Swap)
    v2(s)
    
    # v22 역산 (S-box Inverse)
    inv_v22(s)
    
    # (2) Loop 역산 (100번)
    # Enc Loop: v6(키변환) -> v23 -> v1 -> v3s -> v4(변환된키)
    # Dec Loop: v4(변환된키) -> v3s -> v1 -> inv_v23 -> (키는 이전 상태로 간주)
    
    for r in range(v20):
        # 현재 라운드에서 사용된 키 인덱스: 
        # v20(100)번째 라운드에서는 round_keys[100]이 사용됨.
        # 따라서 거꾸로 100, 99, ..., 1 순으로 가져옴.
        current_k = round_keys[v20 - r]
        
        v4(s, current_k)
        v3s(s) # 자기 자신 역산
        v1(s)  # 자기 자신 역산
        inv_v23(s)
        
    # (3) Pre-processing 역산
    # Enc: v4(초기키)
    # Dec: v4(초기키) -> round_keys[0]
    v4(s, round_keys[0])
    
    return v9(s)

def solve(ciphertext, key_candidate):
    try:
        decrypted = b""
        blocks = v12(ciphertext)
        
        for block in blocks:
            decrypted += decrypt_block(block, key_candidate)
        
        # 패딩 제거 및 출력 시도
        return unpad(decrypted)
    except:
        return None

# --- Main: Brute Force ---

# !중요! 여기에 문제의 출력값(hex string)을 입력하세요.
# 예: ciphertext_hex = "4a1b..." 
ciphertext_hex = "34a0fb58f3f5e740bc663d2e01c9d320842e5af5b38c4e7b08f9029825f50540fd8cee2019f5d7e6a89c6164a6911c08" 

if ciphertext_hex == "OUTPUT_HEX_HERE":
    print("스크립트 내 'ciphertext_hex' 변수에 문제의 16진수 문자열을 입력해주세요.")
else:
    ciphertext = bytes.fromhex(ciphertext_hex)

    print("Brute Forcing 2-byte key...")
    
    # KEY_SIZE = 2 이므로 키의 형태는 [a, b, 0, 0] 또는 [a, b, a, b] 일 가능성이 높습니다.
    # v6 함수가 4번 루프를 돌기 때문에 키 리스트 길이는 4여야 합니다.
    
    found = False
    for a in range(256):
        for b in range(256):
            # 키 후보 생성 (일반적으로 나머지 바이트는 0으로 채움)
            key_candidate = [a, b, 0, 0] 
            
            # 복호화 시도
            res = solve(ciphertext, key_candidate)
            
            if res:
                try:
                    # 플래그 형식이 맞는지 확인 (예: 'DH{', 'FLAG{', 'CTF{')
                    # 문제에 맞는 플래그 포맷으로 수정 가능
                    res_str = res.decode('utf-8')
                    # 일반적인 플래그 문자인지 확인 (출력 가능한 아스키범위)
                    if all(32 <= c <= 126 for c in res):
                        print(f"Found Key: {key_candidate}")
                        print(f"Flag: {res_str}")
                        found = True
                except:
                    pass
        if found: break # 하나 찾으면 종료 (필요시 제거)

    if not found:
        print("키 형식이 [a, b, 0, 0]이 아닐 수 있습니다. [a, b, a, b] 등으로 코드를 수정해보세요.")