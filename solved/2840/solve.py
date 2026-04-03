from hashlib import shake_256

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def crt(remainders, moduli):
    print("[DEBUG] --- CRT 계산 시작 ---")
    total_sum = 0
    prod = 1
    
    # 모든 모듈러의 곱(N) 계산
    for m in moduli:
        prod *= m
    print(f"[DEBUG] 모듈러 전체 곱 (N) = {prod}")
    print(f"[DEBUG] N의 비트 길이: {prod.bit_length()} bits\n")

    for i, (n_i, a_i) in enumerate(zip(moduli, remainders)):
        p = prod // n_i
        inv = pow(p, -1, n_i) # 모듈러 역원 계산
        term = a_i * inv * p
        total_sum += term
        
        print(f"[DEBUG] Step {i+1}:")
        print(f"  - 현재 모듈러 (n_i) = {n_i}")
        print(f"  - 현재 나머지 (a_i) = {a_i}")
        print(f"  - 역원 (inv) = {inv}")
        print(f"  - 누적합 추가 값 = {term}")

    result = total_sum % prod
    print("\n[DEBUG] --- CRT 계산 완료 ---")
    print(f"[DEBUG] 복원된 secret 값 = {result}")
    print(f"[DEBUG] secret 비트 길이: {result.bit_length()} bits\n")
    return result

if __name__ == "__main__":
    # output.txt에서 주어진 값들 세팅
    moduli = [2147483659, 2147483693, 2147483713, 2147483743, 2147483777, 2147483817]
    remainders = [1185049275, 595679234, 93691065, 431984211, 702737809, 1831592642]
    nonce = bytes.fromhex("1337133713371337")
    ciphertext = bytes.fromhex("76705c47fa2c082c951fac742a892e8096ea6f9d519dc928e4ae35abce5ce5c73178b3435627f279b6bf193aad")
    
    print(f"[DEBUG] Ciphertext 길이: {len(ciphertext)} bytes\n")

    # 1. secret 복원
    secret = crt(remainders, moduli)

    # 2. Key Stream 생성
    secret_bytes = long_to_bytes(secret)
    print(f"[DEBUG] secret_bytes (hex): {secret_bytes.hex()}")
    
    hash_input = secret_bytes + nonce
    print(f"[DEBUG] shake_256 입력값 (hex): {hash_input.hex()}")
    
    keystream = shake_256(hash_input).digest(len(ciphertext))
    print(f"[DEBUG] 생성된 Keystream (hex): {keystream.hex()}\n")

    # 3. FLAG 복호화
    flag = xor_bytes(ciphertext, keystream)
    print(f"[*] 최종 복호화된 FLAG: {flag.decode(errors='ignore')}")