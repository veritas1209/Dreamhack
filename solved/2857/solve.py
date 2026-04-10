def swap_bits(n):
    """strIen 함수의 로직: 인접 비트 스왑"""
    return ((n >> 1) & 0x55) | ((n << 1) & 0xAA)

def solve():
    # 1. 데이터 로드
    print("[*] STEP 0: Loading encrypted data from output.txt")
    hex_input = "69 CA 6C 56 E1 CD E4 E7 67 6D DE D0 6F E9 66 E9 32 AF B8 30 9D AF 30 88 B7 A0 A3"
    enc_data = [int(x, 16) for x in hex_input.split()]
    print(f"[DEBUG] Raw: {enc_data}")
    print(f"[DEBUG] Length: {len(enc_data)}")

    # 2. strIen 역산 (비트 스왑 복구)
    step1 = [swap_bits(b) for b in enc_data]
    print(f"[DEBUG] After bit-swap reversal: {['%02X' % b for b in step1]}")

    # 3. ѕ 역산 (XOR 복구)
    # 키는 16바이트이며, 그 이후는 0으로 초기화된 메모리(local_428)를 사용함
    key_base = [
        0xeb, 0xa6, 0xac, 0xed, 0x8d, 0xbc, 0xeb, 0x8b, # _0_8_
        0xeb, 0xaf, 0xbf, 0xbf, 0xeb, 0xa5, 0xec, 0x84  # _8_8_
    ]
    
    # 데이터 길이에 맞춰 키를 확장 (모자란 부분은 0으로 채움)
    full_key = key_base + [0x0] * (len(step1) - len(key_base))
    
    step2 = []
    for i in range(len(step1)):
        val = step1[i] ^ full_key[i]
        step2.append(val)
        # 디버깅을 위해 XOR 과정 출력
        print(f"[DEBUG] Index {i:02d}: {step1[i]:02X} ^ {full_key[i]:02X} -> {val:02X}")

    print(f"[DEBUG] After XOR reversal: {['%02X' % b for b in step2]}")

    # 4. fcIose 역산 (문자열 반전 복구)
    step3 = step2[::-1]
    print(f"[DEBUG] After string reverse: {['%02X' % b for b in step3]}")

    # 5. 최종 결과 출력
    try:
        flag = "".join([chr(b) for b in step3])
        print("\n" + "="*40)
        print(f"[+] FOUND FLAG: {flag}")
        print("="*40)
    except Exception as e:
        print(f"[-] Error decoding to string: {e}")

if __name__ == "__main__":
    solve()