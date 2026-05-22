def solve():
    print("[*] 역연산 준비: VM의 비교 배열(Target) 초기화")
    # output.txt의 맨 처음 (0x03 ~ 0x11A) cmp arr2[x], TARGET 에서 추출한 하드코딩 값
    targets = [
        0x91, 0x47, 0x4c, 0xb4, 0x5c, 0x12, 0x09, 0x99,
        0x01, 0x87, 0x7f, 0x04, 0x98, 0x1a, 0xc7, 0x3c,
        0x2c, 0x07, 0x66, 0x8b, 0x1e, 0x47, 0x61, 0x4d,
        0xf3, 0x75, 0xb1, 0x64, 0x14, 0x3b, 0x78, 0xef
    ]
    
    print(f"[DEBUG] 추출된 Target 배열 ({len(targets)} bytes):")
    print(" ".join(f"{x:02x}" for x in targets))
    print("-" * 65)
    
    flag_bytes = []
    
    # 역연산은 원래 flag의 인덱스 k (0부터 31) 순서대로 진행합니다.
    for k in range(32):
        # i는 VM 내부 루프 카운터입니다. (VM은 스택 구조상 역순으로 flag를 처리함)
        i = 31 - k
        
        # 루프 카운터 i의 값에 따라 암호화 상수가 분기됨 (output.txt 분기문 0x1d3 ~ 0x20a)
        if 0 <= i <= 7:
            c1, c2 = 0x1f, 0x55
        elif 8 <= i <= 15:
            c1, c2 = 0x27, 0x35
        elif 16 <= i <= 23:
            c1, c2 = 0x9a, 0xca
        elif 24 <= i <= 31:
            c1, c2 = 0xf1, 0x8d
            
        print(f"[DEBUG] Flag Index [{k:02d}] (VM Loop i={i:02d}) -> 적용 상수 C1={hex(c1)}, C2={hex(c2)}")
        
        # 1. Target 배열의 정답 바이트에서 시작
        enc = targets[k]
        
        # 2. 연산 역순 1단계: add 0x37 -> sub 0x37
        step1 = (enc - 0x37) & 0xff
        
        # 3. 연산 역순 2단계: Nibble Swap (ROL 4) 역연산 -> 동일하게 좌우 4비트 치환
        step2 = ((step1 << 4) | (step1 >> 4)) & 0xff
        
        # 4. 연산 역순 3단계: XOR 연산 역순 -> 그대로 XOR
        step3 = step2 ^ c2
        
        # 5. 연산 역순 4단계: add C1 역순 -> sub C1
        dec = (step3 - c1) & 0xff
        
        flag_bytes.append(dec)
        
        # 연산 과정 상세 출력
        print(f"   -> 원본 타겟값  : {hex(enc)}")
        print(f"   -> Sub 0x37     : {hex(step1)}")
        print(f"   -> Nibble Swap  : {hex(step2)}")
        print(f"   -> XOR {hex(c2):>4}     : {hex(step3)}")
        print(f"   -> Sub {hex(c1):>4}     : {hex(dec)} ('{chr(dec)}')\n")
        
    print("-" * 65)
    flag_hex = "".join(f"{b:02x}" for b in flag_bytes)
    print(f"[+] 헥스(Hex) 변환 전: {flag_bytes}")
    print(f"[+] 최종 복호화된 Flag (Hex): {flag_hex}")
    print(f"[*] 정답 제출 포맷: DH{{{flag_hex}}}")

if __name__ == "__main__":
    solve()