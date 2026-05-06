import hashlib
import struct
import string

# 디컴파일 코드에서 추출한 9쌍의 64-bit int 해시 타겟
targets = [
    (0xfe5d3a093968d02b, 0xba0aa367c2862eae),
    (0x8bea2ada9e26604f, 0x2e6f41c96dcf5224),
    (0x7fd91bd2949b75f3, 0x05b1ed8e6072f3a6),
    (0xc94045c6d4887611, 0x9d43df6df6b94d95),
    (0xb9a8a83c8ac08d80, 0x6d78e80376518464),
    (0x0e81a20f2023c2d0, 0x2e41eae69d89f186),
    (0x425c831dd2a3e5fd, 0x82788dbbdc4100ec),
    (0x6d0fee8d3901dd20, 0xebe82a0a41e5d783),
    (0x2afa26414b72e506, 0x0d1848e9c21d114d),
]

target_hashes = []
for p1, p2 in targets:
    # 64-bit 정수 2개를 Little-Endian 바이트 배열(16바이트)로 변환
    target_hashes.append(struct.pack('<QQ', p1, p2))

# 플래그에 사용될 가능성이 높은 출력 가능한 ASCII 문자들
charset = string.printable.strip() 

flag = ""
print("[*] 해시 크래킹 시작...")

for i, target in enumerate(target_hashes):
    found = False
    # 3바이트 덩어리이므로 3중 루프로 모든 경우의 수 탐색
    for c1 in charset:
        for c2 in charset:
            for c3 in charset:
                guess = c1 + c2 + c3
                # 추측한 3글자의 MD5 해시값 계산
                if hashlib.md5(guess.encode()).digest() == target:
                    flag += guess
                    print(f"[{i+1}/9] 매치 성공: '{guess}' -> 현재 플래그: {flag}")
                    found = True
                    break
            if found: break
        if found: break

    if not found:
        print(f"[-] {i+1}번째 청크 복구 실패 (특수 문자나 공백이 포함되었는지 확인 필요)")

print(f"\n[+] 최종 FLAG: {flag}")