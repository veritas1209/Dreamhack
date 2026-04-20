import os

# 덤프된 6개의 배열 (Untagged)
arr1 = [134, 253, 242, 215]
arr2 = [171, 5, 27, 188, 155, 224, 211, 226, 247, 250, 204, 58, 138, 8, 27, 237]
arr3 = [154, 43, 5, 191, 224, 186, 255, 41, 26, 160, 66, 60, 140, 104, 29, 142]
arr4 = [245, 196, 11, 126]
arr5 = [145, 50, 236, 24, 129, 129, 209, 11, 106, 46, 237, 89, 18, 2, 66, 66]
arr6 = [126, 201, 174, 83, 92, 249, 129, 110, 136, 236, 65, 211, 204, 99, 149, 217]

def get_streams(state):
    u1 = state & 7
    idx1 = (u1 - 1) // 2
    u3 = (u1 * 7 - 4) & 0x1f
    u2 = (u1 * 5 + 2) & 0x1f
    
    # Stream A (0x406da0)
    a = (arr1[idx1 % 4] ^ arr2[u3 // 2] ^ arr3[u2 // 2])
    # Stream B (0x406e20)
    b = (arr4[idx1 % 4] ^ arr5[u3 // 2] ^ arr6[u2 // 2])
    
    return (a * 2 + 1), (b * 2 + 1)

def solve():
    with open("hello.png.enc", "rb") as f:
        enc = f.read()

    dec = bytearray()
    state = 7  # Initial RAX from GDB (Integer 3)

    print(f"[+] Total: {len(enc)} bytes. Logic: Assembly Clone Mode.")

    for i in range(len(enc)):
        A, B = get_streams(state)
        
        # 0x406637~0x40665a 구간의 어셈블리 로직 (Header/Init Phase)
        # rdi = (State * 41 + A * 13 + B - 54) & 0x1ff
        if i < 12: # cmp rax, 0x17 (11) 지점에 의한 분기 추정
            comb = (state * 41 + A * 13 + B - 54) & 0x1ff
            key = comb >> 1
        else:
            # 0x406740 구간의 본체 로직 (Body Phase)
            # Magic = (State * 29 + 170) & 0x1ff
            # Key = (A ^ B ^ Magic ^ ...)
            magic = (state * 29 + 170) & 0x1ff
            comb = (A ^ B ^ magic) & 0x1ff
            key = comb >> 1

        res = enc[i] ^ (key & 0xFF)
        dec.append(res)

        # 디버깅 정보 출력
        if i < 8:
            print(f"[{i:02x}] State:{state:02x} | A:{A:02x} B:{B:02x} | Key:{key:02x} | Dec:{res:02x}")

        # 피드백 루프: 다음 State는 현재 암호문 바이트 (GDB 실측 데이터 기반)
        state = (enc[i] * 2) + 1

    with open("hello_fixed.png", "wb") as f:
        f.write(dec)

    header = dec[:4].hex().upper()
    print(f"\n[*] Result Header: {header}")
    if header == "89504E47":
        print("[!!!] MISSION ACCOMPLISHED: PNG Header Matched!")

if __name__ == "__main__":
    solve()