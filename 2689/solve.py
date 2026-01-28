def solve():
    # 메모리에 저장된 순서대로 바이트 배열 생성
    # 0x3c4852 -> 52 48 3C
    # 0x537e56 -> 56 7E 53
    # 0x76575c -> 5C 57 76
    encrypted = [0x52, 0x48, 0x3C, 0x56, 0x7E, 0x53, 0x5C, 0x57, 0x76]
    
    print("[*] Brute-forcing XOR Key...")
    for key in range(256):
        decrypted = ""
        valid = True
        for b in encrypted:
            val = b ^ key
            # 출력 가능한 문자 + 일반적인 변수명 문자(A-Z, 0-9, _)
            if not (32 <= val <= 126):
                valid = False
                break
            decrypted += chr(val)
        
        if valid:
            # 알파벳과 언더스코어만 포함된 경우를 우선 출력
            if all(c.isalnum() or c == '_' for c in decrypted):
                print(f"[+] Key 0x{key:02x}: {decrypted}  <-- LIKELY!")
            else:
                print(f"    Key 0x{key:02x}: {decrypted}")

    print("\n[*] Brute-forcing ADD/SUB Key...")
    for key in range(256):
        # SUB (Decrypted = Encrypted - Key)
        sub_res = ""
        valid_sub = True
        for b in encrypted:
            val = (b - key) & 0xFF
            if not (32 <= val <= 126): valid_sub = False; break
            sub_res += chr(val)
        
        if valid_sub and all(c.isalnum() or c == '_' for c in sub_res):
            print(f"[+] SUB Key 0x{key:02x}: {sub_res}")

        # ADD (Decrypted = Encrypted + Key)
        add_res = ""
        valid_add = True
        for b in encrypted:
            val = (b + key) & 0xFF
            if not (32 <= val <= 126): valid_add = False; break
            add_res += chr(val)

        if valid_add and all(c.isalnum() or c == '_' for c in add_res):
            print(f"[+] ADD Key 0x{key:02x}: {add_res}")

solve()