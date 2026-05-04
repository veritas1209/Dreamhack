def solve_byte_caesar():
    # 제공된 암호화된 헥스 문자열[cite: 2]
    encrypted_hex = "061a17d2252720d2251e21291e2bd225172625d221281724d2261a17d215131e1fded2132c272417d22115171320ded2151325261b2019d213d2281b1424132026d2261322172526242bd22118d215211e212425d2131524212525d2261a17d2251d2be0d205171319271e1e25d225211324d2192413151718271e1e2bd2212817241a171316ded2261a171b24d215131e1e25d217151a211b2019d21b20d2261a17d225131e262bd2142417172c17e0d2f325d2261a17d22913281725d2191720261e2bd21e1322d21319131b202526d2261a17d2251320162bd2251a212417ded213d22517202517d22118d22624132023271b1e1b262bd22913251a1725d21f17e0d2fbd2181b2016d225211e131517d21b20d2261a1b25d21f211f172026ded213d2221713151718271ed224172624171326d21824211fd2261a17d2142725261e1b2019d22921241e16e0d2001326272417d925d214171327262bd2172028171e212225d21f17ded224171f1b20161b2019d21f17d22118d2261a17d229212016172425d2261a1326d21e1b17d214172b212016d2212724d216131b1e2bd2242127261b201725e0d2fb20d2261a1b25d2251724172017d2251726261b2019ded2fbd2171f1424131517d2261a17d21a13241f21202bd22118d2261a17d222241725172026d2132016d21e1726d21f2bd2292124241b1725d216241b1826d21329132bd2291b261ad2261a17d2261b1617e0d2f81b20131e1e2bded2fbd2181b2016d21f2b25171e18d2251e1717221b2019d2291b261ad2261a17d2181e1319ded2f6fa2de5e914161815eae4e5e7e4e516171513e8e8e515e9e5e913e815e817e4e61815e7e8e31613e61616e7e3e718e2ebe91518ea13e6ea16e6e3e913e51814e615132f"
    
    # 헥스 문자열을 바이트 배열로 변환
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    total_length = len(encrypted_bytes)
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 입력 데이터 길이: {total_length} bytes")
    print(f"[DEBUG] 예상되는 플래그 포맷: 'DH{{...'[cite: 4]")
    print(f"[DEBUG] 가능한 키 범위: 1 ~ 255[cite: 3]")
    print(f"[DEBUG] ========================================\n")
    
    found_key = None
    decrypted_flag_text = ""
    
    # 1부터 255까지 모든 키를 무차별 대입 (Brute-force)
    for key in range(1, 256):
        decrypted_bytes = bytearray()
        
        # 각 바이트마다 복호화 연산 수행: (b - key) % 256[cite: 3]
        for b in encrypted_bytes:
            dec_b = (b - key) % 256
            decrypted_bytes.append(dec_b)
            
        # 디버깅을 위해 결과 출력 (가독성을 위해 에러 무시하고 ASCII 문자로 변환)
        try:
            # 첫 30바이트만 미리보기로 출력하여 터미널 도배 방지
            preview = decrypted_bytes[:30].decode('ascii', errors='replace')
            # ASCII 출력 불가능한 제어문자는 가독성을 위해 '.'으로 치환
            safe_preview = "".join([c if 32 <= ord(c) <= 126 else '.' for c in preview])
            print(f"[DEBUG] [Key: {key:03d}] 미리보기: {safe_preview}...")
            
            # 복호화된 데이터에 플래그 시그니처 'DH{' 가 있는지 확인
            if b"DH{" in decrypted_bytes:
                found_key = key
                decrypted_flag_text = decrypted_bytes.decode('utf-8', errors='ignore')
                print(f"  ---> [!] 유력한 정답 키 발견! (Key: {key})")
                
        except Exception as e:
            # 디코딩 에러 발생 시 무시하고 진행
            pass
            
    print(f"\n[DEBUG] ================= 결과 =================")
    if found_key:
        print(f"[SUCCESS] 찾은 키 값: {found_key}")
        print(f"[FLAG 포함 원문 출력]\n")
        print(decrypted_flag_text)
    else:
        print("[FAIL] 플래그('DH{')를 포함하는 복호화 결과를 찾지 못했습니다.")

if __name__ == "__main__":
    solve_byte_caesar()