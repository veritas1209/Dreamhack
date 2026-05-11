import requests
import zlib
import time

# ==============================================================================
# 1. Ghidra에서 추출한 데이터 세팅
# ==============================================================================
DAT_00102101 = bytes([
    0x03, 0x13, 0x15, 0x1e, 0x04, 0x1d, 0x29, 0x15, 0x3e, 0x19, 
    0x0d, 0x71, 0x10, 0x1a, 0x00, 0x3e, 0x0b, 0x04, 0x00, 0x04, 0x16
])
DAT_00102121 = bytes([
    0xaf, 0x54, 0x95, 0xc9, 0xdd, 0xfb, 0xdf, 0x77, 0x69, 0xcf, 
    0x6f, 0x10, 0xb3, 0x22, 0x0b, 0x55, 0x8c, 0xd2, 0x4d, 0xca, 0x69
])
DAT_00102141 = bytes([
    0xc0, 0x26, 0xe7, 0xac, 0xbe, 0x8f, 0x80, 0x07, 0x08, 0xbb, 
    0x07, 0x3e, 0xd7, 0x50, 0x6e, 0x34, 0xe1, 0xba, 0x2c, 0xa9, 0x02
])

HOST = "http://host8.dreamhack.games:10810/"

# ==============================================================================
# 2. 서버를 절대 뻗지 않게 할 "순수 텍스트" Key 생성기
# ==============================================================================
def forge_printable_crc32_key():
    print("[*] 아파치 서버가 튕겨내지 못하도록 '순수 텍스트'로만 이루어진 Key를 탐색합니다...")
    target_crc = 0xCAFEBABE
    poly = 0xEDB88320
    
    # 임의의 문자열(pad)을 'flag' 뒤에 붙여가며, 
    # 역산된 4바이트 꼬리표마저 완벽한 ASCII(알파벳/숫자/기호)로 떨어지는 마법의 키를 찾습니다.
    for i in range(1000000):
        pad = str(i).encode()
        prefix = b"flag_" + pad + b"_"
        
        crc = zlib.crc32(prefix) ^ 0xFFFFFFFF
        target = target_crc ^ 0xFFFFFFFF
        
        # O(1) 비트 시프트 역연산
        for _ in range(32):
            if target & 0x80000000:
                target ^= poly
                target = (target << 1) | 1
            else:
                target = (target << 1)
            target &= 0xFFFFFFFF
            
        patch = crc ^ target
        suffix = patch.to_bytes(4, 'little')
        
        # 도출된 4바이트가 화면에 출력 가능한 안전한 ASCII 문자(0x20 ~ 0x7E)인지 검증
        # 추가로 HTTP 파싱을 방해할 수 있는 특수문자(=, &, %, +)는 제외
        if all(0x20 <= b <= 0x7E for b in suffix) and not any(b in suffix for b in b"=&%+"):
            forged = prefix + suffix
            if zlib.crc32(forged) == target_crc:
                return forged.decode('ascii') # 문자열로 리턴!
                
    return None

# ==============================================================================
# 3. 메인 풀이 로직
# ==============================================================================
def solve():
    print("="*60)
    print("[*] CTF 풀이 스크립트 시작 (순수 문자열 & 최적화 버전)")
    print("="*60)

    # [Step 1] URI 역산
    uri_tail = bytearray(22)
    uri_tail[0] = 0x1c ^ 0x7f 
    for i in range(1, 22):
        uri_tail[i] = DAT_00102141[i-1] ^ DAT_00102121[i-1]
    uri_tail_str = uri_tail.decode('ascii', errors='replace')
    print(f"[+] 1단계: URI 타겟 확인 -> {uri_tail_str}")

    # [Step 2] Value 역산
    flag_value = bytearray(22)
    flag_value[0] = uri_tail[0] ^ 5 
    for i in range(1, 22):
        flag_value[i] = uri_tail[i] ^ DAT_00102101[i-1]
    flag_value_str = flag_value.decode('ascii', errors='replace')
    print(f"[+] 2단계: 파라미터 Value -> {flag_value_str}")

    # [Step 3] Key 역산 도출
    start_t = time.time()
    forged_key = forge_printable_crc32_key()
    print(f"    - 생성된 안전한 Key 문자열: {forged_key}")
    print(f"    - 탐색 소요 시간: {time.time() - start_t:.4f}초")
    
    if not forged_key:
        print("[!] 오류: 적합한 변조 키를 찾지 못했습니다.")
        return

    # [Step 4] 대상 서버로 익스플로잇 전송
    target_url = f"{HOST}/{uri_tail_str}"
    print("\n" + "="*60)
    print(f"[*] 4단계: 타겟 서버 공격")
    print(f"    - URL : {target_url}")
    print(f"    - POST Data : {{'{forged_key}': '{flag_value_str}'}}")
    print("="*60)

    try:
        # 완전히 정상적인 문자열 딕셔너리로 전송하므로 인코딩 에러 발생 확률 0%
        payload = {forged_key: flag_value_str}
        resp = requests.post(target_url, data=payload, allow_redirects=False)
        
        if "DH{" in resp.text:
            print(f"\n[🎉🎉🎉] 성공! 드디어 깃발을 뽑았습니다!\n")
            print("="*60)
            print(resp.text.strip())
            print("="*60)
        else:
            print("\n[?] HTTP 요청은 성공했으나, 플래그가 없습니다. (응답 코드: {})".format(resp.status_code))
            print(resp.text.strip())

    except Exception as e:
        print(f"\n[!] 앗... 또 에러 발생: {e}")
        print("\n[💡 추측] 만약 위 코드마저도 서버가 뻗는다면, 이건 페이로드 문제가 아니라 **사용 중인 PC(Mac M1/M2 등 ARM 아키텍처)와 x86_64 빌드로 된 Docker 아파치 모듈 간의 qemu 호환성 문제**로 인해 C 코드가 네이티브에서 돌다가 세그폴트를 뿜는 현상일 가능성이 큽니다.")

if __name__ == '__main__':
    solve()