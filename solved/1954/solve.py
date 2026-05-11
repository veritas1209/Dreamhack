import marshal
import dis

# chall.py에 있는 marshal 바이트 페이로드
PAYLOAD = b'\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00@\x00\x00\x00s\x0c\x00\x00\x00d\x00d\x01\x84\x00Z\x00d\x02S\x00)\x03c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x05\x00\x00\x00C\x00\x00\x00sn\x01\x00\x00d\x01}\x01|\x00D\x00]\t}\x02|\x02|\x01v\x01r\r\x01\x00d\x02S\x00q\x04t\x00|\x00\xa0\x01\xa1\x00\x83\x01}\x03t\x02t\x03|\x03\x83\x01\x83\x01D\x00].}\x04|\x04d\x03\x16\x00}\x05|\x05d\x04k\x02r/|\x03|\x04\x19\x00d\x05\x17\x00d\x06\x16\x00|\x03|\x04<\x00q\x1a|\x05d\x07k\x02r>|\x03|\x04\x19\x00d\x08\x17\x00d\x06\x16\x00|\x03|\x04<\x00q\x1a|\x03|\x04\x19\x00d\t\x17\x00d\x06\x16\x00|\x03|\x04<\x00q\x1at\x02t\x03|\x03\x83\x01\x83\x01D\x00](}\x06|\x06d\x03\x16\x00}\x07|\x07d\x04k\x02rb|\x03|\x06\x05\x00\x19\x00d\nN\x00\x03\x00<\x00qO|\x07d\x07k\x02ro|\x03|\x06\x05\x00\x19\x00d\x0bN\x00\x03\x00<\x00qO|\x03|\x06\x05\x00\x19\x00d\x0cN\x00\x03\x00<\x00qOt\x02t\x03|\x03\x83\x01\x83\x01D\x00].}\x08|\x08d\x03\x16\x00}\t|\td\x04k\x02r\x93|\x03|\x08\x19\x00d\n\x18\x00d\x06\x16\x00|\x03|\x08<\x00q~|\td\x07k\x02r\xa2|\x03|\x08\x19\x00d\x0b\x18\x00d\x06\x16\x00|\x03|\x08<\x00q~|\x03|\x08\x19\x00d\x0c\x18\x00d\x06\x16\x00|\x03|\x08<\x00q~|\x03t\x00d\r\x83\x01k\x02r\xb5d\x0eS\x00d\x02S\x00)\x0fNz_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ F\xe9\x03\x00\x00\x00\xe9\x00\x00\x00\x00\xe9k\x00\x00\x00\xe9\x00\x01\x00\x00\xe9\x01\x00\x00\x00\xe9e\x00\x00\x00\xe9Y\x00\x00\x00\xe9\'\x00\x00\x00\xe9\xf0\x00\x00\x00\xe9\x8d\x00\x00\x00s9\x00\x00\x00bu\xbd\xce7s^:\xbb\xc49\xc2\x953\xb4\x89\x85\xd2\x95:\x80\x9fxg\xd2u\xbe\x92M\xb8\x9e\x85s\xd7y\xbb\x9cwt\xc1\x85\x97\x9c9\xbf\x953g\xc3>\xb3\x92Hw\xc1xjT)\x04\xda\tbytearray\xda\x06encode\xda\x05range\xda\x03len)\n\xda\x01a\xda\x01b\xda\x01c\xda\x01d\xda\x01e\xda\x01f\xda\x01g\xda\x01h\xda\x01i\xda\x01j\xa9\x00r\x19\x00\x00\x00\xfa\x08<string>\xda\x06verify\x02\x00\x00\x00s<\x00\x00\x00\x04\x01\x08\x01\x08\x01\x06\x01\x02\xff\x0c\x03\x10\x02\x08\x01\x08\x01\x16\x01\x08\x01\x16\x01\x16\x02\x10\x02\x08\x01\x08\x01\x12\x01\x08\x01\x12\x01\x12\x02\x10\x02\x08\x01\x08\x01\x16\x01\x08\x01\x16\x01\x16\x02\x0c\x02\x04\x01\x04\x01r\x1b\x00\x00\x00N)\x01r\x1b\x00\x00\x00r\x19\x00\x00\x00r\x19\x00\x00\x00r\x19\x00\x00\x00r\x1a\x00\x00\x00\xda\x08<module>\x01\x00\x00\x00s\x02\x00\x00\x00\x0c\x01'

def main():
    print("[+] 마샬 데이터 로드 중...")
    try:
        module_code = marshal.loads(PAYLOAD)
        print("[+] 모듈 코드 로드 완료.")
    except Exception as e:
        print(f"[-] 마샬 페이로드 로드 에러: {e}")
        return

    # 'verify' 함수 객체 탐색
    verify_code = None
    for const in module_code.co_consts:
        if hasattr(const, 'co_name') and const.co_name == 'verify':
            verify_code = const
            break

    if not verify_code:
        print("[-] 상수 풀에서 'verify' 함수를 찾을 수 없습니다.")
        return

    print("\n" + "="*50)
    print(" 1. 코드 추출 및 분석 (디버깅 정보)")
    print("="*50)
    print("[*] 상수(Constants) 목록 상세:")
    for i, c in enumerate(verify_code.co_consts):
        print(f"  [Idx {i}]: {repr(c)}")
        
    print("\n[*] 지역 변수(Varnames):", verify_code.co_varnames)
    print("[*] 내장/전역 이름(Names):", verify_code.co_names)

    print("\n" + "="*50)
    print(" 2. 자동 역연산 (Reversing)")
    print("="*50)
    
    # 바이트코드 상수 풀에서 타겟 바이트열과 난독화 수치(상수) 자동 추출
    target_bytes = verify_code.co_consts[13]  
    add_consts = [verify_code.co_consts[5], verify_code.co_consts[8], verify_code.co_consts[9]]  # [107, 101, 89]
    sub_xor_consts = [verify_code.co_consts[10], verify_code.co_consts[11], verify_code.co_consts[12]] # [39, 240, 141]
    
    print(f"[*] 타겟 바이트 길이: {len(target_bytes)} bytes")
    print(f"[*] 덧셈 상수 배열 (Loop 1): {add_consts}")
    print(f"[*] XOR 및 뺄셈 상수 배열 (Loop 2, 3): {sub_xor_consts}")

    if isinstance(target_bytes, bytes):
        arr = bytearray(target_bytes)
        print("\n[*] 초기 타겟 배열 상태 (Hex):")
        print("   ", [hex(b) for b in arr])
        
        # [Step 1] 역연산: Loop 3 (뺄셈의 역연산 -> 덧셈)
        print("\n[*] 역연산 Step 1 진행 중 (Loop 3 뺄셈 복구)...")
        for i in range(len(arr)):
            arr[i] = (arr[i] + sub_xor_consts[i % 3]) % 256
            print(f"    - Byte[{i:02d}]: {hex(arr[i])} (Int: {arr[i]:3d})")

        # [Step 2] 역연산: Loop 2 (XOR의 역연산 -> XOR)
        print("\n[*] 역연산 Step 2 진행 중 (Loop 2 XOR 복구)...")
        for i in range(len(arr)):
            arr[i] = arr[i] ^ sub_xor_consts[i % 3]
            print(f"    - Byte[{i:02d}]: {hex(arr[i])} (Int: {arr[i]:3d})")

        # [Step 3] 역연산: Loop 1 (덧셈의 역연산 -> 뺄셈)
        print("\n[*] 역연산 Step 3 진행 중 (Loop 1 덧셈 복구)...")
        for i in range(len(arr)):
            arr[i] = (arr[i] - add_consts[i % 3]) % 256
            print(f"    - Byte[{i:02d}]: {hex(arr[i])} (Int: {arr[i]:3d})")
            
        print("\n" + "="*50)
        print(" [!] 복원 완료. 최종 플래그(Flag):")
        print(" " + arr.decode(errors='ignore'))
        print("="*50)
    else:
        print("[-] 올바른 타겟 바이트열을 인덱스 13에서 찾지 못했습니다.")

if __name__ == '__main__':
    main()