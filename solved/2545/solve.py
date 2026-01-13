import base64
from Crypto.Util.number import long_to_bytes

def solve():
    # 1. 수학 문제에서 도출된 값 (Box B)
    # y = 32
    # B_apples = 4 * 32 = 128
    # B_tangerines = 7 * 32 = 224
    # B_total = 11 * 32 = 352
    
    # 힌트: "b_ga_real_im" -> Box B의 값 중 하나가 key일 확률이 높음
    candidate_keys = [107, 128, 224, 352] 

    # 2. 문제에 주어진 데이터
    shipping_code = "R01ZVEdNUlRHSVpUS01aWEdNNFRHTUpUSEVaVE1NWlFHTTJER09CVEdZWlRRTVpVR00zVEdNUlRHRVpUTU1aVkdNMlRHT0pUR0laVElNWlJHTVlER05KVEc0WlRDTVpTR00zVEdOUlRHUVpUR01aWEdNWlRHTkpUR0FaVE1NWlJHTVpUR01aVEhFWlRFTVpSR000VEdOUlRHRVpUQ01aWkdNWURHTVpUR1FaVENNWlpHTTNUR09KVEdZWlRRTVpYR00zVEdOUlRHNFpUQU1aWEdNMkRHTVpUR0FaVEFNWlVHTTRUR05SVEdBWlRNTVpTR01aREdNWlRIQVpUS01aUkdNM1RHTkE9"
    large_number = 1225791960486847216559241057127643735061339219611903419796877670743004960622385174

    # 3. Shipping Code 디코딩 (Base64 -> Base32)
    try:
        step1 = base64.b64decode(shipping_code)
        # Base32 디코딩 (패딩 문제 방지를 위해 에러 무시 혹은 처리 필요할 수 있음)
        decoded_str = base64.b32decode(step1).decode('utf-8')
        print(f"[+] Shipping Code Decoded: {decoded_str}")
        # 결과가 16진수 문자열처럼 보인다면 이를 다시 바이트로 변환할 수도 있습니다.
    except Exception as e:
        print(f"[-] Decoding error: {e}")

    # 4. Large Number 해독 (XOR)
    # 숫자를 바이트로 변환
    encrypted_bytes = long_to_bytes(large_number)
    print(f"[+] Encrypted bytes (hex): {encrypted_bytes.hex()}")

    print("\n[+] Decrypting with Box B candidates...")
    
    for key in candidate_keys:
        try:
            # XOR 연산 수행 (Single Byte XOR)
            decrypted = bytes([b ^ key for b in encrypted_bytes])
            print(f"Key {key}: {decrypted}")
            
            # 만약 키가 멀티 바이트라면 (예: '224' 문자열 자체 등) 로직을 바꿔야 함
            # 하지만 보통 수학 문제 답(숫자) 하나가 바이트 XOR 키로 쓰임
        except:
            pass

if __name__ == "__main__":
    solve()