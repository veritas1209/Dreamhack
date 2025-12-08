import base64

print("=" * 70)
print("🍊 CTF 문제 풀이: 귤 수학 문제")
print("=" * 70)

# 1단계: 수학 문제 풀이
x = 11
y = 32
tangerines_B = 7 * y  # 224

print(f"\n🔑 핵심 키: 상자 B의 귤 = {tangerines_B}개")

# 2단계: 암호 해독
print("\n" + "=" * 70)
print("[암호 해독 과정]")
print("=" * 70)

shipping_code = "R01ZVEdNUlRHSVpUS01aWEdNNFRHTUpUSEVaVE1NWlFHTTJER09CVEdZWlRRTVpVR00zVEdNUlRHRVpUTU1aVkdNMlRHT0pUR0laVElNWlJHTVlER05KVEc0WlRDTVpTR00zVEdOUlRHUVpUR01aWEdNWlRHTkpUR0FaVE1NWlJHTVpUR01aVEhFWlRFTVpSR000VEdOUlRHRVpUQ01aWkdNWURHTVpUR1FaVENNWlpHTTNUR09KVEdZWlRRTVpYR00zVEdOUlRHNFpUQU1aWEdNMkRHTVpUR0FaVEFNWlVHTTRUR05SVEdBWlRNTVpTR01aREdNWlRIQVpUS01aUkdNM1RHTkE9"

# Base64 → Base32 → Hex
decoded = base64.b64decode(shipping_code).decode('utf-8')
tokens = decoded.split('GM')
hex_string = ""

for token in tokens[1:]:
    if token:
        try:
            b32_str = 'GM' + token
            padding = (8 - len(b32_str) % 8) % 8
            b32_str += '=' * padding
            hex_string += base64.b32decode(b32_str).hex()
        except:
            pass

print(f"Step 1-2: Base64 + Base32 완료")
print(f"Hex 문자열 길이: {len(hex_string)}")

# 첫 번째 Hex 디코딩
hex_decoded_1 = bytes.fromhex(hex_string).decode('ascii', errors='replace')
print(f"\nStep 3: Hex 디코딩 (1차)")
print(f"결과: {hex_decoded_1}")

# 특수 문자 정리 및 2차 Hex 디코딩
print(f"\nStep 4: 특수 문자 정리")

def clean_and_decode(data):
    """특수 문자를 정리하고 Hex 디코딩"""
    cleaned = ""
    for c in data:
        if c in '0123456789abcdefABCDEF':
            cleaned += c
        elif c == '#':
            cleaned += '3'
        elif c in 'Ss':
            cleaned += '5'
        elif c in 'Cc':
            cleaned += 'c'
        elif c == 'G':
            cleaned += '6'
        elif c in 'Oo':
            cleaned += '0'
        elif c == '\x13':  # 0x13
            cleaned += '13'
        elif c == '\x03':  # 0x03
            cleaned += '03'
        # 다른 제어 문자는 무시
    
    print(f"정리 후: {cleaned[:100]}...")
    
    # Hex 디코딩 시도
    if len(cleaned) % 2 == 1:
        cleaned = '0' + cleaned
    
    try:
        return bytes.fromhex(cleaned).decode('ascii', errors='ignore')
    except:
        return cleaned

hex_decoded_2 = clean_and_decode(hex_decoded_1)
print(f"\nStep 5: Hex 디코딩 (2차)")
print(f"결과: {hex_decoded_2}")

# 더 디코딩이 필요한지 확인
if any(c in '0123456789abcdefABCDEF' for c in hex_decoded_2):
    print(f"\nStep 6: Hex 디코딩 (3차) 시도")
    hex_decoded_3 = clean_and_decode(hex_decoded_2)
    print(f"결과: {hex_decoded_3}")
    final_data = hex_decoded_3
else:
    final_data = hex_decoded_2

# XOR 디코딩
print(f"\n" + "=" * 70)
print(f"[XOR 디코딩]")
print("=" * 70)

keys_to_try = [224, 128, 33, 22, 107, 55, 352, 257, 150]

for key in keys_to_try:
    try:
        xor_result = ''.join(chr(ord(c) ^ key) for c in final_data if ord(c) < 256)
        
        # FLAG 패턴 확인
        if 'DH{' in xor_result or 'FLAG{' in xor_result or 'flag{' in xor_result:
            print(f"\n🎯🎯🎯 키 {key}로 FLAG 발견! 🎯🎯🎯")
            print("=" * 70)
            print(xor_result)
            print("=" * 70)
            break
        elif key == 224:
            print(f"키 {key} (상자 B 귤): {xor_result[:80]}")
    except:
        pass
else:
    print(f"\nFLAG 패턴을 찾지 못했습니다.")
    print(f"최종 데이터: {final_data}")
    
    # 바이트 단위로 XOR 시도
    print(f"\n바이트 단위 XOR 시도:")
    try:
        final_bytes = final_data.encode('latin-1')
        xor_result = bytes([b ^ 224 for b in final_bytes])
        print(f"결과: {xor_result}")
        print(f"ASCII: {xor_result.decode('ascii', errors='ignore')}")
    except Exception as e:
        print(f"실패: {e}")

print("\n" + "=" * 70)
print("완료!")
print("=" * 70)