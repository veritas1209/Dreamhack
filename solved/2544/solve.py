# gyul_bomb_decoder.py

# 제로폭 문자 -> 2비트 매핑
zw_to_bit = {
    "\u200b": "00",  # zero width space
    "\u200c": "01",  # zero width non-joiner
    "\u200d": "10",  # zero width joiner
    "\ufeff": "11",  # zero width no-break space / BOM
}

def zw_to_byte(zw_seq: str) -> int:
    """제로폭 문자 4개를 바이트로 변환"""
    bits = ""
    for char in zw_seq:
        if char in zw_to_bit:
            bits += zw_to_bit[char]
    
    if len(bits) != 8:
        return None
    
    b = int(bits, 2)
    # XOR 복호화
    b ^= 0x37
    return b

# 파일 읽기
with open("gyulisyummy.txt", "r", encoding="utf-8") as f:
    content = f.read()

print("🍊 귤 폭탄 해체 중...\n")

# 🍊으로 토큰 분리
tokens = content.split("🍊")[1:]  # 첫 번째는 빈 문자열
print(f"총 {len(tokens)}개의 귤 발견!")

# 각 토큰에서 제로폭 문자 추출 및 디코딩
flag_bytes = []
debug_info = []

for i, token in enumerate(tokens):
    # 제로폭 문자만 추출
    zw_chars = [c for c in token if c in zw_to_bit]
    
    if len(zw_chars) == 4:
        byte_val = zw_to_byte(''.join(zw_chars))
        if byte_val is not None:
            flag_bytes.append(byte_val)
            
            # 디버그 정보 (처음 5개만)
            if i < 5:
                bits = ''.join(zw_to_bit[c] for c in zw_chars)
                debug_info.append(
                    f"귤 #{i+1}: {bits} → {byte_val:3d} (0x{byte_val:02x}) → '{chr(byte_val) if 32 <= byte_val < 127 else '?'}'"
                )

# 디버그 출력
print("\n📊 디코딩 샘플 (처음 5개):")
for info in debug_info:
    print(f"  {info}")

# 플래그 변환
try:
    flag = bytes(flag_bytes).decode('ascii')
    print(f"\n🚩 FLAG: {flag}")
    print(f"\n✅ 성공! 플래그 길이: {len(flag)} 문자")
except:
    print(f"\n원본 바이트: {bytes(flag_bytes)}")
    print(f"16진수: {bytes(flag_bytes).hex()}")
    
    # UTF-8로 시도
    try:
        flag = bytes(flag_bytes).decode('utf-8')
        print(f"\n🚩 FLAG (UTF-8): {flag}")
    except:
        print("\n❌ 디코딩 실패")

# 추가 분석
print(f"\n📈 통계:")
print(f"  - 추출된 바이트 수: {len(flag_bytes)}")
print(f"  - ASCII 범위 문자: {sum(1 for b in flag_bytes if 32 <= b < 127)}")
print(f"  - NULL 바이트: {flag_bytes.count(0)}")