def rc4_ksa(key):
    """RC4 Key Scheduling Algorithm"""
    S = list(range(256))
    j = 0
    key_length = len(key)
    
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) & 0xff
        S[i], S[j] = S[j], S[i]
    
    return S

def rc4_decrypt(key, data):
    """RC4 복호화"""
    result = bytearray()
    
    for offset in range(0, len(data), 1024):
        block = data[offset:offset+1024]
        S = rc4_ksa(key)
        
        i = 0
        j = 0
        for byte_val in block:
            i = (i + 1) & 0xff
            j = (j + S[i]) & 0xff
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) & 0xff]
            result.append(byte_val ^ k)
    
    return bytes(result)

def xor_decrypt(data):
    """XOR 복호화 (짝수: 0x85, 홀수: 0x44)"""
    result = bytearray()
    
    for i, byte in enumerate(data):
        if i % 2 == 0:
            result.append(byte ^ 0x85)
        else:
            result.append(byte ^ 0x44)
    
    return bytes(result)

def find_jpeg_end_marker(data):
    """JPEG 끝 마커 찾기"""
    positions = []
    for i in range(len(data) - 1):
        if data[i] == 0xff and data[i+1] == 0xd9:
            positions.append(i)
    return positions

def analyze_with_xor_key(data, xor_key):
    """특정 XOR 키로 복호화하고 분석"""
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ xor_key[i % len(xor_key)])
    
    result = bytes(result)
    
    # JPEG 마커 확인
    is_jpeg = result[:2] == b'\xff\xd8'
    eoi_positions = find_jpeg_end_marker(result)
    
    # PNG 마커 확인
    is_png = result[:4] == b'\x89PNG'
    
    return {
        'data': result,
        'is_jpeg': is_jpeg,
        'is_png': is_png,
        'eoi_count': len(eoi_positions),
        'eoi_positions': eoi_positions,
        'ff_count': result.count(b'\xff')
    }

def brute_force_xor_key(data):
    """4바이트 XOR 키 브루트포스"""
    print("\n" + "="*60)
    print("4바이트 XOR 키 브루트포스 분석")
    print("="*60)
    
    # JPEG 헤더로부터 가능한 XOR 키 계산
    current_header = data[:4]
    print(f"현재 헤더: {current_header.hex()}")
    
    # 가능한 JPEG 시작 패턴들
    jpeg_patterns = [
        b'\xff\xd8\xff\xe0',  # JFIF
        b'\xff\xd8\xff\xe1',  # EXIF  
        b'\xff\xd8\xff\xdb',  # Quantization table first
        b'\xff\xd8\xff\xe2',  # APP2
    ]
    
    results = []
    
    for pattern in jpeg_patterns:
        xor_key = bytes([current_header[i] ^ pattern[i] for i in range(4)])
        print(f"\n패턴: {pattern.hex()}")
        print(f"XOR 키: {xor_key.hex()} ('{xor_key.decode('latin1')}')")
        
        analysis = analyze_with_xor_key(data, xor_key)
        
        print(f"  JPEG 시그니처: {analysis['is_jpeg']}")
        print(f"  EOI 마커 개수: {analysis['eoi_count']}")
        print(f"  FF 바이트 개수: {analysis['ff_count']}")
        
        if analysis['eoi_count'] > 0:
            print(f"  EOI 위치: {analysis['eoi_positions'][:5]}...")
            results.append((xor_key, analysis))
    
    # 끝에서 4바이트로 추가 검증
    print(f"\n파일 끝 4바이트: {data[-4:].hex()}")
    
    # JPEG EOI + 패딩으로 가정하고 역계산
    # JPEG는 보통 FF D9로 끝남
    for pattern in jpeg_patterns:
        xor_key = bytes([current_header[i] ^ pattern[i] for i in range(4)])
        
        # 끝부분 확인
        end_decrypted = bytes([data[-4 + i] ^ xor_key[i % 4] for i in range(4)])
        print(f"\nXOR 키 {xor_key.hex()}로 파일 끝 복호화: {end_decrypted.hex()}")
    
    return results

def extract_all_files(data):
    """파일에서 JPG, TXT, PNG 모두 추출"""
    print("\n" + "="*60)
    print("파일 내용 분석 및 추출")
    print("="*60)
    
    files = []
    
    # 1. JPEG 찾기
    jpg_start = data.find(b'\xff\xd8')
    if jpg_start != -1:
        jpg_end = data.find(b'\xff\xd9', jpg_start)
        if jpg_end != -1:
            jpg_data = data[jpg_start:jpg_end+2]
            files.append(('jpg', jpg_start, jpg_end+2, jpg_data))
            print(f"✓ JPEG: offset {jpg_start} ~ {jpg_end+2} ({len(jpg_data)} bytes)")
    
    # 2. PNG 찾기
    png_start = data.find(b'\x89PNG')
    if png_start != -1:
        png_end = data.find(b'IEND\xae\x42\x60\x82', png_start)
        if png_end != -1:
            png_data = data[png_start:png_end+8]
            files.append(('png', png_start, png_end+8, png_data))
            print(f"✓ PNG: offset {png_start} ~ {png_end+8} ({len(png_data)} bytes)")
    
    # 3. 텍스트/FLAG 찾기
    for pattern in [b'DH{', b'FLAG{', b'flag{']:
        idx = data.find(pattern)
        if idx != -1:
            end_idx = data.find(b'}', idx)
            if end_idx != -1:
                flag = data[idx:end_idx+1]
                print(f"✓ FLAG: {flag.decode('utf-8', errors='ignore')}")
                
                # 주변 컨텍스트 확인
                context_start = max(0, idx - 50)
                context_end = min(len(data), end_idx + 50)
                context = data[context_start:context_end]
                
                try:
                    readable = context.decode('utf-8', errors='ignore')
                    print(f"  컨텍스트: ...{readable}...")
                except:
                    pass
    
    return files

def main():
    print("\n" + "="*60)
    print("CTF 파일 복호화 도구 v4 - 상세 분석")
    print("="*60)
    
    # 원본 hex 데이터 로드
    hex_data = """1D DA DB B9 6D D3 E2 34 61 3A 11 CF C8 00 F6 FA F2 A2 0E 05 AD E0 5A C9 97 98 30 C0 A2 C1 5D 37 AA 8A E5 E4 FE 10 18 0A 85 1E 31 7C 86 70 36 01 1B 2C DB 28 01 62 FA 36 38 E9 CA FC 7D 6B 4D CD C2 E7 FC EB 61 3F 9E 71 6A 3F D2 49 17 E5 C6 5F FE 8B 12 91 F8 2E 3C FE A4 6F B4 BD FC 91 D3 E0 EF 4C 5A E3 DB 52 1B 71 13 64 8E 5A 7C BB 88 2B C7 79 C8 9C 6A 80 BD"""
    
    # 실제 파일에서 읽기
    try:
        with open('flag.jpg', 'rb') as f:
            encrypted_data = f.read()
        print(f"파일 크기: {len(encrypted_data)} bytes")
    except:
        print("⚠ flag.jpg 파일을 찾을 수 없습니다.")
        return
    
    # [1단계] 기본 복호화
    print("\n[1단계] 기본 복호화 (XOR → RC4)")
    xor_decrypted = xor_decrypt(encrypted_data)
    rc4_decrypted = rc4_decrypt(b"unfunfun", xor_decrypted)
    
    print(f"복호화 결과: {rc4_decrypted[:16].hex()}")
    
    with open('step1_rc4_decrypted.bin', 'wb') as f:
        f.write(rc4_decrypted)
    
    # [2단계] XOR 키 브루트포스
    xor_results = brute_force_xor_key(rc4_decrypted)
    
    # [3단계] 가장 유망한 결과 저장
    print("\n[3단계] 파일 저장 및 분석")
    print("="*60)
    
    best_results = sorted(xor_results, key=lambda x: x[1]['eoi_count'], reverse=True)
    
    for i, (xor_key, analysis) in enumerate(best_results[:3]):
        filename = f"final_decoded_{i+1}.jpg"
        with open(filename, 'wb') as f:
            f.write(analysis['data'])
        
        print(f"\n✓ {filename}")
        print(f"  XOR 키: {xor_key.hex()}")
        print(f"  EOI 개수: {analysis['eoi_count']}")
        
        # 내부 파일 추출
        extracted = extract_all_files(analysis['data'])
        
        for j, (ftype, start, end, fdata) in enumerate(extracted):
            extract_filename = f"extracted_{i+1}_{ftype}_{j}.{ftype}"
            with open(extract_filename, 'wb') as f:
                f.write(fdata)
            print(f"    → {extract_filename} 추출")
    
    print("\n" + "="*60)
    print("완료! 생성된 파일들을 확인해보세요.")
    print("="*60)

if __name__ == "__main__":
    main()