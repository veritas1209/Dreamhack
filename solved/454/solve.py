import struct
import sys

def solve(enc_filename, out_filename):
    print(f"[*] Reading {enc_filename}...")
    try:
        with open(enc_filename, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: {enc_filename} not found.")
        return

    # 1. 헤더 파싱 (원본 크기)
    if len(data) < 8:
        print("Error: File too small.")
        return

    original_size = struct.unpack('<Q', data[:8])[0]
    encoded_data = data[8:]
    print(f"[*] Original size: {original_size} bytes")
    
    # 2. 비트 스트림 생성 (LSB First)
    # C코드: byte >> (cnt & 7) -> 하위 비트부터 읽음
    bits = []
    for b in encoded_data:
        for i in range(8):
            bits.append((b >> i) & 1)
            
    print(f"[*] Total encoded bits: {len(bits)}")
    
    ptr = 0
    decoded_bits = []
    
    while ptr < len(bits):
        # 복구된 비트가 원본 사이즈에 도달하면 종료
        if len(decoded_bits) >= original_size * 8:
            break

        # 첫 비트 읽기
        first_bit = bits[ptr]
        ptr += 1
        
        if first_bit == 0:
            # 0으로 시작하는 경우: 두 가지 가능성 (N=0 또는 N=1)
            # 구분자(0)를 읽은 셈 치고, 바로 값(Value) 비트를 하나 읽음
            if ptr >= len(bits): break
            
            val_bit = bits[ptr]
            ptr += 1
            
            if val_bit == 0:
                # 패턴 '00': Special Case (N=0)
                # 원본: 1
                decoded_bits.append(1)
            else:
                # 패턴 '01': N=1
                # 원본: 01
                decoded_bits.append(0)
                decoded_bits.append(1)
        
        else:
            # 1로 시작하는 경우: N >= 2
            # first_bit가 이미 1이므로 Length(L) = 1로 시작
            L = 1
            
            # 0(구분자)이 나올 때까지 1의 개수 카운트
            while ptr < len(bits):
                if bits[ptr] == 0:
                    ptr += 1 # 구분자 0 소비
                    break
                L += 1
                ptr += 1
            
            # 값(Value) 읽기: L + 1 비트를 읽어야 함
            # (N=1일 때 1비트였으므로, N>=2면 L+1 비트임)
            N = 0
            for i in range(L + 1):
                if ptr < len(bits):
                    if bits[ptr] == 1:
                        N |= (1 << i) # LSB First로 값 복원
                    ptr += 1
            
            # 원본 복구: N개의 0과 마지막 1
            for _ in range(N):
                decoded_bits.append(0)
            decoded_bits.append(1)

    # 3. 비트 -> 바이트 변환
    output_bytes = bytearray()
    for i in range(0, len(decoded_bits), 8):
        val = 0
        chunk = decoded_bits[i:i+8]
        for bit_idx, bit in enumerate(chunk):
            if bit:
                val |= (1 << bit_idx)
        output_bytes.append(val)

    # 4. 파일 저장
    final_data = output_bytes[:original_size]
    with open(out_filename, 'wb') as f:
        f.write(final_data)
    
    print(f"[+] Decoded successfully! Check {out_filename}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python solve_final.py <enc_file>")
    else:
        out_name = sys.argv[2] if len(sys.argv) > 2 else "flag.txt"
        solve(sys.argv[1], out_name)