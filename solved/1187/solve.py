import os
import struct

# 망가진 파일 읽기
with open('flag.bmp.broken', 'rb') as f:
    data = bytearray(f.read())

file_size = len(data)

# --- 1단계: 고정적인 BMP 헤더 복구 ---
data[0:2] = b'BM'                               # 0x00: 시그니처 'BM'
data[2:6] = struct.pack('<I', file_size)        # 0x02: 파일 전체 크기
# 0x06 ~ 0x09 (Reserved)는 이미 0x00이므로 패스
data[10:14] = struct.pack('<I', 54)             # 0x0A: 픽셀 데이터 시작 오프셋 (24-bit 기본 54바이트)
data[14:18] = struct.pack('<I', 40)             # 0x0E: DIB 헤더 크기 (기본 40바이트)
data[26:28] = struct.pack('<H', 1)              # 0x1A: 컬러 플레인 수 (항상 1)

# 순수 픽셀 데이터의 크기 (전체 크기 - 헤더 크기 54바이트)
pixel_data_size = file_size - 54

print(f"[*] 파일 전체 크기: {file_size} bytes")
print(f"[*] 픽셀 데이터 크기: {pixel_data_size} bytes")
print("[*] 가능한 가로x세로 조합을 생성합니다...\n")

# --- 2단계: 가로/세로 길이 브루트포스 ---
# 가로(Width)를 1부터 적당한 크기(예: 3000)까지 반복하며 맞는 세로(Height)를 찾습니다.
count = 0
for width in range(1, 3000):
    # 24-bit BMP는 한 픽셀당 3바이트(24비트)를 차지하며, 각 행은 4의 배수로 패딩됨
    row_size = ((width * 24 + 31) // 32) * 4
    
    # 픽셀 데이터 크기가 현재 가로 길이 기준의 행 크기로 나누어 떨어지면 유효한 해상도로 간주
    if pixel_data_size % row_size == 0:
        height = pixel_data_size // row_size
        
        # 가로, 세로 값을 데이터에 기록
        data[18:22] = struct.pack('<I', width)   # 0x12: Width
        data[22:26] = struct.pack('<I', height)  # 0x16: Height
        
        # 파일로 저장 (결과물 확인용)
        out_filename = f"flag_{width}x{height}.bmp"
        with open(out_filename, 'wb') as out_f:
            out_f.write(data)
            
        print(f"[+] 생성 완료: {out_filename}")
        count += 1

print(f"\n[*] 총 {count}개의 파일이 생성되었습니다. 폴더를 확인하여 플래그가 보이는 이미지를 찾으세요!")