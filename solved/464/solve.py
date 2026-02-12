import struct

# 1. 문제 데이터 (k: 암호화된 결과값)
k = [161, 55, 37, 106, 136, 128, 88, 143, 139, 247, 182, 192, 140, 132, 222, 141, 79, 38, 69, 75, 184, 232, 66, 72, 152, 14, 202, 49, 143, 58, 194, 161, 241, 230, 237, 118, 254, 112, 85, 32, 220, 192, 179, 201, 216, 132, 141, 42, 53]
data = bytearray(k)

# 2. 역연산 수행 (뒤에서 앞으로)
# range(len(ipt)-3) 였으므로, 역순은 len(data)-4 부터 0까지
length = len(data)

print("[*] Decrypting...")

for i in range(length - 4, -1, -1):
    # 4바이트 읽기 (Little Endian)
    val = int.from_bytes(data[i:i+4], 'little')
    
    # [Inverse Logic]
    # Forward: val = ((Rotate_Right) & Mask) ^ 0xDEADBEEF
    
    # 1. XOR 역연산 (XOR는 자기 자신이 역연산)
    val ^= 0xDEADBEEF
    
    # 2. Rotate 역연산
    # Forward Shift Amount: r_shift = (i + 16) % 32
    # Forward가 Right Rotate였으므로, Inverse는 Left Rotate를 해야 함.
    # Left Rotate Amount = r_shift
    
    amt = (i + 16) % 32
    
    # Left Rotate 구현: ((val << amt) | (val >> (32-amt))) & 0xFFFFFFFF
    recovered = ((val << amt) & 0xFFFFFFFF) | (val >> (32 - amt))
    
    # 3. 데이터 덮어쓰기
    data[i:i+4] = recovered.to_bytes(4, 'little')

print(f"\n[🎉] FLAG: {data.decode(errors='ignore')}")