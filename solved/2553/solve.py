import struct

# 1. Ghidra에서 추출한 하드코딩된 데이터 (8바이트 정수들)
# 순서: local_78 -> uStack_70 -> local_68 -> auStack_60
encrypted_chunks = [
    0x0f2e0c07611b6417,
    0x376439660f211367,
    0x3623316734646412,
    0x286810120f223967
]

flag = b""

# 2. 각 청크를 리틀 엔디안(<Q) 바이트로 변환 후 XOR 0x55 수행
for chunk in encrypted_chunks:
    # 64비트 정수를 바이트열로 변환 (Little Endian)
    byte_array = struct.pack('<Q', chunk)
    
    for b in byte_array:
        # 각 바이트를 0x55와 XOR
        flag += bytes([b ^ 0x55])

print(f"Flag: {flag.decode('utf-8')}")