import struct

# 1. 비교 대상 문자열 (Target String)
target_str = "Please_input_the_correct_new_year_greetings_at_this_problem"
target_bytes = target_str.encode()

# 2. 하드코딩된 Key 값들 (코드에 있는 변수 순서대로)
# x64 시스템은 Little Endian이므로 struct.pack('<Q', ...)를 사용해 바이트 순서를 뒤집어줍니다.
key_data = b""

# local_128 ~ local_108 (8 bytes * 5개)
key_data += struct.pack('<Q', 0x0c313a0a11150d18) # local_128
key_data += struct.pack('<Q', 0x2c37426d44472f19) # local_120
key_data += struct.pack('<Q', 0x1b1a3a1704000f00) # local_118
key_data += struct.pack('<Q', 0x1301263b1904312a) # local_110
key_data += struct.pack('<Q', 0x361f06041a0a3e17) # local_108

# 크기가 특이한 변수들 처리 (undefined3, undefined5 등)
# local_100 (3 bytes)
key_data += (0x70202).to_bytes(3, byteorder='little')
# uStack_fd (5 bytes)
key_data += (0x43e1c3e2c).to_bytes(5, byteorder='little')
# uStack_f8 (3 bytes)
key_data += (0x2c1018).to_bytes(3, byteorder='little')

# local_f5 (8 bytes) - 마지막 부분
key_data += struct.pack('<Q', 0x1f0004160a151f2b)

# 3. XOR 연산 수행 (Target ^ Key = Flag)
flag = ""
for t, k in zip(target_bytes, key_data):
    flag += chr(t ^ k)

print("Decoded String:", flag)
print(f"Final Flag: DH{{{flag}}}")