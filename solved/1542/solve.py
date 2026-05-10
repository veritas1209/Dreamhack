import ctypes

# 우리가 구한 찐 경우의 수
result = 4734429039332245112509383301816908330905209520728736

# 1. 32-bit Unsigned (unsigned int)
ans_32u = result % (2**32)
print(f"DH{{{ans_32u}}}")

# 2. 64-bit Unsigned (unsigned long long)
ans_64u = result % (2**64)
print(f"DH{{{ans_64u}}}")

# 3. 32-bit Signed (int) - 음수가 나올 수도 있음
ans_32s = ctypes.c_int32(ans_32u).value
print(f"DH{{{ans_32s}}}")

# 4. 64-bit Signed (long long) - 음수가 나올 수도 있음
ans_64s = ctypes.c_int64(ans_64u).value
print(f"DH{{{ans_64s}}}")