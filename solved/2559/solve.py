# 암호화된 데이터 배열
encrypted_flag = [63, 76, 51, 73, 47, 36, 6, 25, 4, 19, 73, 16, 76, 30, 34, 22, 78, 4, 34, 17, 77, 26, 76, 30, 34, 45, 15, 76, 62, 78, 0]

# 계산된 키
key = 125

# XOR 복호화
decrypted = ''.join([chr(x ^ key) for x in encrypted_flag])
print(decrypted)