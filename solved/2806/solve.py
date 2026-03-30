enc = [13, 1, 50, 45, 38, 39, 46, 33, 48, 44, 38, 34, 22, 58, 61, 38, 37, 44, 22, 36, 48, 22, 60, 58, 43, 52]
key = 73

flag = ""
for c in enc:
    flag += chr(c ^ key)

print(f"Flag: {flag}")