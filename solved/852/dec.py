# hex_list를 그대로 유지
hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

# encfile 읽기
with open('encfile', 'r', encoding='utf-8') as f:
    enc_list = f.read().strip()

# enc_list가 16진수로 이루어진 문자열이어야 하므로, 이를 변환하여 복호화
dec_list = []
for i in range(0, len(enc_list), 2):
    hex_b = enc_list[i:i+2]  # 2자리씩 잘라서 처리
    try:
        index = hex_list.index(hex_b)
        dec_list.append(hex_list[(index - 128) % len(hex_list)])
    except ValueError:
        print(f"Error: {hex_b} not in hex_list")
        continue  # 해당 값이 hex_list에 없으면 건너뜁니다.

# 복호화된 바이트를 16진수로 변환
dec_bytes = bytes([int(i, 16) for i in dec_list])

# 복호화된 데이터를 flag.png로 저장
with open('dec_flag.png', 'wb') as f:
    f.write(dec_bytes)
