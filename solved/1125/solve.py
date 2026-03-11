from pwn import *
import struct
import math

# ---------------------------------------------------------
# 1. 외부 모듈 없이 구현한 순수 파이썬 MD5 Length Extension
# ---------------------------------------------------------
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

def process_chunk(chunk, h0, h1, h2, h3):
    w = list(struct.unpack('<16I', chunk))
    s = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]
    K = [int((1 << 32) * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

    a, b, c, d = h0, h1, h2, h3

    for i in range(64):
        if 0 <= i <= 15:
            f = (b & c) | (~b & d)
            g = i
        elif 16 <= i <= 31:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        elif 48 <= i <= 63:
            f = c ^ (b | ~d)
            g = (7 * i) % 16

        f = (f + a + K[i] + w[g]) & 0xFFFFFFFF
        new_b = (b + left_rotate(f, s[i])) & 0xFFFFFFFF
        a = d
        d = c
        c = b
        b = new_b

    return (h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF, (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF

def generate_payload(original_hash_hex, original_msg, extra_data, key_len):
    original_msg_len = key_len + len(original_msg)

    # 서버에서 준 해시값(h1)을 MD5 내부 상태(State)로 복구
    hash_bytes = bytes.fromhex(original_hash_hex)
    h0 = struct.unpack('<I', hash_bytes[0:4])[0]
    h1_st = struct.unpack('<I', hash_bytes[4:8])[0]
    h2_st = struct.unpack('<I', hash_bytes[8:12])[0]
    h3_st = struct.unpack('<I', hash_bytes[12:16])[0]

    # 원래 메시지에 붙었을 가상의 패딩 계산
    padding = b'\x80'
    padding += b'\x00' * ((56 - (original_msg_len + 1) % 64) % 64)
    padding += struct.pack('<Q', original_msg_len * 8)

    # 연장할 데이터의 새로운 패딩 계산
    total_len = original_msg_len + len(padding)
    new_msg_len = total_len + len(extra_data)

    extra_padding = b'\x80'
    extra_padding += b'\x00' * ((56 - (new_msg_len + 1) % 64) % 64)
    extra_padding += struct.pack('<Q', new_msg_len * 8)

    extra_data_padded = extra_data + extra_padding

    # 남은 데이터만 추가로 해싱(연장)
    for i in range(0, len(extra_data_padded), 64):
        chunk = extra_data_padded[i:i+64]
        h0, h1_st, h2_st, h3_st = process_chunk(chunk, h0, h1_st, h2_st, h3_st)

    new_hash = struct.pack('<I', h0) + struct.pack('<I', h1_st) + struct.pack('<I', h2_st) + struct.pack('<I', h3_st)
    new_msg = original_msg + padding + extra_data

    return new_hash.hex(), new_msg.hex()


# ---------------------------------------------------------
# 2. 서버 통신 및 페이로드 전송 로직
# ---------------------------------------------------------
host = "host3.dreamhack.games"
port = 20880

p = remote(host, port)

# h1 파싱
p.recvuntil(b'HMAC("Dreamhack") = ')
h1 = p.recvline().strip().decode()
print(f"[*] Received Original Hash (h1): {h1}")

# 데이터 세팅
m1 = b"Dreamhack"
extra_data = b"pwned_by_hajin" # 원하는 글자 아무거나
key_length = 500

# 우리가 직접 만든 함수로 해시와 메시지 계산
new_hash, new_message_hex = generate_payload(h1, m1, extra_data, key_length)

print(f"[*] Calculated New Message (hex): {new_message_hex}")
print(f"[*] Calculated New Hash (h2): {new_hash}")

# 서버에 전송
p.recvuntil(b"Your message: ")
p.sendline(new_message_hex.encode())

p.recvuntil(b"Your hash: ")
p.sendline(new_hash.encode())

# 짠! 결과 확인
print("\n[+] Exploitation Complete! Result:")
print(p.recvall(timeout=2).decode())