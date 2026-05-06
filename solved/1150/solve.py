import struct
import hashlib

# 1. C언어의 비트 섞기 연산을 파이썬으로 구현 (32비트 unsigned int 기준)
def scramble(x):
    # 파이썬은 정수 오버플로우가 없으므로 32비트 마스킹(& 0xFFFFFFFF) 필수
    x &= 0xFFFFFFFF
    p1 = (x << 22) & 0xFFFFFFFF
    p2 = ((x & 0xfc00) << 6) & 0xFFFFFFFF
    p3 = (x >> 9) & 0xff80
    p4 = (x >> 25)
    return p1 | p2 | p3 | p4

def solve():
    # TODO: IDA, Ghidra, HxD 또는 pwntools를 이용해 DAT_00104020의 
    # 400,000바이트 (100,000 * 4바이트) 데이터를 'data.bin'으로 추출해오세요.
    try:
        with open('data.bin', 'rb') as f:
            raw_data = f.read(400000)
    except FileNotFoundError:
        print("data.bin 파일이 필요합니다. 바이너리에서 DAT_00104020 영역을 추출해주세요.")
        return

    # 2. 바이트 배열을 100,000개의 4바이트 부호없는 정수(uint) 리스트로 언패킹
    # '<' = 리틀 엔디안, 'I' = 4바이트 unsigned int
    integers = list(struct.unpack('<100000I', raw_data))

    print("[*] 스투지 정렬 대신 파이썬 내장 정렬 시작...")
    # 3. 비트 스크램블 결과를 기준으로 오름차순 정렬 O(n log n)
    integers.sort(key=scramble)
    print("[+] 정렬 완료!")

    # 4. 정렬된 정수들을 다시 바이트 배열로 패킹 (FUN_001014a9 로직)
    sorted_raw_data = struct.pack('<100000I', *integers)

    # 5. SHA256 해시 계산
    sha256 = hashlib.sha256()
    sha256.update(sorted_raw_data)
    hash_hex = sha256.hexdigest()

    # 6. 플래그 출력
    print(f"Flag is: DH{{{hash_hex}}}")

if __name__ == '__main__':
    solve()