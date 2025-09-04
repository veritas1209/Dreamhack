import itertools
import multiprocessing
from tqdm import tqdm
import os

# 암호화된 파일 로드
with open("1974/flag.txt.enc", "rb") as f:
    enc = f.read()

assert len(enc) == 64

# 유효한 flag인지 검사
def is_valid_flag(flag: bytes) -> bool:
    if not flag.startswith(b'DH{'):
        return False
    if not flag.endswith(b'}'):
        return False
    body = flag[3:-1]
    return all((0x41 <= x <= 0x5a) or (0x61 <= x <= 0x7a) or (x == 0x5f) for x in body)

# clock 재현
def make_clock(H, M):
    for h in range(8):
        for m in range(8):
            yield 8 * H[h] + M[m]

# 한 조합에 대해 flag 복호화 시도
def try_decrypt(pair):
    H, M = pair
    clock = make_clock(H, M)
    decrypted = bytes([a ^ next(clock) for a in enc])
    if is_valid_flag(decrypted):
        return decrypted.decode()
    return None

# 메인 실행
def main():
    perms = list(itertools.permutations(range(8)))  # 8! = 40320
    total = len(perms) ** 2

    # pair 조합 생성 (H, M 순열쌍)
    def gen_pairs():
        for H in perms:
            for M in perms:
                yield (H, M)

    # 멀티프로세싱 풀 생성
    with multiprocessing.Pool() as pool:
        # tqdm으로 진행률 표시
        for result in tqdm(pool.imap_unordered(try_decrypt, gen_pairs(), chunksize=100), total=total):
            if result is not None:
                print("\n[+] Flag found:", result)
                pool.terminate()  # 다른 프로세스 중단
                return

    print("[-] Flag not found.")

if __name__ == "__main__":
    multiprocessing.freeze_support()  # Windows 호환
    main()
