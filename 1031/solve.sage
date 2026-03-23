import re
from multiprocessing import Pool, cpu_count
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 419987277261396331
a = 267849768333949543
b = 190288349752338993

F = GF(p)
a_F = F(a)
b_F = F(b)

x0 = -F(3) * b_F / (F(2) * a_F)
c = F(3) * x0

# 전역 공간에 선언하여 멀티프로세싱 Worker들이 구조를 그대로 상속받도록 합니다.
if c == 0:
    MODE = 'cusp'
elif c.is_square():
    MODE = 'split'
    t = c.sqrt()
    N = p - 1
else:
    MODE = 'non-split'
    PR = PolynomialRing(F, 'x')
    x = PR.gen()
    F2 = GF(p**2, modulus=x**2 - c, names='s')
    s = F2.gen()
    t = s
    N = p + 1

# 개별 점에 대해 이산 대수를 푸는 함수
def solve_dlp_worker(args):
    idx, P_val, Q_val = args
    if Q_val is None:
        return idx, 0

    px, py = P_val
    qx, qy = Q_val

    if MODE == 'cusp':
        u_P, v_P = F(px) - x0, F(py)
        u_Q, v_Q = F(qx) - x0, F(qy)
        k = int((u_Q / v_Q) / (u_P / v_P))
    elif MODE == 'split':
        u_P, v_P = F(px) - x0, F(py)
        u_Q, v_Q = F(qx) - x0, F(qy)
        phi_P = (v_P + t*u_P) / (v_P - t*u_P)
        phi_Q = (v_Q + t*u_Q) / (v_Q - t*u_Q)
        k = int(discrete_log(phi_Q, phi_P, ord=N))
    else:
        u_P, v_P = F2(px) - x0, F2(py)
        u_Q, v_Q = F2(qx) - x0, F2(qy)
        phi_P = (v_P + t*u_P) / (v_P - t*u_P)
        phi_Q = (v_Q + t*u_Q) / (v_Q - t*u_Q)
        k = int(discrete_log(phi_Q, phi_P, ord=N))

    return idx, k

def main():
    with open("output.txt", "r") as f:
        text = f.read()

    ct_hex = text.strip().split()[-1]

    print("[*] 파일 파싱 중...")
    P_dict = {}
    for m in re.finditer(r'P_(\d+):\s*Point\(x=(\d+),\s*y=(\d+)\)', text):
        P_dict[int(m.group(1))] = (int(m.group(2)), int(m.group(3)))

    Q_dict = {}
    for m in re.finditer(r'Q_(\d+):\s*(Point\(x=(\d+),\s*y=(\d+)\)|None)', text):
        idx = int(m.group(1))
        if m.group(2) == 'None':
            Q_dict[idx] = None
        else:
            Q_dict[idx] = (int(m.group(3)), int(m.group(4)))

    tasks = []
    for i in range(4096):
        if i in P_dict and i in Q_dict:
            tasks.append((i, P_dict[i], Q_dict[i]))

    cores = cpu_count()
    print(f"[*] {cores}개의 CPU 코어를 모두 사용하여 병렬 연산을 시작합니다...")

    key = 0
    done = 0

    # 멀티프로세싱 풀 가동 (순서와 무관하게 연산 완료되는 즉시 처리)
    with Pool(processes=cores) as pool:
        for idx, k in pool.imap_unordered(solve_dlp_worker, tasks):
            key ^= (k << (8 * (idx % 10)))
            done += 1
            if done % 100 == 0:
                print(f"[+] 진행도: {done} / 4096")

    key_bytes = int(key).to_bytes(16, 'big')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    flag = cipher.decrypt(bytes.fromhex(ct_hex))

    print("\n[🎉] Flag Found:")
    try:
        print(unpad(flag, 16).decode('utf-8'))
    except:
        print(flag.decode('utf-8', errors='ignore'))

if __name__ == '__main__':
    main()