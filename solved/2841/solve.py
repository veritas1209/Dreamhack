import sys
from hashlib import sha256, shake_256

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def long_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def crt(remainders, moduli):
    total_sum = 0
    prod = 1
    for m in moduli:
        prod *= m
    for n_i, a_i in zip(moduli, remainders):
        p = prod // n_i
        inv = pow(p, -1, n_i)
        total_sum += a_i * inv * p
    return total_sum % prod

def solve():
    print("[DEBUG] === LWE/CRT 복구 익스플로잇 시작 ===")
    
    # 주어진 파라미터 세팅
    M = 79228162514264337593667407189
    m_list = [536870923, 536871931, 536872957, 536873959, 536874991, 536876009, 536877013, 536878049, 536879059, 536880071, 536881087, 536882239]
    d = 47893489367115774634385277346838405874917158424435934
    
    # output.txt 값 세팅
    pairs = [
        [7563522098488459674620593866480572204, 33702162267083489441336344993043635999],
        [1801482409838487045221003725615096967, 12304453748499516033511924583639332314],
        [43985476314902019539976820852136751, 18963282436631815546408429183160775175],
        [30556778346703664905142097052140116791, 20943063364495142029096042223260658241],
        [661320475031264818072133199279148576, 5688402327423287325184727106721882689],
        [19229513703274292635618135247542593059, 24758041371512844345158894194335462665],
        [29116355334889236372108413067482936091, 2657714441029548319085339696044373384],
        [7476224164630470845424706331300936376, 1044829697892350762757943603689422101],
        [34136844412213174317295607372244532487, 2150773287094209377357948523927871273],
        [42057055365863803579708823246807808019, 17742404056558463966565747491666167243],
        [27950740151837427171958797939220502304, 12819144848549389592443383729974852670],
        [41838237480797376864223397633217791162, 26837479737077859550809888197822605193]
    ]
    nonce = bytes.fromhex("b16b00b5cafef00d")
    ciphertext = bytes.fromhex("c4ddba62480ea46eb1cb408f133cbb9b8877c5826af422a988255d734df5a6695c6f1df021d3284a83cd79bd53f0e0")

    print(f"[DEBUG] 파라미터 M: {M}")
    print(f"[DEBUG] 모듈러 갯수: {len(m_list)}개\n")

    # --- 1단계: Pair Unshuffling (클러스터링) ---
    print("[DEBUG] --- 1단계: Pair Unshuffling ---")
    ref = pairs[0][0] % M
    print(f"[DEBUG] 그룹 1의 기준점(ref) 설정: {ref}")
    
    list1 = []
    list2 = []
    
    for i, p in enumerate(pairs):
        v0 = p[0] % M
        d0 = min((v0 - ref) % M, (ref - v0) % M)
        
        # 거리가 M/4 보다 작으면 같은 그룹(Q1)으로 판별
        if d0 < M // 4:
            list1.append(p[0])
            list2.append(p[1])
            print(f"  [+] Pair {i:2d}: [0] -> Q1, [1] -> Q2 (거리: {d0})")
        else:
            list1.append(p[1])
            list2.append(p[0])
            print(f"  [+] Pair {i:2d}: [1] -> Q1, [0] -> Q2 (거리: {d0})")
            
    # --- 2단계: q' 추출 ---
    def get_q_prime(t_list, name):
        print(f"\n[DEBUG] --- {name} q' 추출 ---")
        x0 = t_list[0] % M
        q_prime = []
        for i, t in enumerate(t_list):
            rem = t % M
            delta = (rem - x0) % M
            if delta > M // 2:
                delta -= M
            
            # 노이즈를 제거하여 정확한 몫 계산
            q = (t - x0 - delta) // M
            q_prime.append(q)
            print(f"  [-] {name}[{i:2d}]: t = {t}")
            print(f"      -> 몫(q') = {q}, 오차(delta) = {delta}")
        return q_prime
        
    q1_prime = get_q_prime(list1, "Q1")
    q2_prime = get_q_prime(list2, "Q2")
    
    # --- 3단계: CRT 적용 및 Base Q 계산 ---
    print("\n[DEBUG] --- 3단계: CRT 연산 ---")
    Q1_base = crt(q1_prime, m_list)
    Q2_base = crt(q2_prime, m_list)
    print(f"[DEBUG] Q1_base 계산 완료: {Q1_base}")
    print(f"[DEBUG] Q2_base 계산 완료: {Q2_base}\n")
    
    # --- 4단계: 오프셋 브루트포싱 및 FLAG 복호화 ---
    print("[DEBUG] --- 4단계: 오프셋 탐색 및 복호화 ---")
    offsets = [-2, -1, 0, 1, 2]
    
    for k1 in offsets:
        for k2 in offsets:
            # 전체 모듈러의 곱 d에 대해 오프셋을 적용
            q1_cand = (Q1_base - k1) % d
            q2_cand = (Q2_base - k2) % d
            
            qmin, qmax = sorted((q1_cand, q2_cand))
            key = sha256(long_to_bytes(qmin) + b"|" + long_to_bytes(qmax)).digest()
            flag_cand = xor_bytes(ciphertext, shake_256(key + nonce).digest(len(ciphertext)))
            
            # FLAG 형식 'DH{' 시그니처 확인
            if b"DH{" in flag_cand:
                print(f"[DEBUG] >>> 성공! (적용된 오프셋: k1={k1}, k2={k2}) <<<")
                print(f"[DEBUG] 찾은 키 값(hex): {key.hex()}")
                print(f"\n[*] 최종 복호화된 FLAG: {flag_cand.decode('utf-8', errors='ignore')}")
                return

    print("\n[DEBUG] FLAG를 찾지 못했습니다. 출력된 로그를 바탕으로 로직을 점검해주세요.")

if __name__ == "__main__":
    solve()