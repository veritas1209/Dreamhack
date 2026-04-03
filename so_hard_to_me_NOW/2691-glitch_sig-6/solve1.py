from pwn import *
import math
import subprocess
import os
import time
from Crypto.Util.number import inverse

# 빠른 리트라이 루프에서 pwntools의 기본 로그가 너무 길어지는 것을 방지하되,
# 중요한 디버깅 정보는 직접 print로 상세히 출력하도록 error 레벨로 설정합니다.
context.log_level = 'error'

# ==============================================================================
# C 소스 코드 (최초 1회만 컴파일)
# ==============================================================================
C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

#define MAX_SIGS 20

mpz_t sigs[MAX_SIGS];
mpz_t q;

void strip_small(mpz_t p_cand) {
    int primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
    for(int i=0; i<15; i++) {
        while (mpz_divisible_ui_p(p_cand, primes[i])) {
            mpz_divexact_ui(p_cand, p_cand, primes[i]);
        }
    }
}

int main() {
    FILE *f = fopen("data.txt", "r");
    if(!f) return 1;
    
    mpz_init(q);
    gmp_fscanf(f, "%Zd", q);
    
    int num_sigs;
    fscanf(f, "%d", &num_sigs);
    for(int i=0; i<num_sigs; i++) {
        mpz_init(sigs[i]);
        gmp_fscanf(f, "%Zd", sigs[i]);
    }
    fclose(f);
    
    mpz_t LHS, RHS, g, p_cand, t1, t2, t3;
    mpz_inits(LHS, RHS, g, p_cand, t1, t2, t3, NULL);
    
    mpz_t A_list[50], B_list[50];
    for(int i=0; i<50; i++) {
        mpz_init(A_list[i]);
        mpz_init(B_list[i]);
    }
    
    // 최대 6번 비트까지만 아주 빠르게 훑고 포기하도록 설정 (파이썬에서 타임아웃으로도 제어됨)
    for (int b_max = 1; b_max <= 6; b_max++) {
        long long deltas[50];
        int D = 0;
        for(int b=0; b<=b_max; b++) {
            deltas[D++] = 1LL << b;
            deltas[D++] = -(1LL << b);
        }
        
        int search_sigs = b_max + 4;
        if (search_sigs > num_sigs) search_sigs = num_sigs;
        
        for (int i0 = 0; i0 < search_sigs - 3; i0++) {
            for (int i1 = i0 + 1; i1 < search_sigs - 2; i1++) {
                for (int i2 = i1 + 1; i2 < search_sigs - 1; i2++) {
                    for (int i3 = i2 + 1; i3 < search_sigs; i3++) {
                        
                        for (int k0 = 0; k0 < D; k0++) {
                            for (int k1 = 0; k1 < D; k1++) {
                                long long d0 = deltas[k0];
                                long long d1 = deltas[k1];
                                
                                int num_A = 0;
                                for (int k2 = 0; k2 < D; k2++) {
                                    long long d2 = deltas[k2];
                                    long long u = d0 - d1, v = d1 - d2;
                                    if (u == 0 || v == 0 || u + v == 0) continue;
                                    
                                    long long p_S0 = v > 0 ? v : 0, n_S0 = v > 0 ? 0 : -v;
                                    long long p_S2 = u > 0 ? u : 0, n_S2 = u > 0 ? 0 : -u;
                                    long long p_S1 = (u+v) > 0 ? (u+v) : 0, n_S1 = (u+v) > 0 ? 0 : -(u+v);
                                    
                                    mpz_pow_ui(t1, sigs[i0], p_S0); mpz_pow_ui(t2, sigs[i2], p_S2); mpz_pow_ui(t3, sigs[i1], n_S1);
                                    mpz_mul(LHS, t1, t2); mpz_mul(LHS, LHS, t3);
                                    
                                    mpz_pow_ui(t1, sigs[i0], n_S0); mpz_pow_ui(t2, sigs[i2], n_S2); mpz_pow_ui(t3, sigs[i1], p_S1);
                                    mpz_mul(RHS, t1, t2); mpz_mul(RHS, RHS, t3);
                                    
                                    mpz_sub(A_list[num_A], LHS, RHS);
                                    mpz_abs(A_list[num_A], A_list[num_A]);
                                    if (mpz_sgn(A_list[num_A]) > 0) num_A++;
                                }
                                
                                if (num_A == 0) continue;
                                
                                int num_B = 0;
                                for (int k3 = 0; k3 < D; k3++) {
                                    long long d3 = deltas[k3];
                                    long long u = d0 - d1, v = d1 - d3;
                                    if (u == 0 || v == 0 || u + v == 0) continue;
                                    
                                    long long p_S0 = v > 0 ? v : 0, n_S0 = v > 0 ? 0 : -v;
                                    long long p_S3 = u > 0 ? u : 0, n_S3 = u > 0 ? 0 : -u;
                                    long long p_S1 = (u+v) > 0 ? (u+v) : 0, n_S1 = (u+v) > 0 ? 0 : -(u+v);
                                    
                                    mpz_pow_ui(t1, sigs[i0], p_S0); mpz_pow_ui(t2, sigs[i3], p_S3); mpz_pow_ui(t3, sigs[i1], n_S1);
                                    mpz_mul(LHS, t1, t2); mpz_mul(LHS, LHS, t3);
                                    
                                    mpz_pow_ui(t1, sigs[i0], n_S0); mpz_pow_ui(t2, sigs[i3], n_S3); mpz_pow_ui(t3, sigs[i1], p_S1);
                                    mpz_mul(RHS, t1, t2); mpz_mul(RHS, RHS, t3);
                                    
                                    mpz_sub(B_list[num_B], LHS, RHS);
                                    mpz_abs(B_list[num_B], B_list[num_B]);
                                    if (mpz_sgn(B_list[num_B]) > 0) num_B++;
                                }
                                
                                for(int a=0; a<num_A; a++) {
                                    for(int b=0; b<num_B; b++) {
                                        mpz_gcd(g, A_list[a], B_list[b]);
                                        if (mpz_cmp(g, q) > 0) {
                                            mpz_divexact(p_cand, g, q);
                                            strip_small(p_cand);
                                            size_t bits = mpz_sizeinbase(p_cand, 2);
                                            if (bits >= 255 && bits <= 257) {
                                                gmp_printf("%Zd\n", p_cand);
                                                return 0;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    printf("0\n");
    return 0;
}
"""

def compile_c_code():
    print(f"[*] C 연산 모듈을 최초 1회 컴파일합니다... (디버깅 정보: 최적화 플래그 -O3 사용)")
    with open("solve_p.c", "w") as f:
        f.write(C_SOURCE)
    subprocess.run(["gcc", "-O3", "solve_p.c", "-o", "solve_p", "-lgmp"], check=True)
    print("[+] 컴파일 완료!\n")

def main():
    compile_c_code()
    
    host, port = '127.0.0.1', 5000
    attempt = 1
    p, q, unique_sigs = None, None, None
    r = None

    # "럭키 케이스"가 뜰 때까지 무한 리트라이
    while True:
        print("="*60)
        print(f"🔄 [리트라이 시도 #{attempt}] 새로운 Faulty Sig 수집 및 연산 시작")
        print("="*60)
        
        try:
            r = remote(host, port)
            faulty_sigs = []
            
            for _ in range(20):
                line = r.recvline().decode('utf-8').strip()
                if "faulty_sig =" in line:
                    sig_val = int(line.split("=")[1].strip())
                    faulty_sigs.append(sig_val)
                    
            unique_sigs = list(set(faulty_sigs))
            print(f"[*] 데이터 수신 완료. (고유한 서명 개수: {len(unique_sigs)}개)")
            
            # Step 1: 소수 q 구하기
            q_cand = abs(unique_sigs[0] - unique_sigs[1])
            for i in range(2, len(unique_sigs)):
                q_cand = math.gcd(q_cand, abs(unique_sigs[i-1] - unique_sigs[i]))
                
            for small_p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
                while q_cand % small_p == 0:
                    q_cand //= small_p
            q = q_cand
            
            print(f"[DEBUG] 복구된 q의 길이: {q.bit_length()} bits")
            if q.bit_length() > 260 or q.bit_length() < 250:
                print(f"[!] [경고] q가 256비트 부근이 아닙니다. 이 세트는 건너뜁니다.")
                r.close()
                attempt += 1
                continue
                
            # Step 2: C 코드로 p 탐색 (타임아웃 2.0초 제한)
            with open("data.txt", "w") as f:
                f.write(f"{q}\n")
                f.write(f"{len(unique_sigs)}\n")
                for sig in unique_sigs:
                    f.write(f"{sig}\n")
            
            print(f"[*] C 연산기 실행 중... (제한 시간: 2.0초)")
            start_time = time.time()
            
            try:
                # 2초 동안 답이 안 나오면 강제로 Process Kill 후 Exception 발생
                result = subprocess.run(["./solve_p"], capture_output=True, text=True, timeout=2.0)
                elapsed = time.time() - start_time
                
                p_str = result.stdout.strip()
                if p_str and p_str != "0":
                    p = int(p_str)
                    print(f"  -> [DEBUG] C 연산 소요 시간: {elapsed:.3f}초")
                    print(f"[+] ✨ 엄청난 운입니다! 소수 p를 초고속으로 복구했습니다!")
                    print(f"  -> [DEBUG] 복구된 p 길이: {p.bit_length()} bits")
                    print(f"  -> [DEBUG] p = {p}")
                    break # 성공 시 무한 루프 탈출!
                else:
                    print(f"  -> [DEBUG] C 연산 소요 시간: {elapsed:.3f}초")
                    print("[-] 작은 비트 에러 조합이 없습니다 (운빨 실패). 즉시 리트라이합니다.")
                    
            except subprocess.TimeoutExpired:
                elapsed = time.time() - start_time
                print(f"  -> [DEBUG] C 연산 소요 시간: {elapsed:.3f}초")
                print("[-] ⏳ 타임아웃 발생! 큰 에러 비트가 많아 버벅거립니다. 강제 종료하고 리트라이합니다.")

        except Exception as e:
            print(f"[-] 예상치 못한 에러 발생: {e}")
            
        # 실패 시 연결을 닫고 다음 루프로 넘어감
        if r:
            r.close()
        attempt += 1
        time.sleep(0.1) # 서버 과부하 방지용 짧은 대기

    # ==============================================================================
    # 루프를 성공적으로 탈출했다면(p, q 획득) 원본 msg 복구를 진행합니다.
    # ==============================================================================
    print("\n" + "="*60)
    print(f"[*] [Step 3] p, q를 바탕으로 원본 msg 브루트포싱을 시작합니다...")
    e = 65537
    phi = (p - 1) * (q - 1)
    N = p * q
    d = inverse(e, phi)
    dp = d % (p - 1)
    
    S_target = unique_sigs[0]
    m_q = pow(S_target, e, q)
    p_inv = inverse(p, q)
    
    msg = None
    for bit in range(64):
        for sign in (1, -1):
            delta = sign * (1 << bit)
            dp_fault = (dp + delta) % (p - 1)
            
            try:
                e_fault = inverse(dp_fault, p - 1)
            except ValueError:
                continue
                
            m_p = pow(S_target % p, e_fault, p)
            k = ((m_q - m_p) * p_inv) % q
            m_cand = m_p + p * k
            
            if 490 <= m_cand.bit_length() <= 505:
                msg = m_cand
                print(f"[+] msg 복원 완료! (에러 위치: {bit}번 비트)")
                print(f"  -> [DEBUG] 복원된 msg = {msg}")
                break
        if msg is not None: break

    print("\n" + "="*60)
    print(f"[*] [Step 4] 복구된 메시지를 서버에 전송하여 Flag를 탈취합니다...")
    r.sendlineafter(b"> ", str(msg).encode())
    
    print("[*] 서버 응답(Flag) 대기 중...")
    try:
        result = r.recvall(timeout=5).decode('utf-8')
        print(f"\n[+] 🚩 최종 획득 결과:\n{result}")
    except Exception as e:
        print(f"[-] Flag 수신 중 에러 발생: {e}")
    
    # 임시 파일 정리
    try:
        os.remove("data.txt")
        os.remove("solve_p.c")
        os.remove("solve_p")
    except:
        pass

if __name__ == "__main__":
    main()