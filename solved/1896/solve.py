#!/usr/bin/env python3
import sys

# pwntools 및 z3 임포트 (오류 시 친절한 안내)
try:
    from z3 import *
except ImportError:
    print("[-] z3-solver가 설치되어 있지 않습니다. 'pip install z3-solver'를 실행하세요.")
    sys.exit(1)

try:
    from pwn import ELF
    import logging
    logging.getLogger('pwnlib').setLevel(logging.ERROR) # pwntools 불필요한 로그 숨김
    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False
    print("[!] pwntools가 없습니다. 파일 직접 읽기 모드로 작동합니다.")

def read_encrypted_data(filename):
    print("\n[*] 1단계: 바이너리에서 스레드별 암호화 데이터를 추출합니다.")
    # ELF 구조상 .data 영역의 오프셋 0x4020, 0x4420, 0x4820, 0x4c20 에 각각 1024바이트씩 하드코딩 되어있음
    if HAS_PWNTOOLS:
        try:
            elf = ELF(filename, checksec=False)
            base = elf.address
            dat1 = elf.read(base + 0x4020, 1024)
            dat2 = elf.read(base + 0x4420, 1024)
            dat3 = elf.read(base + 0x4820, 1024)
            dat4 = elf.read(base + 0x4c20, 1024)
            print(f"  [+] pwntools를 이용하여 각 {len(dat1)} 바이트 성공적으로 추출 완료.")
            return dat1, dat2, dat3, dat4
        except Exception as e:
            print(f"  [!] pwntools 추출 실패({e}). 직접 파일 읽기로 전환합니다.")
    
    # pwntools 실패 혹은 미설치 시 Raw Binary에서 직접 오프셋 읽기 시도
    try:
        with open(filename, 'rb') as f:
            f.seek(0x4020)
            dat1 = f.read(1024)
            dat2 = f.read(1024)
            dat3 = f.read(1024)
            dat4 = f.read(1024)
            print(f"  [+] 파일 직접 읽기를 통해 각 {len(dat1)} 바이트 성공적으로 추출 완료.")
            return dat1, dat2, dat3, dat4
    except FileNotFoundError:
        print(f"[-] '{filename}' 파일을 찾을 수 없습니다. 바이너리 이름을 확인해주세요.")
        sys.exit(1)

def rc4_ksa_and_prga(reset_j, dat1, dat2, dat3, dat4):
    print(f"\n[*] 2단계: RC4 에뮬레이션 및 데이터 복호화 (j 레지스터 초기화 여부: {reset_j})")
    
    # 1. KSA (Key-Scheduling Algorithm)
    sbox = list(range(256))
    j = 0
    
    def ksa_round(key_bytes, round_idx):
        nonlocal j, sbox
        if reset_j:
            j = 0
        for i in range(256):
            # 모든 키 길이는 강제로 % 5 (디컴파일러 로직 i + (i/5)*-5)에 의해 제한됨
            j = (j + sbox[i] + key_bytes[i % 5]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        print(f"  [Debug] KSA 라운드 {round_idx} 완료 (사용 키: {key_bytes}) | 직후 j값: {j}")
        return list(sbox)
    
    # 디컴파일을 통해 확인한 정확한 5바이트 컷(Cut) 키 배열
    keys = [b"apple"[:5], b"banana"[:5], b"canary"[:5], b"theduck"[:5]]
    
    sbox1 = ksa_round(keys[0], 1)
    sbox2 = ksa_round(keys[1], 2)
    sbox3 = ksa_round(keys[2], 3)
    sbox4 = ksa_round(keys[3], 4)

    # 2. PRGA (Pseudo-Random Generation Algorithm)
    def prga(sbox_in, enc_data):
        sbox = list(sbox_in)
        out = bytearray(enc_data)
        j = 0 # PRGA 루프 진입 전에는 j가 0으로 초기화됨을 C코드(bVar11=0)에서 확인
        for i_idx in range(1024):
            i = (i_idx + 1) % 256
            j = (j + sbox[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
            k = sbox[(sbox[i] + sbox[j]) % 256]
            out[i_idx] ^= k
        return out

    dec1 = prga(sbox1, dat1)
    dec2 = prga(sbox2, dat2)
    dec3 = prga(sbox3, dat3)
    dec4 = prga(sbox4, dat4)
    print("  [+] PRGA 스트림 복호화 정상 완료.")
    
    return dec1, dec2, dec3, dec4

def run_z3_solver(dec1, dec2, dec3, dec4):
    print("\n[*] 3단계: Z3 Solver 방정식 구성 시작")
    solver = Solver()
    
    # 256비트(32바이트)를 Boolean 배열로 선언
    B = [Bool(f"b_{i}") for i in range(256)]
    out_exprs = []
    
    print("  [+] 4개의 스레드가 동일한 메모리 상태를 갖도록 제약 조건 1536개 생성 중...")
    for k in range(512):
        # 쌍으로 존재: [비트 인덱스, XOR 할 값]
        idx1, xor1 = dec1[2*k], dec1[2*k+1]
        idx2, xor2 = dec2[2*k], dec2[2*k+1]
        idx3, xor3 = dec3[2*k], dec3[2*k+1]
        idx4, xor4 = dec4[2*k], dec4[2*k+1]
        
        # 앞부분 약간만 디버깅용으로 출력
        if k < 2:
            print(f"    [Debug] idx {k}번 제약 -> Thread1(bit:{idx1}, xor:{xor1}), Thread2(bit:{idx2}, xor:{xor2})")

        # 각 스레드가 연산한 결과
        v1 = Xor(B[idx1], xor1 == 1)
        v2 = Xor(B[idx2], xor2 == 1)
        v3 = Xor(B[idx3], xor3 == 1)
        v4 = Xor(B[idx4], xor4 == 1)
        
        # 합이 고정되기 위해선 결과가 무조건 모두 일치해야 함 (Race Condition 극복 조건)
        solver.add(v1 == v2)
        solver.add(v2 == v3)
        solver.add(v3 == v4)
        
        out_exprs.append(v1)
        
    # 부모 프로세스의 검증: 합계가 384(0x180)이어야 함
    sum_expr = Sum([If(v, 1, 0) for v in out_exprs])
    solver.add(sum_expr == 384)
    print("  [+] 전체 합계 384(0x180) 제약 조건 적용 완료.")

    print("\n[*] 4단계: Z3 모델 검증 시작 (Solving...)")
    if solver.check() == sat:
        print("  [+] SAT! 정답을 찾았습니다!")
        m = solver.model()
        
        flag_bytes = []
        for byte_idx in range(32):
            val = 0
            for bit_idx in range(8):
                if is_true(m[B[byte_idx * 8 + bit_idx]]):
                    val |= (1 << bit_idx)
            flag_bytes.append(val)
            
        hex_str = bytes(flag_bytes).hex()
        print("\n" + "="*50)
        print(f"🎉 성공적으로 플래그를 복구했습니다!")
        print(f"📌 Flag: DH{{{hex_str}}}")
        print("="*50 + "\n")
        return True
    else:
        print("  [-] UNSAT. 해당 설정으로는 풀리지 않습니다.")
        return False

def main():
    target_binary = "./main"
    
    # 1. 암호화 데이터 추출
    dat1, dat2, dat3, dat4 = read_encrypted_data(target_binary)
    
    # 2. bVar3(j) 리셋 여부에 따른 2가지 분기 시도 (리버싱 불확실성 제거)
    # 디컴파일을 보면 부모 프로세스의 KSA 간 bVar3가 명시적으로 0으로 셋되지 않음 (False 먼저 시도)
    for reset_j in [False, True]:
        dec1, dec2, dec3, dec4 = rc4_ksa_and_prga(reset_j, dat1, dat2, dat3, dat4)
        if run_z3_solver(dec1, dec2, dec3, dec4):
            sys.exit(0)
            
    print("[-] 모든 조건에서 플래그 복구에 실패했습니다. 데이터를 다시 확인해주세요.")

if __name__ == "__main__":
    main()