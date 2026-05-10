import os
from z3 import *

# 어셈블리 덤프에서 확인된 정확한 69개의 캐릭터셋 (null 바이트 \x00 포함)
CHARSET = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}.,: \x00"

def solve():
    file_path = '996/output'
    if not os.path.exists(file_path):
        print(f"[-] '{file_path}' 파일이 없습니다.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    parsed_paths = []
    curr_path = ""
    i = 0
    # 4바이트씩 끊어서 이모지를 완벽하게 파싱
    while i < len(data):
        chunk = data[i:i+4]
        if chunk == b'\xf0\x9f\x8c\xb4':   # 🌴 Insert
            parsed_paths.append((curr_path, 'I'))
            curr_path = ""
            i += 4
        elif chunk == b'\xf0\x9f\x8e\x84': # 🎄 Equal
            parsed_paths.append((curr_path, 'E'))
            curr_path = ""
            i += 4
        elif chunk == b'\xf0\x9f\x8c\xb3': # 🌳 Left (New < Curr)
            curr_path += 'L'
            i += 4
        elif chunk == b'\xf0\x9f\x8c\xb2': # 🌲 Right (New > Curr)
            curr_path += 'R'
            i += 4
        else:
            i += 1 

    FLAG_LEN = len(parsed_paths)
    print(f"[*] 파싱 완료! 총 문자열 길이: {FLAG_LEN}")

    if FLAG_LEN == 0:
        print("[-] 파싱 실패: output 파일의 데이터가 올바르지 않습니다.")
        return

    print("[*] Z3 BitVec 모델 탐색 시작 (lar_solver 버그 회피)...")

    # Python 단에서 Key를 돌려 Z3의 부담을 최소화
    for key in range(256):
        s = Solver()
        
        # [핵심] Int 대신 8비트 BitVec를 사용하여 SMT 엔진 크래시 원천 차단
        V = [BitVec(f'V_{idx}', 8) for idx in range(FLAG_LEN)]
        
        # 1. 캐릭터셋 제약 조건 추가
        for idx in range(FLAG_LEN):
            s.add(Or([V[idx] == c for c in CHARSET]))
        
        # 2. 이진 탐색 트리(BST) 대소 관계 부등식 적용
        tree = {}
        is_valid_tree = True
        
        for idx, (path, term) in enumerate(parsed_paths):
            curr_node_path = ""
            for step in path:
                if curr_node_path not in tree:
                    is_valid_tree = False
                    break
                
                curr_idx = tree[curr_node_path]
                
                # BitVec의 ^ 연산 후 <, > 비교는 Z3 파이썬에서 자동으로
                # C언어와 동일한 '부호 있는 대소 비교(Signed Compare)'로 동작합니다.
                val_new = V[idx] ^ key
                val_curr = V[curr_idx] ^ key
                
                if step == 'L':
                    s.add(val_new < val_curr)
                elif step == 'R':
                    s.add(val_new > val_curr)
                    
                curr_node_path += step
            
            if not is_valid_tree:
                break
                
            if term == 'I':
                tree[curr_node_path] = idx
            elif term == 'E':
                curr_idx = tree[curr_node_path]
                s.add(V[idx] == V[curr_idx]) # 중복 문자 처리
        
        if not is_valid_tree:
            continue
            
        # 3. 플래그 포맷(DH{) 슬라이딩 윈도우 탐색
        dh_match = []
        for offset in range(FLAG_LEN - 2):
            dh_match.append(And(V[offset] == ord('D'), V[offset+1] == ord('H'), V[offset+2] == ord('{')))
        s.add(Or(dh_match))
        
        # BitVec 기반 검증
        if s.check() == sat:
            m = s.model()
            result = "".join(chr(m[V[idx]].as_long()) for idx in range(FLAG_LEN))
            
            print("\n" + "="*60)
            print(f"[+] 성공! 플래그를 완벽하게 복구했습니다 🎉")
            print(f"[*] 일치하는 XOR Key : {key:#04x}")
            print(f"\n[ 복구된 문자열 ]\n{result}")
            print("="*60 + "\n")
            return

    print("\n[-] 실패: 조건을 만족하는 플래그를 찾지 못했습니다.")

if __name__ == "__main__":
    solve()