import os
from z3 import *

# Ghidra에서 추출한 정확한 캐릭터셋
CHARSET = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}.,: "

def solve():
    file_path = '996/output'
    if not os.path.exists(file_path):
        print("[-] output 파일이 없습니다.")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    parsed_paths = []
    curr_path = ""
    i = 0
    # 바이너리 바이트 단위로 트리 경로 완벽 파싱
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
        elif chunk == b'\xf0\x9f\x8c\xb3': # 🌳 Left (curr > new)
            curr_path += 'L'
            i += 4
        elif chunk == b'\xf0\x9f\x8c\xb2': # 🌲 Right (curr < new)
            curr_path += 'R'
            i += 4
        else:
            i += 1 

    FLAG_LEN = len(parsed_paths)
    print(f"[*] 파싱 완료! 총 문자열 길이: {FLAG_LEN}")

    # C언어의 (char) 형변환 부호 비교 완벽 구현
    def to_signed(bv):
        val_int = BV2Int(bv)
        return If(val_int > 127, val_int - 256, val_int)

    print("[*] Z3 탐색 시작 (XOR Key 0~255 고속 브루트포스)...")

    # Key를 Python 단에서 순회하여 Z3 연산 속도 극대화
    for key in range(256):
        s = Solver()
        flag = [BitVec(f'c_{idx}', 8) for idx in range(FLAG_LEN)]
        
        # 1. 캐릭터셋 제약 조건
        for idx in range(FLAG_LEN):
            s.add(Or([flag[idx] == c for c in CHARSET]))
        
        # 2. 유연한 플래그 앵커: 문자열 어딘가에 "DH{" 가 반드시 포함되어 있어야 함
        dh_match = []
        for idx in range(FLAG_LEN - 3):
            dh_match.append(And(flag[idx] == ord('D'), flag[idx+1] == ord('H'), flag[idx+2] == ord('{')))
        s.add(Or(dh_match))
        
        # 3. 트리 구조 부등식 제약 조건
        tree = {}
        is_valid_tree = True
        
        for idx, (path, term) in enumerate(parsed_paths):
            curr_node_path = ""
            for step in path:
                if curr_node_path not in tree:
                    is_valid_tree = False
                    break
                
                curr_idx = tree[curr_node_path]
                
                # XOR 결과값을 부호 있는 정수로 대소 비교
                val_new = to_signed(flag[idx] ^ key)
                val_curr = to_signed(flag[curr_idx] ^ key)
                
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
                s.add(flag[idx] == flag[curr_idx]) # 중복 노드 처리
        
        # 모순된 트리면 즉시 다음 키로 패스
        if not is_valid_tree:
            continue
        
        # 조건이 맞는 모델 탐색
        if s.check() == sat:
            m = s.model()
            result = "".join(chr(m[flag[idx]].as_long()) for idx in range(FLAG_LEN))
            print("\n" + "="*60)
            print(f"[+] 성공! 플래그를 복구했습니다 🎉")
            print(f"[*] 일치하는 XOR Key : {key:#04x}")
            print(f"\n[ 복구된 문자열 ]\n{result}")
            print("="*60 + "\n")
            return

    print("\n[-] 실패: 조건을 만족하는 플래그를 찾지 못했습니다.")

if __name__ == "__main__":
    solve()