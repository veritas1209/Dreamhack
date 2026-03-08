import sys

# 1. 암호화에 사용된 행렬
matrix = [
    [0x42, 0x1f, 0x88, 0x3a],
    [0xe1, 0x24, 0x9, 0x5c],
    [0x73, 0xa1, 0xff, 0x12],
    [0xb, 0x6d, 0x44, 0x9e]
]

# 2. 타겟 Hex 문자열
target_hex = "389fb36e33671b341e9b357232c6435a51b386b326763405eb407b3303d32c243466735836b411231dde32596336b3b2387338b53404837230b342133303b3591b61bbb450432008b2834b4d2eb3022b2cfcb4920b57cfb42d53359e33759b5c4d3493bb"

# 3. 행렬 역산 (NumPy 사용 권장, 여기서는 직접 구현을 위해 numpy 호출)
import numpy as np

M = np.array(matrix, dtype=float)
try:
    M_inv = np.linalg.inv(M)
except:
    print("Matrix is not invertible")
    sys.exit()

# 비트 연산 역함수
def reverse_bit_op(hex_chunk):
    val = int(hex_chunk, 16)
    # Check: (val ^ 0x1a2b)의 하위 3비트가 0이어야 함 (<< 3 의 결과였으므로)
    # 0x1a2b의 하위 3비트는 011(3)
    # 즉, val의 하위 3비트도 3이어야 XOR 결과가 0이 됨.
    if (val & 7) != 3:
        return None
    
    decoded = (val ^ 0x1a2b) >> 3
    return decoded

# 재귀적으로 Hex 문자열을 파싱하며 정답을 찾는 함수
def solve_block(hex_str, decoded_message):
    if not hex_str:
        print(f"[*] Found Flag: {decoded_message}")
        return True

    # 블록 하나(4글자)를 처리하기 위해 4개의 숫자가 필요함
    # 이 부분은 DFS로 4개의 유효한 Hex 덩어리를 찾아야 함
    # depth: 현재 찾은 숫자 개수 (0~3), current_nums: 찾은 숫자 리스트, str_idx: 현재 hex 위치
    
    stack = [(0, [], 0)] # (depth, numbers_list, hex_index)

    # 4개의 숫자를 찾는 내부 DFS
    def find_4_nums(h_str):
        # (index, found_numbers)
        q = [(0, [])]
        
        results = []
        
        while q:
            idx, nums = q.pop()
            
            # 4개를 다 찾았으면 반환
            if len(nums) == 4:
                results.append((idx, nums))
                continue
            
            # Hex 길이는 가변적임. 보통 4~6글자 사이일 확률이 높음 (값의 범위 상)
            # 하지만 안전하게 3~6글자 시도
            remaining = h_str[idx:]
            for length in range(4, 7): 
                if len(remaining) < length: break
                
                chunk = remaining[:length]
                val = reverse_bit_op(chunk)
                
                if val is not None:
                    new_nums = nums + [val]
                    q.append((idx + length, new_nums))
        return results

    # 현재 남은 hex string에서 가능한 4개 숫자 조합을 모두 찾음
    candidates = find_4_nums(hex_str)
    
    for next_idx, vector_y in candidates:
        # 역행렬 곱셈: X = M_inv * Y
        Y = np.array(vector_y)
        X = np.dot(M_inv, Y)
        
        # 유효성 검사: 복호화된 X가 모두 ASCII 범위 내의 정수여야 함
        # 부동소수점 오차 고려하여 round 처리
        X_rounded = np.round(X).astype(int)
        
        is_valid = True
        block_str = ""
        for char_code in X_rounded:
            # 일반적인 출력 가능 ASCII + Null(패딩)
            if not (0 <= char_code <= 127): 
                is_valid = False
                break
            if char_code == 0: continue # 패딩 무시
            block_str += chr(char_code)
            
        if is_valid:
            # 다음 블록으로 진행
            if solve_block(hex_str[next_idx:], decoded_message + block_str):
                return True

    return False

print("Solving...")
solve_block(target_hex, "")