from Crypto.Util.number import long_to_bytes

# --- 문제 데이터 ---
ct_base10 = "핵천7백1십2무량대수7천2백8십5불가사의8백5십나유타4천3백핵십핵아승기1천7백8십2항하사6천핵백핵십3극3천핵백9십핵재1천핵백핵십6정5천핵백4십핵간핵백1십구6천7백8십양8천2백5십6자3천핵백7십핵해3천핵경핵천5백9십1조9천4백6십3억8천5백5십만6천1백7십3"
ct_base2 = "100핵1핵0010핵10핵00111101핵01핵01000001핵핵000핵10핵0111010핵1111010핵0핵0000핵10001핵10001000핵0111110핵11100100110000011핵0핵01010111110111001핵핵01100핵001101100핵111011000핵1001101011핵핵1011101핵001001핵0핵001핵핵00핵0011010100111핵110011111100핵핵1111001111핵1핵핵111핵01"

unit1 = ["","십","백","천"]
unit2 = ["","만","억","조","경","해","자","양","구","간","정","재","극","항하사","아승기","나유타","불가사의","무량대수"]

# --- 1. Base 10 파싱 (기존과 동일) ---
def parse_korean_number(korean_str):
    unknowns = [] 
    known_value = 0
    current_str = korean_str
    
    for i in range(len(unit2)-1, -1, -1):
        u2 = unit2[i]
        chunk = ""
        if u2 == "": chunk = current_str 
        else:
            if u2 in current_str:
                parts = current_str.split(u2)
                chunk = parts[0]; current_str = parts[1]
            else: continue 
        
        base_power = i * 4
        temp_chunk = chunk
        for j in range(3, -1, -1):
            u1 = unit1[j]
            digit_char = '0'
            if u1 == "":
                if len(temp_chunk) > 0: digit_char = temp_chunk[-1]
            else:
                if u1 in temp_chunk:
                    idx = temp_chunk.index(u1)
                    digit_char = temp_chunk[idx-1]
                    temp_chunk = temp_chunk.replace(digit_char + u1, "", 1)
            
            power = base_power + j
            if digit_char == '핵': unknowns.append(power)
            elif digit_char in '123456789': known_value += int(digit_char) * (10 ** power)
                
    return known_value, sorted(unknowns)

base_val, unknown_powers = parse_korean_number(ct_base10)
print(f"[+] 파싱 완료. 미지수 개수: {len(unknown_powers)}")

# --- 2. Base 2 암호문을 비트 마스크로 변환 (속도 최적화 핵심) ---
# 문자열 비교 대신 (val & mask) == target 연산을 하기 위해 정수로 변환
target_bits_val = 0
target_bits_mask = 0

# ct_base2는 bin(pt)[2:] 형식이므로 index 0이 가장 높은 자릿수(MSB)
# 하지만 비트 연산은 LSB(오른쪽 끝)가 0번 비트이므로 역순으로 처리 필요
for char in ct_base2:
    target_bits_val <<= 1
    target_bits_mask <<= 1
    if char != '핵':
        target_bits_mask |= 1 # 검증해야 할 위치면 1
        if char == '1':
            target_bits_val |= 1 # 값이 1이면 1

full_length = len(ct_base2)
print("[+] 비트 마스크 생성 완료")

# --- 3. 고속 DFS Solver ---
def solve_fast(idx, current_val):
    # 1. 종료 조건: 모든 미지수를 다 채움
    if idx == len(unknown_powers):
        # 전체 길이 체크
        if current_val.bit_length() != full_length:
            return
        # 전체 비트 일치 여부 체크
        if (current_val & target_bits_mask) == target_bits_val:
            print(f"\n[!] Flag Found!")
            try:
                print(f"Decoded: {long_to_bytes(current_val).decode()}")
            except:
                print(f"Value: {current_val}")
            exit() # 찾으면 즉시 종료
        return

    # 2. 가지치기 (Pruning) 로직
    # 현재 단계: unknown_powers[idx] (p1) 자리를 채울 예정
    # 다음 단계: unknown_powers[idx+1] (p2) 자리를 채울 예정
    # 10^p2 는 2진수로 p2개의 0으로 끝남.
    # 즉, 지금 p1 자리를 결정하고 나면, 0 ~ (p2 - 1) 번째 비트는 더 이상 변하지 않음!
    # 이 확정된 비트들이 target과 다르면 즉시 가지치기.
    
    current_power = unknown_powers[idx]
    
    # 다음 미지수의 파워 (없으면 전체 길이까지 검사)
    if idx + 1 < len(unknown_powers):
        next_power_limit = unknown_powers[idx+1]
    else:
        next_power_limit = full_length # 마지막은 끝까지 검사

    # 현재 자리(10^current_power)의 계수 1~9 대입
    term_unit = 10 ** current_power
    
    for digit in range(1, 10):
        next_val = current_val + digit * term_unit
        
        # [핵심 검증]
        # 0 ~ next_power_limit-1 비트까지만 마스킹해서 비교
        # 파이썬은 (1 << k) - 1 로 0~k-1 비트가 1인 마스크를 만듦
        
        check_mask = (1 << next_power_limit) - 1
        
        # 전체 타겟 마스크와 교집합 (검증 필요한 비트만 남김)
        effective_mask = target_bits_mask & check_mask
        
        if (next_val & effective_mask) == (target_bits_val & effective_mask):
            # 통과하면 다음 단계로
            solve_fast(idx + 1, next_val)

print("[+] 복호화 시작 (Fast Mode)...")
solve_fast(0, base_val)