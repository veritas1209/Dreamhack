from Crypto.Util.number import long_to_bytes
import itertools
import re

# 한국어 숫자 단위 정의
unit1 = ["","십","백","천"]
unit2 = ["","만","억","조","경","해","자","양","구","간","정","재","극","항하사","아승기","나유타","불가사의","무량대수"]

# 주어진 암호문
base10_encrypted = "핵천7백1십2무량대수7천2백8십5불가사의8백5십나유타4천3백핵십핵아승기1천7백8십2항하사6천핵백핵십3극3천핵백9십핵재1천핵백핵십6정5천핵백4십핵간핵백1십구6천7백8십양8천2백5십6자3천핵백7십핵해3천핵경핵천5백9십1조9천4백6십3억8천5백5십만6천1백7십3"
base2_encrypted = "100핵1핵0010핵10핵00111101핵01핵01000001핵핵000핵10핵0111010핵1111010핵0핵0000핵10001핵10001000핵0111110핵11100100110000011핵0핵01010111110111001핵핵01100핵001101100핵111011000핵1001101011핵핵1011101핵001001핵0핵001핵핵00핵0011010100111핵110011111100핵핵1111001111핵1핵핵111핵01"

def advanced_decrypt_base10(encrypted):
    """고급 Base10 복호화"""
    results = []
    
    # 1. 핵을 완전히 제거
    clean_text = encrypted.replace('핵', '')
    result = decode_korean_number(clean_text)
    if result:
        results.append(result)
        print(f"핵 제거: {result}")
    
    # 2. 핵 패턴 분석 - 연속된 핵들 특별 처리
    # 핵십핵 -> 십, 핵백핵 -> 백 등의 패턴
    pattern_fixes = [
        ('핵십핵', '십'),
        ('핵백핵', '백'),
        ('핵천핵', '천'),
        ('핵십', '십'),
        ('핵백', '백'),
        ('십핵', '십'),
        ('백핵', '백'),
    ]
    
    for i, (pattern, replacement) in enumerate(pattern_fixes):
        test_text = encrypted
        test_text = test_text.replace(pattern, replacement)
        test_text = test_text.replace('핵', '')  # 남은 핵들 제거
        result = decode_korean_number(test_text)
        if result and result not in results:
            results.append(result)
            print(f"패턴 수정 {i+1} ({pattern}->{replacement}): {result}")
    
    # 3. 핵을 특정 숫자들로 시도 (가장 가능성 높은 것들)
    common_replacements = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
    for replacement in common_replacements:
        test_text = encrypted.replace('핵', replacement)
        result = decode_korean_number(test_text)
        if result and result not in results:
            results.append(result)
            print(f"핵 -> {replacement}: {result}")
    
    return results

def advanced_decrypt_base2(encrypted):
    """고급 Base2 복호화"""
    results = []
    
    # 1. 핵을 완전히 제거
    clean_binary = encrypted.replace('핵', '')
    if all(c in '01' for c in clean_binary):
        try:
            result = int(clean_binary, 2)
            results.append(result)
            print(f"핵 제거 (Base2): {result}")
        except:
            pass
    
    # 2. 연속된 핵들을 단일 비트로 처리
    # 핵핵 -> 0 또는 1
    test_cases = [
        ('핵핵', '0'),
        ('핵핵', '1'),
        ('핵', '0'),
        ('핵', '1'),
    ]
    
    for pattern, replacement in test_cases:
        test_binary = encrypted.replace(pattern, replacement)
        if '핵' in test_binary:
            test_binary = test_binary.replace('핵', replacement)
        
        if all(c in '01' for c in test_binary):
            try:
                result = int(test_binary, 2)
                if result not in results:
                    results.append(result)
                    print(f"패턴 수정 (Base2) {pattern}->{replacement}: {result}")
            except:
                continue
    
    # 3. 제한된 브루트포스 - 핵이 많으면 샘플링
    hack_count = encrypted.count('핵')
    if hack_count <= 8:  # 적당한 수준에서만 전체 브루트포스
        for bits in itertools.product(['0', '1'], repeat=hack_count):
            test_binary = encrypted
            for bit in bits:
                test_binary = test_binary.replace('핵', bit, 1)
            
            if all(c in '01' for c in test_binary):
                try:
                    result = int(test_binary, 2)
                    if result not in results:
                        results.append(result)
                        if len(results) > 20:  # 너무 많은 결과 방지
                            break
                except:
                    continue
    
    return results

def decode_korean_number(text):
    """개선된 한국어 숫자 파서"""
    if not text:
        return None
    
    try:
        # 역순으로 되어있으므로 뒤집기
        text = text[::-1]
        
        # 전체 값
        total = 0
        
        # 큰 단위별로 분할
        parts = []
        current_part = ""
        
        i = 0
        while i < len(text):
            found_big_unit = False
            
            # 큰 단위 찾기 (역순이므로 긴 단위부터)
            for j in range(len(unit2) - 1, -1, -1):
                unit = unit2[j]
                if unit and text[i:].startswith(unit):
                    if current_part:
                        parts.append((current_part, j-1 if j > 0 else 0))
                    current_part = ""
                    parts.append(("", j))
                    i += len(unit)
                    found_big_unit = True
                    break
            
            if not found_big_unit:
                current_part += text[i]
                i += 1
        
        if current_part:
            parts.append((current_part, 0))
        
        # 각 파트 처리
        for part_text, multiplier in reversed(parts):
            if not part_text:
                continue
                
            part_value = parse_part(part_text)
            total += part_value * (10000 ** multiplier)
        
        return total if total > 0 else None
        
    except Exception as e:
        print(f"파싱 오류: {e}")
        return None

def parse_part(text):
    """4자리 이하의 한국어 숫자 파싱"""
    if not text:
        return 0
    
    value = 0
    current_num = 0
    
    i = 0
    while i < len(text):
        # 작은 단위 체크
        found_small_unit = False
        for j in range(len(unit1) - 1, -1, -1):
            unit = unit1[j]
            if unit and text[i:].startswith(unit):
                if current_num == 0:
                    current_num = 1  # 단위만 있으면 1로 간주
                value += current_num * (10 ** j)
                current_num = 0
                i += len(unit)
                found_small_unit = True
                break
        
        if not found_small_unit:
            if text[i].isdigit():
                current_num = int(text[i])
            i += 1
    
    # 남은 숫자 처리
    if current_num > 0:
        value += current_num
    
    return value

def check_flag_advanced(number):
    """더 관대한 플래그 검증"""
    try:
        flag_bytes = long_to_bytes(number)
        flag_text = flag_bytes.decode('ascii', errors='ignore')
        
        # DH{ 패턴 체크
        if 'DH{' in flag_text and '}' in flag_text:
            return flag_text
        
        # 플래그로 보이는 패턴 체크
        if flag_text.startswith('DH{') or 'flag{' in flag_text.lower():
            return flag_text
            
        # ASCII 문자로만 이루어져 있고 길이가 적당하면 출력
        if all(32 <= ord(c) <= 126 for c in flag_text) and 10 <= len(flag_text) <= 100:
            if '{' in flag_text and '}' in flag_text:
                return flag_text
                
    except Exception as e:
        pass
    return None

def main():
    print("=== 개선된 Dreamhack 2277 해결 ===\n")
    
    print("Base10 고급 복호화...")
    base10_results = advanced_decrypt_base10(base10_encrypted)
    print(f"\nBase10 후보 개수: {len(base10_results)}")
    
    print("\nBase2 고급 복호화...")
    base2_results = advanced_decrypt_base2(base2_encrypted)
    print(f"\nBase2 후보 개수: {len(base2_results)}")
    
    print("\n" + "="*50)
    print("플래그 검색 결과")
    print("="*50)
    
    all_candidates = set(base10_results + base2_results)
    
    found_flags = []
    for candidate in all_candidates:
        flag = check_flag_advanced(candidate)
        if flag:
            source = []
            if candidate in base10_results:
                source.append("Base10")
            if candidate in base2_results:
                source.append("Base2")
            
            print(f"🎉 플래그 발견 ({'/'.join(source)}): {flag}")
            found_flags.append((flag, source))
    
    if not found_flags:
        print("명확한 플래그를 찾지 못했습니다. 상위 후보들:")
        for i, candidate in enumerate(sorted(all_candidates)[:5]):
            try:
                text = long_to_bytes(candidate).decode('ascii', errors='ignore')
                print(f"{i+1}. {candidate} -> '{text}'")
            except:
                print(f"{i+1}. {candidate}")
    
    # 교집합 확인
    common = set(base10_results) & set(base2_results)
    if common:
        print(f"\n교집합 ({len(common)}개):")
        for candidate in common:
            flag = check_flag_advanced(candidate)
            if flag:
                print(f"✅ 교집합 플래그: {flag}")
            else:
                try:
                    text = long_to_bytes(candidate).decode('ascii', errors='ignore')
                    print(f"교집합 후보: {candidate} -> '{text}'")
                except:
                    print(f"교집합 후보: {candidate}")

if __name__ == "__main__":
    main()