import string

# 알파벳 상수
ALPHABET = string.ascii_uppercase

# 강제로 지정한 알파벳 매핑
forced_map = {
    'O': 'A',
    'X': 'F',
    'W': 'L',
    'R': 'H',
    'T': 'D',
    'B': 'O',
    'H': 'T',
    'M': 'U',
    'A': 'P',
    'P': 'I',
    'L': 'S',
    'C': 'R',
    'N': 'Y',
    'E': 'B',
    'S': 'N',
    'Q': 'V',
    'Z': 'X',
    'U': 'C',
    'D': 'M',
    'G': 'W',
    'F': 'G',
    'K': 'K',
    'J': 'Q',
    'I': 'J',
    'Y': 'Z',
    'V': 'E'

}

# 대소문자 매핑 생성
mapping_upper = forced_map
mapping_lower = {k.lower(): v.lower() for k, v in mapping_upper.items()}

# 복호화 함수: 지정된 문자만 해석, 나머지는 * 처리
def decode_partial(text, mapping_upper):
    mapping_lower = {k.lower(): v.lower() for k, v in mapping_upper.items()}
    result = ""
    for c in text:
        if c.isupper():
            result += mapping_upper.get(c, '*') if c.isalpha() else c
        elif c.islower():
            result += mapping_lower.get(c, '*') if c.isalpha() else c
        else:
            result += c  # 공백, 구두점 등
    return result

# 입력 파일 전체 읽기
with open("MyNewBook.txt", 'r', encoding='utf-8') as f:
    original_lines = f.readlines()

# 복호화된 전체 라인 처리
decoded_lines = [decode_partial(line, mapping_upper) for line in original_lines]

# 결과 저장
with open("Decoded_Partial.txt", 'w', encoding='utf-8') as f:
    f.writelines(decoded_lines)

print("복호화 완료. 결과는 Decoded_Partial.txt에 저장되었습니다.")
