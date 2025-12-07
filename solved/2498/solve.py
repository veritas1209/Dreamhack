# Whitespace Morse Code Decoder
# 09 = dot(.), 20 = dash(-), 0A = 문자 구분

# 하드코딩된 hex 데이터
hex_data = """09 20 20 20 20 0A 20 20 20 20 09 0A 09 20 20 20 20 0A 09 09 09 20 20 0A 09 09 20 20 20 0A 09 20 20 20 0A 09 09 20 20 20 0A 20 20 20 20 09 0A 09 20 20 20 20 0A 09 09 09 20 20 0A 09 20 20 20 20 0A 09 09 09 09 20 0A 09 09 20 20 20 0A 20 20 20 09 09 0A 20 20 20 20 20 0A 20 20 09 20 0A 09 20 20 20 20 0A 09 09 09 09 20 0A 09 09 20 20 20 0A 20 20 20 09 09 0A 20 20 20 20 20 0A 20 20 09 20 0A 09 20 20 20 20 0A 20 20 20 20 20 0A 09 20 20 20 20 0A 09 20 20 0A 09 09 20 20 20 0A 09 09 09 09 09 0A 09 09 20 20 20 0A 20 20 20 20 09 0A 09 09 20 20 20 0A 09 09 09 09 20 0A 20 20 20 20 20 0A 20 20 09 20 0A 09 20 20 20 20 0A 20 20 09 09 09 0A 09 09 20 20 20 0A 20 20 20 20 20 0A 09 09 20 20 20 0A 20 20 20 20 09 0A 20 20 20 20 20 0A 20 20 09 20 0A 09 20 20 20 20 0A 09 20 20 20 20 0A 09 09 20 20 20 0A 20 20 20 20 20 0A 09 20 20 20 20 0A 09 20 09 20 0A 09 20 20 20 20 0A 09 20 09 20 0A 09 09 20 20 20 0A 09 20 20"""

# 국제 모스 부호 사전
morse_code = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '{': '{', '}': '}', '_': '_', '-': '-'
}

print("=== Hex to Morse Decoder ===")
print("버전 1: 09 = dot (.), 20 = dash (-)")
print("버전 2: 09 = dash (-), 20 = dot (.)")
print()

# Hex 파싱
hex_list = hex_data.split()

# 0A로 구분된 각 그룹 만들기
groups = []
current_group = []

for hex_val in hex_list:
    if hex_val == '0A':
        if current_group:
            groups.append(current_group)
        current_group = []
    else:
        current_group.append(hex_val)

if current_group:
    groups.append(current_group)

print(f"총 {len(groups)}개 문자 발견")
print()

# 버전 1: 09 = ., 20 = -
print("=== 버전 1: 09=dot, 20=dash ===")
decoded_chars = []

for i, group in enumerate(groups, 1):
    morse = ''
    for hex_val in group:
        if hex_val == '09':
            morse += '.'
        elif hex_val == '20':
            morse += '-'
    
    if morse in morse_code:
        char = morse_code[morse]
    else:
        char = f'[{morse}]'
    
    print(f"{i:2d}. {morse:15s} -> {char}")
    decoded_chars.append(char)

print()
result1 = ''.join(decoded_chars)
print(f"결과 1: {result1}")
print()

# 버전 2: 09 = -, 20 = .
print("=== 버전 2: 09=dash, 20=dot ===")
decoded_chars2 = []

for i, group in enumerate(groups, 1):
    morse = ''
    for hex_val in group:
        if hex_val == '09':
            morse += '-'
        elif hex_val == '20':
            morse += '.'
    
    if morse in morse_code:
        char = morse_code[morse]
    else:
        char = f'[{morse}]'
    
    print(f"{i:2d}. {morse:15s} -> {char}")
    decoded_chars2.append(char)

print()
result2 = ''.join(decoded_chars2)
print(f"결과 2: {result2}")
print()

# 결과 2가 hex 문자열처럼 보임 - ASCII로 변환
print("=== 결과 2를 Hex → ASCII 변환 ===")
try:
    # hex 문자열을 bytes로 변환
    flag_bytes = bytes.fromhex(result2)
    flag = flag_bytes.decode('ascii')
    print(f"플래그: {flag}")
except Exception as e:
    print(f"변환 실패: {e}")