import re

# VM의 바이트코드 파일을 읽어옵니다. (파일명이 다르면 수정하세요)
with open('command', 'rb') as f:
    data = f.read()

# 정규표현식을 통해 각 블록의 상수 A, B, C를 추출합니다.
# 패턴: '#' + 1바이트(레지스터) + 1바이트(값) 이 3번 반복되고 '(' 가 나옴
matches = re.findall(b'#.(.)#.(.)#.(.)\\(', data, re.DOTALL)

flag = ""

for A, B, C in matches:
    # 각 바이트 배열의 첫 번째 요소를 가져와 정수형으로 XOR 연산
    char_val = A[0] ^ B[0] ^ C[0]
    flag += chr(char_val)

# 스택 구조(LIFO)로 인해 플래그가 역순으로 검증되었으므로, 다시 뒤집어줍니다.
print("Flag:", flag[::-1])