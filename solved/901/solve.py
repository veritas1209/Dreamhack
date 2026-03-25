# 1. 타겟 문자열 (비교 대상)
target = "C@qpl==Bppl@<=pG<>@l>@Blsp<@l@AArqmGr=B@A>q@@B=GEsmC@ArBmAGlA=@q"

# 2. 역연산 1단계: XOR 3
step1 = [ord(c) ^ 3 for c in target]

# 3. 역연산 2단계: 배열 뒤집기
step2 = step1[::-1]

# 4. 역연산 3단계: 13 빼고 아스키 범위(0~127)로 맞추기
original_chars = [(val - 13) % 128 for val in step2]

# 5. 문자로 변환하여 조립
flag = "".join(chr(c) for c in original_chars)

# C 코드에서 printf("Flag is DH{%s}\n",input); 로 출력하므로
# 구한 문자열 자체가 우리가 입력해야 할 정답입니다.
print(f"입력해야 할 값(플래그): DH{{{flag}}}")