# 코드 상단에 정의된 하드코딩된 배열
target_array = [
    148, 27, 14, 27, 34, 25, 10, 30, 48, 33, 23, 15, 19, 43, 46, 30,
    23, 15, 19, 43, 33, 34, 60, 54, 49, 47, 42, 42, 51, 80, 63, 137
]

# 중간 계산 값을 저장할 배열 (ModInput)
mod_input = [0] * 32

# 1. 덧셈 역연산 (Reverse Block 2)
# 마지막 글자는 '}' (ASCII 125)임이 확실하므로 시작점으로 사용
# IL 로직: Target[k] = ModInput[j] + ModInput[j-1]
# 여기서 k는 0부터 증가, j는 31부터 감소
# 즉, Target[0] = ModInput[31] + ModInput[30]
# 따라서, ModInput[30] = Target[0] - ModInput[31]

mod_input[31] = ord('}')  # Known last char

for k in range(31):
    j = 31 - k
    # ModInput[j-1]을 구하기 위해 이항
    mod_input[j-1] = target_array[k] - mod_input[j]

# 2. XOR 역연산 (Reverse Block 1)
# IL 로직: ModInput[i] = Input[i] ^ Input[i+1]
# 역연산: Input[i] = ModInput[i] ^ Input[i+1]
# 뒤에서부터 앞으로 계산

final_flag = [0] * 32
final_flag[31] = ord('}') # Known last char

for i in range(30, -1, -1):
    final_flag[i] = mod_input[i] ^ final_flag[i+1]

# 결과 출력
print("Flag:", "".join(chr(c) for c in final_flag))