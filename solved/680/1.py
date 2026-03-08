import signal

# 서버로부터 받은 challenge 값 (예시)
challenge = int(input("challenge 값을 입력하세요: "), 10)

# XOR 연산을 통해 원래 randn224 값을 복원
key = 0xdeaddeadbeefbeefcafecafe13371337DEFACED0DEFACED0
randn224 = challenge ^ key

# randn224를 그대로 입력
print("복원된 randn224 값:", randn224)
