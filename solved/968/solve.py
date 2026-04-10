import hashlib

# 우리가 악착같이 구해낸 완벽한 스도쿠 17개의 정답 배열
inputs = [11, 7, 13, 2, 5, 11, 7, 13, 3, 7, 11, 7, 13, 5, 3, 3, 5]

# 1. 17개의 숫자를 1바이트 char(bytes) 형태로 변환
byte_array = bytes(inputs)

# 2. C++ 코드와 동일하게 SHA256 해시값 계산
flag_hash = hashlib.sha256(byte_array).hexdigest()

# 3. 플래그 포맷에 맞춰 출력!
print("\n[🚩] 드디어 획득한 최종 플래그입니다!")
print(f"DH{{{flag_hash}}}")