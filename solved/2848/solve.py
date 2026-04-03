# 1글자로 인식되지만 1,211 바이트를 차지하는 페이로드 생성기
base_char = "a"
combining_char = "\u0300" # 2바이트 결합 문자

# 1바이트(a) + 2바이트 * 605 = 1211 바이트
payload = base_char + (combining_char * 605)

print(payload)