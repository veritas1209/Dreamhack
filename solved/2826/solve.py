import sys
from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

print("[*] [DEBUG] 디버깅 모드로 익스플로잇을 시작합니다.")

# 1. 서버에서 받은 값들을 하드코딩합니다.
p = 936094875250801540060355915024576074656453283649223961920880958854521890034394331671
g = 526991985305142886524754133333069893669546671905391743727546088898674565286351654696
A = 500738311631924547465236824268992258215942326791923106454736104896213926578137492245
server_pub = 157903641548110768153365184644535484224743234242892590655694080380770752289150534190
iv_hex = "45851509dc53a0a8011f53fe26187588"
ct_hex = "281e78a57fe43ee40393560c7e389fc4b842ac171b2c7dd7dc9b4bbfde3abc4b"

print(f"\n[*] [DEBUG] 하드코딩된 파라미터 로드 완료.")

small_factors = [2, 3, 5, 7, 11, 13, 17, 19]
print(f"\n[*] [DEBUG] 하드코딩된 소인수 목록: {small_factors}")

M = 1
for x in small_factors:
    M *= x
print(f"[*] [DEBUG] 그룹의 위수(Order) M 계산 완료: {M}")

# 2. Pohlig-Hellman Algorithm
rem = []
print("\n[*] [DEBUG] Pohlig-Hellman 알고리즘 시작: 각 소인수 모듈러에 대한 a의 나머지 계산")
for r in small_factors:
    Mr = M // r
    gr = pow(g, Mr, p)
    Ar = pow(A, Mr, p)
    print(f"  [-] [DEBUG] 소인수 r={r:<2} 처리 중 (Mr={Mr}, gr={gr % 10000}..., Ar={Ar % 10000}...)")
    
    for i in range(r):
        if pow(gr, i, p) == Ar:
            rem.append(i)
            print(f"  [+] [DEBUG] 찾았습니다! a ≡ {i} (mod {r})")
            break

# 3. Chinese Remainder Theorem (CRT)
print("\n[*] [DEBUG] 중국인의 나머지 정리(CRT)를 이용해 원래의 a 복원 시작")
a = 0
for i in range(len(small_factors)):
    r = small_factors[i]
    Mr = M // r
    Mr_inv = inverse(Mr, r)
    a = (a + rem[i] * Mr * Mr_inv) % M
    print(f"  [-] [DEBUG] r={r:<2} CRT 병합 중... 현재까지 복원된 a = {a}")

print(f"\n[+] [DEBUG] 최종 복원된 비밀키 a = {a}")

# 4. 키 복구 및 복호화
print("\n[*] [DEBUG] 공유 키(final_shared) 계산")
final_shared = pow(server_pub, a, p)
print(f"  [-] [DEBUG] final_shared = {final_shared}")

print("\n[*] [DEBUG] AES 키 파생 (SHA256)")
final_key = sha256(long_to_bytes(final_shared)).digest()[:16]
print(f"  [-] [DEBUG] 파생된 final_key (hex) = {final_key.hex()}")

print("\n[*] [DEBUG] AES-CBC 복호화 진행")
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)
cipher = AES.new(final_key, AES.MODE_CBC, iv)

try:
    decrypted = unpad(cipher.decrypt(ct), 16)
    print(f"\n[+] [DEBUG] 플래그 복호화 성공!")
    print("\n========== FLAG ==========")
    print(decrypted.decode())
    print("==========================")
except Exception as e:
    print(f"[-] [DEBUG] 복호화 실패 (패딩 에러 등): {e}")