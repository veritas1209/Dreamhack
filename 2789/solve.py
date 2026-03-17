import random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct_hex = "f0509319eab2fd63d05ad829b9e8ade42624ac30a2841ee1f130db7ad050a6b5943d959ba5fce6e169950505f310f105ba0b44ada8d8da605f20e97256e2db24"
ct = bytes.fromhex(ct_hex)

# 피치 업 되어 A Key가 되었으므로 대소문자 모두 테스트
keys_of_song = ['A', 'a']
tempos = [70] # 악보에 명시된 템포

# 이전 플래그의 변형 및 알맹이들 집중 공략
secrets = [
    "Old_songs_are_everything",
    "old_songs_are_everything",
    "Old songs are everything",
    "DH{Old_songs_are_everything}",
    "Diatonic Scale",
    "Diatonic_Scale"
]

print("🙏 제발 이번엔 열려라 참깨...\n")

for k in keys_of_song:
    for t in tempos:
        r = random.Random(k)
        nums = [r.getrandbits(32) for _ in range(t)]
        p = 1
        for i in nums:
            p *= i
            
        for s in secrets:
            key = sha256((str(s) + str(p)).encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            
            try:
                decrypted = unpad(cipher.decrypt(ct), 16)
                decrypted_text = decrypted.decode('utf-8')
                
                if "DH{" in decrypted_text:
                    print("========================================")
                    print(f"🎉 미쳤다 드디어 뚫었습니다!!!")
                    print(f"[+] 사용된 key_of_song : '{k}'")
                    print(f"[+] 사용된 secret      : '{s}'")
                    print(f"[+] 복호화된 Flag 원본 : {decrypted_text}")
                    print("========================================")
                    print(f"👉 최종 제출 시 '?->?' 부분을 'C7->C#m7'로 바꾸는 거 잊지 마세요!")
                    exit()
            except:
                pass

print("[-] 만약 이것도 안 되면... 출제자의 멱살을 잡아도 무죄입니다.")