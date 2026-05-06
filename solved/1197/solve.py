from Crypto.Cipher import AES

# out.txt의 Hex 데이터
hex_data = (
    "E1 6D FC EC B9 34 22 BD 80 FF 05 45 56 E4 0B 7A "
    "05 E4 8D 3F D3 03 FB 01 F0 00 C5 70 F0 52 8F 68 "
    "3A DD 5A 23 B1 6F 19 3A 57 36 E6 D7 FB B1 FF 8B "
    "5F 4A 7B 8D 6D 0A 98 21 8B 04 00 C4 3D B7 19 82 "
    "58 E1 B1 23 B4 B6 6B D2 5D 0A BF 52 0F B3 08 E6 "
    "35 8B 25 B0 15 A4 87 2C 32 11 33 72 BF 5D BA CC "
    "94 F6 DB 09 D0 BC 31 7F D1 05 89 7C 06 F5 BF 58 "
    "B9 2D 0E 98 9C 23 C5 1F D5 8C B4 73 8E 28 75 D3 "
    "40 DC 68 F6 F3 2E 1E 0F BC 8B CF 6A D9 46 7D 1F "
    "7D 8E 08 66 B6 CF 43 5A 4B FC E0 BA CB B5 F9 A9 "
    "F3 96 6C B3 C6 2C 87 CF A5 CB 8D AE D0 67 5C F7 "
    "BE 13 2D 67 1B 2D F8 C6 B1 41 F9 20 D0 DB F3 16 "
    "60 50 6B 2F 1A 31 9E 19 8F 06 95 C3 BC 17 59 C5 "
    "F7 14 F7 8C 7D 8E 26 53 CA 67 FD 99 19 BF 84 35 "
    "E0 68 D4 A3 2D 17 09 94 87 F4 B7 F7 B3 BC C4 B3 "
    "E1 E5 74 27 B0 29 75 83 AA 3A 7F D1 DB B0 B8 5D"
)
ciphertext = bytes.fromhex(hex_data.replace(" ", ""))
iv = b'\x00' * 16

# 1. BSS / Data 섹션의 초기 하드코딩된 Key
base_key = [
    0x41, 0x28, 0x19, 0x4E, 0xA5, 0x7C, 0xA1, 0x41, 
    0x13, 0xCF, 0x88, 0xAC, 0x2A, 0xF0, 0xB7, 0xDA
]

# 2. _INIT_1 함수 로직: 누적 합(Cumulative Sum) 적용
for i in range(15):
    base_key[i+1] = (base_key[i+1] + base_key[i]) & 0xFF

# 3. _INIT_2 함수 로직: 랜덤 1바이트(0~255) XOR 브루트포스
for x in range(256):
    # 최종 조합된 키 생성
    final_key = bytes([(k ^ x) for k in base_key])
    
    # 복호화 진행
    cipher = AES.new(final_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # Dreamhack 플래그 포맷(DH{)을 포함하는지 확인
    if b"DH{" in plaintext:
        # 패딩용 널바이트 정리 후 출력
        flag = plaintext.decode('ascii', errors='ignore').rstrip('\x00')
        print(f"[+] 발견된 XOR 키 바이트: {hex(x)}")
        print(f"[!] 제작자가 입력한 내용(Flag): \n{flag}")
        break