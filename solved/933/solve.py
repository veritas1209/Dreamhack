from pwn import *

def solve_otp_reuse():
    # 문제 서버 주소
    host = 'host8.dreamhack.games'
    port = 17507
    
    # 소스코드에 하드코딩된 MASK 값 추출 (길이 역산용)[cite: 9]
    MASK_BIN_STR = '0b10010110101011100100111011100101101011110011001110000101111010111110010111100000111110000000010101101011001100010100010101111000111111100010001010110000010111110111110010001111110011110101001011111010100101010100001110010111111010001101111110011001010110011001010101010000001010100000101101001010010010100010100001011101011011010011010101111111010010100111011001100000101011100001010111111101000110011000110101111111010111001101111110011101101100011101001111111000010011010111100010111001100101011111101111111001'
    mask_int = int(MASK_BIN_STR, 2)
    
    print(f"[DEBUG] ================= 시작 =================")
    print(f"[DEBUG] 접속 준비: {host}:{port}")
    
    # 서버 접속
    p = remote(host, port)
    
    # 1. 서버로부터 암호화된 플래그(flag_enc) 수신
    p.recvuntil(b"flag_enc: ")
    flag_enc_str = p.recvline().decode('utf-8').strip()
    flag_enc_int = int(flag_enc_str, 2)
    print(f"[DEBUG] 서버로부터 flag_enc 수신 완료!")
    print(f"[DEBUG] flag_enc (2진수): {flag_enc_str[:50]}... (생략)")
    
    # 2. 64바이트 평문 페이로드 전송 (최대 길이를 꽉 채움)
    payload_text = "A" * 64
    print(f"\n[DEBUG] 64바이트 평문 페이로드 생성: {payload_text}")
    
    # 서버와 동일한 로직으로 평문을 2진수 정수로 변환[cite: 9]
    plist = ['0b']
    for ch in payload_text:
        plist.append(format(ord(ch), 'b').zfill(8))
    payload_bin_str = "".join(plist)
    payload_int = int(payload_bin_str, 2)
    print(f"[DEBUG] 페이로드 2진수 변환 완료 (길이: {len(payload_bin_str)})")
    
    p.sendlineafter(b"Plain text : ", payload_text.encode('utf-8'))
    
    # 3. 사용자 입력이 암호화된 결과(input_enc) 수신[cite: 9]
    p.recvuntil(b"input_enc: ")
    input_enc_str = p.recvline().decode('utf-8').strip()
    input_enc_int = int(input_enc_str)
    print(f"[DEBUG] 서버로부터 input_enc 수신 완료!")
    print(f"[DEBUG] input_enc (10진수): {input_enc_int}")
    
    # 4. new_key 역산 
    # 로직: input_enc = payload ^ new_key  =>  new_key = input_enc ^ payload
    new_key_int = input_enc_int ^ payload_int
    print(f"\n[DEBUG] 역산된 new_key (10진수): {new_key_int}")
    
    # 5. 원본 key 복구
    # 로직: new_key = original_key ^ mask  =>  original_key = new_key ^ mask
    original_key_int = new_key_int ^ mask_int
    print(f"[DEBUG] 원본 key 복구 완료 (10진수): {original_key_int}")
    
    # 6. 플래그 복구
    # 로직: flag_enc = flag ^ original_key  =>  flag = flag_enc ^ original_key
    flag_int = flag_enc_int ^ original_key_int
    
    # 복구된 정수를 다시 바이너리 스트링으로 변환
    flag_bin_str = bin(flag_int)[2:]
    
    # 앞자리의 0이 생략되었을 수 있으므로 8의 배수로 길이 맞춤 패딩
    if len(flag_bin_str) % 8 != 0:
        flag_bin_str = flag_bin_str.zfill(((len(flag_bin_str) // 8) + 1) * 8)
    
    print(f"[DEBUG] 복구된 플래그 바이너리: {flag_bin_str[:50]}... (생략)")
    
    # 8비트씩 잘라서 아스키 문자로 변환[cite: 9]
    flag_inner = ""
    for i in range(0, len(flag_bin_str), 8):
        byte_chunk = flag_bin_str[i:i+8]
        flag_inner += chr(int(byte_chunk, 2))
        
    print(f"\n[DEBUG] ================= 최종 결과 =================")
    print(f"[FLAG] DH{{{flag_inner}}}")
    
    p.close()

if __name__ == '__main__':
    solve_otp_reuse()