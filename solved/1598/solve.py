import struct

def solve():
    # output.mp3 파일 읽기
    with open("output.mp3", "rb") as f:
        data = f.read()

    offset = 0
    bits = []

    # MP3 비트레이트 및 샘플링 레이트 테이블 (MPEG-1 / MPEG-2 Layer III 기준)
    bitrates_mpeg1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    bitrates_mpeg2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
    samplerates_mpeg1 = [44100, 48000, 32000, 0]
    samplerates_mpeg2 = [22050, 24000, 16000, 0]

    while offset < len(data):
        if offset + 4 > len(data):
            break
            
        header = data[offset:offset+4]
        
        # Sync word 확인 (11 bits가 모두 1인지 확인)
        if header[0] != 0xff or (header[1] >> 5) != 7:
            offset += 1
            continue
            
        # 헤더 정보 파싱 (C코드와 동일한 로직)
        version_id = (header[1] >> 3) & 3
        bitrate_idx = (header[2] >> 4) & 0xf
        samplerate_idx = (header[2] >> 2) & 3
        padding = (header[2] >> 1) & 1
        
        # 조작된 Private bit 추출
        private_bit = header[2] & 1 
        
        is_mpeg1 = (version_id == 3)
        br_table = bitrates_mpeg1 if is_mpeg1 else bitrates_mpeg2
        sr_table = samplerates_mpeg1 if is_mpeg1 else samplerates_mpeg2
        
        bitrate = br_table[bitrate_idx] * 1000
        samplerate = sr_table[samplerate_idx]
        
        if bitrate == 0 or samplerate == 0:
            offset += 1
            continue
            
        # 프레임 크기 계산
        samples_per_frame = 1152 if is_mpeg1 else 576
        frame_size = int((samples_per_frame / 8 * bitrate) / samplerate) + padding
        
        payload_size = frame_size - 4
        payload = data[offset+4 : offset+4+payload_size]
        
        if len(payload) < payload_size:
            break
            
        # Payload의 Parity 계산 (모든 바이트를 XOR 후, 비트 단위 축소)
        parity = 0
        for b in payload:
            parity ^= b
        parity ^= (parity >> 4)
        parity ^= (parity >> 2)
        parity = (parity ^ (parity >> 1)) & 1
        
        # 플래그 비트 복구 (Private bit XOR Parity)
        flag_bit = private_bit ^ parity
        bits.append(flag_bit)
        
        # 다음 프레임으로 이동
        offset += frame_size

    # 추출된 비트들을 8개씩 묶어 문자(ASCII)로 변환 (LSB First)
    flag = ""
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        char_val = sum(b << j for j, b in enumerate(byte_bits))
        flag += chr(char_val)

    # 보통 플래그 포맷(예: ctf{...} 등) 뒤에 쓰레기값이 붙을 수 있으니 출력 후 확인 필요
    print("Extracted Flag:")
    print(flag)

if __name__ == "__main__":
    solve()