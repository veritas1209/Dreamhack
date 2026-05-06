import itertools
import re
from PIL import Image

def solve_quilt():
    # 1. 바이너리에서 팔레트 추출
    try:
        with open('quilt', 'rb') as f:
            f.seek(0x2020)
            palette_raw = f.read(192)
    except FileNotFoundError:
        print("[-] 'quilt' 파일이 필요합니다.")
        return

    # [핵심 수정] 딕셔너리의 Value를 단일 인덱스가 아닌 '리스트'로 변경하여 중복 인덱스 보존
    palette = {}
    for i in range(64):
        r, g, b = palette_raw[i*3], palette_raw[i*3+1], palette_raw[i*3+2]
        
        # RGB, BGR 모두 고려
        for c in [(r, g, b), (b, g, r)]:
            if c not in palette:
                palette[c] = []
            if i not in palette[c]:
                palette[c].append(i)

    # 2. 이미지 파싱
    try:
        img = Image.open('quilt.bmp').convert('RGB')
    except FileNotFoundError:
        print("[-] 'quilt.bmp' 파일이 필요합니다.")
        return
        
    pixels = img.load()
    encoded_indices_options = []

    # 각 픽셀 블록에 대해 '가능한 모든 인덱스 리스트'를 추출
    for row in range(16):
        for col in range(16):
            actual_col = col if row % 2 == 0 else 15 - col
            x = actual_col * 32 + 16
            y = row * 32 + 16
            color = pixels[x, y]
            
            if color in palette:
                encoded_indices_options.append(palette[color])
            else:
                # 미세한 색상 오차가 있을 경우를 대비해 가장 가까운 색상 매칭
                closest = min(palette.keys(), key=lambda k: sum((a-b)**2 for a, b in zip(k, color)))
                encoded_indices_options.append(palette[closest])

    # 3. 4개의 인덱스(6비트)를 묶어 3바이트 청크 단위로 모든 경우의 수 생성
    chunk_options = []
    for i in range(0, 256, 4):
        opts0 = encoded_indices_options[i]
        opts1 = encoded_indices_options[i+1]
        opts2 = encoded_indices_options[i+2]
        opts3 = encoded_indices_options[i+3]
        
        possible_chunks = []
        # 각 자리마다 가능한 인덱스 조합을 모두 계산
        for v0, v1, v2, v3 in itertools.product(opts0, opts1, opts2, opts3):
            val = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3
            possible_chunks.append(bytes([(val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]))
        
        # 중복된 바이트 결과 제거
        chunk_options.append(list(set(possible_chunks)))

    # 4. 베이스 디코딩으로 플래그 문자열이 시작되는 오프셋(DH{ 위치) 찾기
    base_data = b''.join([opts[0] for opts in chunk_options])
    start_idx = base_data.find(b'DH{')
    
    if start_idx == -1:
        print("[-] 'DH{' 시작 지점을 찾을 수 없습니다.")
        return
        
    print(f"[*] 플래그 시작 위치 발견: offset {start_idx}")
    
    # 5. 플래그가 걸쳐있는 부분만 잘라내어 모든 인덱스 조합 탐색 (무차별 대입 최적화)
    start_chunk = start_idx // 3
    end_chunk = min(len(chunk_options), (start_idx + 68) // 3 + 1)
    flag_chunks = chunk_options[start_chunk:end_chunk]
    
    print(f"[*] 복구 대상 청크 수: {len(flag_chunks)}개 (올바른 조합 탐색 중...)")
    
    for seq in itertools.product(*flag_chunks):
        combined = b''.join(seq)
        local_offset = start_idx % 3
        flag_candidate = combined[local_offset:local_offset+68]
        
        try:
            # errors='ignore' 없이 엄격하게 아스키로 디코딩
            flag_str = flag_candidate.decode('ascii')
            # 완전히 소문자와 숫자로만 64글자인지 정규식 검증
            if re.match(r'^DH\{[a-z0-9]{64}\}$', flag_str):
                print(f"\n[+] 완벽한 플래그 복구 성공!")
                print(f"Flag: {flag_str}")
                return
        except UnicodeDecodeError:
            continue # 아스키로 변환 불가한 쓰레기값이 나오면 버리고 다음 조합 시도
            
    print("[-] 정규식 조건에 완벽히 맞는 플래그 조합을 찾지 못했습니다.")

if __name__ == "__main__":
    solve_quilt()