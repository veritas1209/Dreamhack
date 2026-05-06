import math
import re

def solve():
    # 1. 암호화된 파일 읽기
    with open("flag.jpg.crossing", "rb") as f:
        data = f.read()

    # 2. 파일 크기로부터 2D 그리드의 한 변의 길이(L) 계산
    L = int(math.isqrt(len(data)))
    if L * L != len(data):
        print("Warning: File size is not a perfect square.")
    
    # 2D 그리드 생성 (행 단위 분리)
    grid = [data[i*L : (i+1)*L] for i in range(L)]

    # 3. 정규표현식으로 유효한 단어(시퀀스) 찾기
    # 패턴: [0xFF] + [0x00,0x01,0xFF가 아닌 값들] + [0xFF] + [0x01의 연속] + [0xFF]
    pattern = re.compile(rb'\xff[^\x00\x01\xff]+\xff\x01+\xff')
    
    sequences = []
    
    # 가로 방향 스캔
    for row in grid:
        for match in pattern.finditer(bytes(row)):
            sequences.append(list(match.group(0)))

    # 세로 방향 스캔
    for col_idx in range(L):
        col_bytes = bytes([grid[row_idx][col_idx] for row_idx in range(L)])
        for match in pattern.finditer(col_bytes):
            sequences.append(list(match.group(0)))

    # 4. 시퀀스 파싱 및 니블(nibble) 복원
    nibbles = {}
    for seq in sequences:
        mid_ff_idx = seq.index(0xff, 1)
        
        # 위치 인덱스 데이터 추출 (첫 번째 0xff와 중간 0xff 사이)
        id_bytes = seq[1:mid_ff_idx]
        
        # 니블 값 추출: 1의 개수 - 1 (중간 0xff와 마지막 0xff 사이)
        ones_count = len(seq) - mid_ff_idx - 2
        nibble_value = ones_count - 1
        
        # 위치 인덱스 계산 (Base-253 디코딩)
        val = 0
        multiplier = 1
        for b in id_bytes:
            val += (b - 2) * multiplier  # +2 더해졌던 것을 복구
            multiplier *= 253
        nibble_index = val - 1
        
        # 딕셔너리에 저장 (가로/세로 중복 추출 방지용)
        nibbles[nibble_index] = nibble_value

    if not nibbles:
        print("No valid sequences found.")
        return

    # 5. 원본 파일로 재조립
    max_idx = max(nibbles.keys())
    original_data = bytearray()
    
    # 니블을 2개씩 짝지어 1바이트로 복원 (High Nibble << 4 | Low Nibble)
    for i in range((max_idx // 2) + 1):
        high = nibbles.get(i * 2, 0)
        low = nibbles.get(i * 2 + 1, 0)
        original_data.append((high << 4) | low)
        
    # 결과 저장
    with open("flag.jpg", "wb") as f:
        f.write(original_data)
        
    print(f"[+] 성공적으로 복호화 완료! ({len(original_data)} bytes saved to flag.jpg)")

if __name__ == "__main__":
    solve()