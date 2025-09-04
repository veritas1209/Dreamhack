"""
C 코드를 Python으로 변환한 최적화된 DFS 솔루션
"""

# PNG 헤더와 암호화된 데이터
from_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 
             0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]
to_bytes = [0x83, 0x57, 0x44, 0x4B, 0x07, 0x0C, 0x1C, 0x09, 
            0x07, 0x08, 0x0B, 0x00, 0x47, 0x4A, 0x44, 0x5A]

# 타겟 키스트림
target = [from_bytes[i] ^ to_bytes[i] for i in range(16)]

print("최적화된 DFS 탐색")
print("=" * 50)
print(f"타겟 키스트림: {target}")

# 전역 변수
s = [-1] * 16
visit = [False] * 16
history = []
solutions = []

def search_key(pos, a, b):
    """DFS로 가능한 S-box 찾기"""
    global s, visit, history, solutions
    
    if pos >= 16:
        # 해답 찾음 - 초기 S-box 복구
        answer = s.copy()
        
        # swap 히스토리를 역순으로 되돌리기
        for i in range(15, -1, -1):
            from_idx, to_idx = history[i]
            answer[from_idx], answer[to_idx] = answer[to_idx], answer[from_idx]
        
        solutions.append(answer)
        print(f"가능한 S-box 발견: {answer}")
        return
    
    from_idx = (a + 1) % 16
    
    if s[from_idx] != -1:
        # s[from_idx]가 이미 결정된 경우
        require = target[pos] ^ s[from_idx]
        to_idx = (b + s[from_idx]) % 16
        
        if s[to_idx] == -1:
            # s[to_idx]에 require 넣기
            if require < 16 and not visit[require]:
                s[to_idx] = require
                visit[require] = True
                
                # swap
                s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                history.append((from_idx, to_idx))
                
                search_key(pos + 1, from_idx, to_idx)
                
                # 백트래킹
                history.pop()
                s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                s[to_idx] = -1
                visit[require] = False
        else:
            # s[to_idx]가 이미 결정된 경우
            if s[to_idx] == require:
                # swap
                s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                history.append((from_idx, to_idx))
                
                search_key(pos + 1, from_idx, to_idx)
                
                # 백트래킹
                history.pop()
                s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
    else:
        # s[from_idx]가 결정되지 않은 경우 - 모든 가능한 값 시도
        for i in range(16):
            if not visit[i]:
                s[from_idx] = i
                visit[i] = True
                
                require = target[pos] ^ s[from_idx]
                to_idx = (b + s[from_idx]) % 16
                
                if require < 16:
                    if s[to_idx] == -1 and not visit[require]:
                        # s[to_idx]에 require 넣기
                        s[to_idx] = require
                        visit[require] = True
                        
                        # swap
                        s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                        history.append((from_idx, to_idx))
                        
                        search_key(pos + 1, from_idx, to_idx)
                        
                        # 백트래킹
                        history.pop()
                        s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                        s[to_idx] = -1
                        visit[require] = False
                    elif s[to_idx] != -1 and s[to_idx] == require:
                        # s[to_idx]가 이미 require로 설정된 경우
                        # swap
                        s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                        history.append((from_idx, to_idx))
                        
                        search_key(pos + 1, from_idx, to_idx)
                        
                        # 백트래킹
                        history.pop()
                        s[from_idx], s[to_idx] = s[to_idx], s[from_idx]
                
                s[from_idx] = -1
                visit[i] = False

# DFS 실행
print("\nDFS 탐색 시작...")
search_key(0, 0, 0)

if solutions:
    print(f"\n총 {len(solutions)}개의 가능한 S-box 발견")
    
    # 첫 번째 솔루션으로 복호화
    S = solutions[0]
    print(f"\n사용할 S-box: {S}")
    
    # 복호화
    def decrypt_with_sbox(S):
        def stream():
            i, j = 0, 0
            S_copy = S.copy()
            while True:
                i = (i + 1) % 16
                j = (j + S_copy[i]) % 16
                S_copy[i], S_copy[j] = S_copy[j], S_copy[i]
                yield S_copy[i] ^ S_copy[j]
        
        input_file = r'C:\Users\hajin\hacking_study\dreamhack\1791\image.png.enc'
        output_file = 'solution.png'
        
        print(f"\n복호화 시작: {input_file}")
        
        try:
            with open(input_file, 'rb') as f:
                encrypted = f.read()
            
            decrypted = bytearray()
            stream_gen = stream()
            
            for idx, byte in enumerate(encrypted):
                decrypted.append(byte ^ next(stream_gen))
                
                if idx % 500000 == 0 and idx > 0:
                    print(f"진행: {idx}/{len(encrypted)} ({idx/len(encrypted)*100:.1f}%)")
            
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            print(f'\n✓ 복호화 완료: {output_file}')
            print(f'파일 크기: {len(decrypted)} bytes')
            
            # PNG 검증
            if decrypted[:8] == bytes(from_bytes[:8]):
                print('✓ 유효한 PNG 파일입니다!')
                print('\n이미지를 열어서 플래그를 확인하세요!')
            else:
                print('⚠ PNG 헤더 불일치')
                
        except Exception as e:
            print(f"에러: {e}")
    
    decrypt_with_sbox(S)
else:
    print("\nS-box를 찾지 못했습니다.")