import random

# 목표 키스트림
target_keystream = [10, 7, 10, 12, 10, 6, 6, 3, 7, 8, 11, 13, 14, 2, 0, 8]

def test_seed(seed, name=""):
    """특정 seed 테스트"""
    random.seed(seed)
    S = list(range(16))
    random.shuffle(S)
    
    # RC4 스트림 생성 및 비교
    i = j = 0
    S_copy = list(S)
    
    for expected in target_keystream:
        i = (i + 1) % 16
        j = (j + S_copy[i]) % 16
        S_copy[i], S_copy[j] = S_copy[j], S_copy[i]
        if (S_copy[i] ^ S_copy[j]) != expected:
            return None
    
    print(f"✓ 찾았습니다! {name}")
    print(f"Seed: {seed}")
    print(f"S-box: {S}")
    return S

print("파일 크기 기반 Seed 테스트")
print("=" * 50)

# 파일 크기 관련 seed들
file_size = 4311958
seeds_to_try = [
    (file_size, "파일 크기 그대로"),
    (4311958, "직접 입력"),
    (file_size % 10000, "파일 크기 mod 10000"),
    (file_size % 100000, "파일 크기 mod 100000"),
    (file_size % 1000000, "파일 크기 mod 1000000"),
    (file_size // 1000, "파일 크기 / 1000"),
    (311958, "뒤 6자리"),
    (11958, "뒤 5자리"),
    (1958, "뒤 4자리"),
    (958, "뒤 3자리"),
    (58, "뒤 2자리"),
    (4311, "앞 4자리"),
    (431, "앞 3자리"),
    (43, "앞 2자리"),
]

found = False
for seed, description in seeds_to_try:
    print(f"\n시도: {description} = {seed}")
    S = test_seed(seed, description)
    if S:
        found = True
        break

if not found:
    print("\n파일 크기 직접 관련 seed 실패")
    print("다른 가능성 테스트...")
    
    # PNG 관련 매직 넘버
    png_seeds = [
        (0x89504E47, "PNG 헤더 시그니처"),
        (0x49454E44, "IEND 청크"),
        (0x49484452, "IHDR 청크"),
    ]
    
    for seed, description in png_seeds:
        print(f"\n시도: {description} = {seed}")
        S = test_seed(seed, description)
        if S:
            found = True
            break

if not found:
    print("\n마지막 시도: 간단한 seed들")
    for seed in range(100):
        S = test_seed(seed)
        if S:
            print(f"간단한 seed 발견: {seed}")
            found = True
            break

if found and S:
    print("\n" + "=" * 50)
    print("복호화 코드:")
    print("=" * 50)
    
    # 복호화 실행
    def decrypt():
        def stream():
            i, j = 0, 0
            S_copy = list(S)
            while True:
                i = (i + 1) % 16
                j = (j + S_copy[i]) % 16
                S_copy[i], S_copy[j] = S_copy[j], S_copy[i]
                yield S_copy[i] ^ S_copy[j]
        
        input_file = r'C:\Users\hajin\hacking_study\dreamhack\1791\image.png.enc'
        output_file = 'decrypted_forest.png'
        
        try:
            with open(input_file, 'rb') as f:
                encrypted = f.read()
            
            print(f"암호화된 파일 크기: {len(encrypted)} bytes")
            
            decrypted = bytearray()
            stream_gen = stream()
            
            for idx, byte in enumerate(encrypted):
                decrypted.append(byte ^ next(stream_gen))
                
                # 진행 상황 표시
                if idx % 100000 == 0:
                    print(f"복호화 진행: {idx}/{len(encrypted)} ({idx/len(encrypted)*100:.1f}%)")
            
            with open(output_file, 'wb') as f:
                f.write(decrypted)
            
            print(f'\n✓ 복호화 완료: {output_file}')
            print(f'출력 파일 크기: {len(decrypted)} bytes')
            
            # PNG 검증
            if decrypted[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]):
                print('✓ 유효한 PNG 파일입니다!')
                
                # IEND 청크 확인
                if decrypted[-8:-4] == bytes([0x49, 0x45, 0x4E, 0x44]):
                    print('✓ PNG 끝 시그니처도 올바릅니다!')
            else:
                print('⚠ PNG 헤더가 올바르지 않습니다.')
                print(f'실제 헤더: {decrypted[:8].hex()}')
        
        except FileNotFoundError:
            print(f"파일을 찾을 수 없습니다: {input_file}")
        except Exception as e:
            print(f"에러: {e}")
    
    decrypt()
else:
    print("\n여전히 못 찾음.")
    print("\n혹시 문제를 잘못 이해했을 가능성:")
    print("1. shuffle()이 comment out 되어있거나")
    print("2. 실제 사용된 코드가 다르거나")
    print("3. 특별한 Python 환경에서 실행")
    
    print("\n제안: 작은 범위 순차 테스트")
    print("0부터 1000까지 하나씩 시도해보는 중...")
    
    for seed in range(1000):
        S = test_seed(seed)
        if S:
            print(f"\nSeed {seed}에서 발견!")
            break