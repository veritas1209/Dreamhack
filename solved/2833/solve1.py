import os

# 앞서 압축 해제한 파일 이름
file_path = "extracted_payload.bin"

# 메모리 부담을 줄이고 디버깅 로그를 보기 위해 10MB 단위로 잘라서 읽음
chunk_size = 1024 * 1024 * 10 
target_byte = ord('0') # 0x30 (걸러낼 타겟 문자)

print(f"[DEBUG] === 숨겨진 데이터 추출 스크립트 시작 ===")
print(f"[DEBUG] 분석 대상 파일: {file_path}")

try:
    file_size = os.path.getsize(file_path)
    print(f"[DEBUG] 파일 총 크기: {file_size:,} 바이트")
except FileNotFoundError:
    print(f"[DEBUG] 에러: {file_path} 파일을 찾을 수 없습니다. 경로를 확인해주세요.")
    exit()

extracted_data = bytearray()
offset = 0

print("[DEBUG] 파일 분석을 시작합니다...")

with open(file_path, "rb") as f:
    while True:
        # chunk_size 만큼 파일 읽기
        chunk = f.read(chunk_size)
        if not chunk:
            print("[DEBUG] 파일의 끝(EOF)에 도달했습니다.")
            break
        
        current_chunk_size = len(chunk)
        print(f"[DEBUG] {offset:,} ~ {offset + current_chunk_size:,} 바이트 구간 분석 중...")
        
        # '0' (0x30)이 아닌 바이트만 찾아내서 저장
        for byte in chunk:
            if byte != target_byte:
                extracted_data.append(byte)
        
        offset += current_chunk_size

print(f"[DEBUG] === 분석 완료 ===")
print(f"[DEBUG] '0'이 아닌 의미 있는 데이터 총 길이: {len(extracted_data)} 바이트")

# 결과 출력
if len(extracted_data) > 0:
    print("\n[DEBUG] >> 추출된 데이터 확인 <<")
    
    # 먼저 일반 문자열(UTF-8/ASCII)로 디코딩 시도
    try:
        decoded_text = extracted_data.decode('utf-8')
        print("[DEBUG] 문자열 디코딩 성공! 내용:")
        print("-" * 50)
        print(decoded_text)
        print("-" * 50)
    except UnicodeDecodeError:
        print("[DEBUG] 추출된 데이터가 일반 텍스트가 아닙니다. (바이너리 데이터일 가능성 높음)")
        print(f"[DEBUG] 헥스 값으로 출력 (앞 100바이트): {extracted_data[:100].hex().upper()}")
        
        # 바이너리일 경우 파일로 저장
        out_filename = "hidden_secret.bin"
        with open(out_filename, "wb") as out_f:
            out_f.write(extracted_data)
        print(f"[DEBUG] 바이너리 데이터를 '{out_filename}'로 저장했습니다. 다시 HxD로 확인해보세요!")
else:
    print("[DEBUG] 특이 데이터가 전혀 발견되지 않았습니다. 파일이 100% '0'으로만 이루어져 있네요.")

print("[DEBUG] === 스크립트 종료 ===")