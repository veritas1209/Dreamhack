from pwn import *
import struct

def extract_timestamps(binary_path):
    print("="*60)
    print(f"[DEBUG] 바이너리 파일 분석 시작: {binary_path}")
    print("="*60)
    
    try:
        elf = ELF(binary_path)
        print(f"[DEBUG] ELF 파일 로드 성공.")
        print(f"  ➜ Architecture: {elf.arch}")
        print(f"  ➜ PIE Enabled: {elf.pie}")
        print(f"  ➜ ELF Base Address: {hex(elf.address)}")
    except Exception as e:
        print(f"[ERROR] ELF 파일 로드 실패: {e}")
        return []

    # Ghidra 주소 0x104040 -> Base 0x100000 제외한 실제 오프셋 0x4040
    start_addr = 0x4040
    end_addr = 0x8040 
    size = end_addr - start_addr
    
    print(f"\n[DEBUG] 추출 타겟 정보 세팅 완료")
    print(f"  ➜ 타겟 파일 오프셋(Offset): {hex(start_addr)} ~ {hex(end_addr)}")
    print(f"  ➜ 읽어들일 바이트 크기: {size} bytes")

    try:
        # 수정된 오프셋으로 데이터 읽기
        raw_data = elf.read(start_addr, size)
        print(f"\n[DEBUG] 메모리 읽기 성공. (읽어온 바이트 수: {len(raw_data)})")
    except Exception as e:
        print(f"[ERROR] 데이터 읽기 실패: {e}")
        return []

    print("\n[DEBUG] 8바이트(QWORD) 리틀엔디안 정수 배열로 변환 작업 시작...")
    timestamps = []
    
    for i in range(0, len(raw_data), 8):
        chunk = raw_data[i:i+8]
        if len(chunk) == 8:
            val = struct.unpack('<q', chunk)[0]
            timestamps.append(val)
        else:
            print(f"[WARNING] 오프셋 {hex(start_addr + i)} 위치에서 자투리 데이터 발견: {chunk}")
    
    print(f"[DEBUG] 변환 완료! 총 {len(timestamps)} 개의 타임스탬프 명령어 추출됨.")
    if timestamps:
        print(f"[DEBUG] 데이터 샘플 (첫 3개): {timestamps[:3]}")
        print(f"[DEBUG] 데이터 샘플 (마지막 3개): {timestamps[-3:]}")
    
    return timestamps

if __name__ == "__main__":
    # 타겟 바이너리 파일 이름
    BINARY_FILE = "./855/time_machine" 
    
    extracted_data = extract_timestamps(BINARY_FILE)
    
    if extracted_data:
        print("\n" + "="*60)
        print("[+] 추출 성공! 아래 데이터를 에뮬레이터 코드에 덮어씌워주세요.")
        print("="*60 + "\n")
        
        output_str = f"extracted_timestamps = {extracted_data}"
        print(output_str)
        
        with open("extracted_data.py", "w") as f:
            f.write(output_str)
        print("\n[DEBUG] 'extracted_data.py' 파일로 저장 완료.")