import base64
import sys

# 1. 파일 이름 설정
INPUT_FILE = "ld_dump.b64"       # base64 문자열이 저장된 파일 (사용자가 만든 파일명)
OUTPUT_FILE = "ld_hacked_real.so" # 복원될 바이너리 파일

def decode_base64_file(input_path, output_path):
    try:
        # 파일 읽기
        with open(input_path, 'r', encoding='utf-8') as f:
            b64_string = f.read().strip()
            
        # 디코딩
        decoded_data = base64.b64decode(b64_string)
        
        # 바이너리 쓰기
        with open(output_path, 'wb') as f:
            f.write(decoded_data)
            
        print(f"[+] Success! Decoded '{input_path}' to '{output_path}'")
        print(f"[+] Output size: {len(decoded_data)} bytes")
        
        # 헤더 확인 (ELF 파일인지 검증)
        if decoded_data.startswith(b'\x7fELF'):
            print("[*] Verification: Valid ELF header detected.")
        else:
            print("[!] Warning: File header does not match ELF (Is the base64 correct?)")
            
    except FileNotFoundError:
        print(f"[-] Error: Input file '{input_path}' not found.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    decode_base64_file(INPUT_FILE, OUTPUT_FILE)