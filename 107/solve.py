import base64
import os

def convert():
    input_filename = 'b64.txt'
    output_filename = 'chall'

    try:
        # 1. 텍스트 파일 읽기
        with open(input_filename, 'r') as f:
            raw_data = f.read()
        
        # 공백이나 개행 제거 (안전장치)
        b64_data = raw_data.replace('\n', '').replace(' ', '').strip()

        if not b64_data:
            print(f"[-] Error: '{input_filename}' 파일이 비어있습니다.")
            return

        # 2. 디코딩 및 바이너리 쓰기
        binary_data = base64.b64decode(b64_data)
        
        with open(output_filename, 'wb') as f:
            f.write(binary_data)
            
        # 3. 실행 권한 부여
        os.system(f'chmod +x {output_filename}')
        
        print(f"[+] 변환 성공!")
        print(f"[+] '{output_filename}' 파일이 생성되었습니다.")
        print(f"[+] 기드라에 '{output_filename}'을 넣고 분석해보세요.")

    except Exception as e:
        print(f"[-] 변환 중 오류 발생: {e}")

if __name__ == '__main__':
    convert()