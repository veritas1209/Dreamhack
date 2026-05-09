import re
import struct
import os

def hex_to_float(hex_str):
    try:
        # 기드라 디컴파일러는 간혹 부호 확장 때문에 0xffffffffc3960000 처럼 출력합니다.
        # 뒤의 8자리(4바이트)만 잘라서 사용합니다.
        if len(hex_str) > 8:
            hex_str = hex_str[-8:]
            
        hex_str = hex_str.zfill(8) # 8자리가 안되면 0으로 채움
        byte_data = bytes.fromhex(hex_str)
        
        # C 코드 상에 표기된 0x43960000는 사람이 읽는 방향(Big Endian)으로 적혀있습니다.
        f_val = struct.unpack('>f', byte_data)[0]
        return f_val
    except Exception as e:
        print(f"[DEBUG_ERROR] 헥스 '{hex_str}' 변환 중 오류: {e}")
        return None

def main():
    print("=============================================")
    print("[SYSTEM] C 코드 기반 플래그 좌표 추출 디버거")
    print("=============================================")
    
    code_file = "C:/Users/hajin/IT_Projects/hacking_study/dreamhack/1237/code.txt"
    
    if not os.path.exists(code_file):
        print(f"[FATAL] {code_file} 파일이 없습니다! 디컴파일 코드를 저장해주세요.")
        return
        
    with open(code_file, "r", encoding="utf-8") as f:
        code_lines = f.readlines()
        
    print(f"[INFO] 타겟 코드 파일 로드 완료. 총 {len(code_lines)} 라인")
    
    float_values = []
    
    # 정규식: "변수명 = 0x어쩌구;" 형태에서 0x 뒤의 헥스값만 추출
    hex_pattern = re.compile(r'=\s*0x([0-9a-fA-F]+);')
    
    print("\n[SYSTEM] --- 헥스 데이터 파싱 및 디버그 로그 ---")
    for line_num, line in enumerate(code_lines):
        match = hex_pattern.search(line)
        if match:
            raw_hex = match.group(1)
            
            # 1.0, 300.0, -300.0 등 유의미한 좌표값 헥스는 보통 8자리 혹은 16자리입니다.
            if len(raw_hex) >= 8:
                f_val = hex_to_float(raw_hex)
                if f_val is not None:
                    # 쓰레기값(너무 크거나 작은 수) 필터링
                    if 0.0 < abs(f_val) < 2000.0 or f_val == 0.0:
                        float_values.append(f_val)
                        print(f"[DEBUG] Line {line_num+1:04d} | 추출된 헥스: 0x{raw_hex:<16} -> Float 변환: {f_val:8.3f}")

    print("\n=============================================")
    print(f"[INFO] 총 {len(float_values)} 개의 유효한 Float 데이터 추출 완료.")
    
    # 좌표 묶기 (보통 X, Y, Z, 그리고 색상이나 크기값 등이 섞여있을 수 있으니 디버깅 필요)
    # 데이터를 3개씩(X, Y, Z) 묶어보고 출력해봅니다.
    print("[SYSTEM] --- 3D 좌표(X, Y, Z) 그룹화 디버그 ---")
    
    x_coords, y_coords, z_coords = [], [], []
    STRIDE = 3 
    
    for i in range(0, len(float_values), STRIDE):
        chunk = float_values[i:i+STRIDE]
        if len(chunk) < 3:
            break
            
        x, y, z = chunk[0], chunk[1], chunk[2]
        
        # 전부 0.0인 경우는 의미 없는 데이터이므로 패스
        if x == 0.0 and y == 0.0 and z == 0.0:
            continue
            
        x_coords.append(x)
        y_coords.append(y)
        z_coords.append(z)
        
        print(f"[DATA] Object #{len(x_coords):02d} | X: {x:8.3f}, Y: {y:8.3f}, Z: {z:8.3f}")

    print("=============================================")
    
    if not x_coords:
        print("[FAIL] 플롯을 그릴 좌표가 없습니다.")
        return

    print("[SYSTEM] 디버깅 종료. Matplotlib으로 좌표를 그립니다...")
    import matplotlib.pyplot as plt
    
    fig = plt.figure(figsize=(12, 10))
    ax = fig.add_subplot(111, projection='3d')
    ax.scatter(x_coords, z_coords, y_coords, c='red', marker='s', s=100, edgecolor='black')
    
    ax.set_xlabel('X Axis')
    ax.set_ylabel('Z Axis')
    ax.set_zlabel('Y Axis')
    ax.set_title('Real CTF Flag Reveal (Parsed from C Code)')
    
    plt.show()

if __name__ == "__main__":
    main()