import sys

def extract_matrix():
    print("[*] =============== Matrix Extraction Start ===============")
    
    base_addr_str = "0011c8e0"
    base_addr = currentProgram.getAddressFactory().getAddress(base_addr_str)
    
    if base_addr is None:
        print("[!] 시작 주소를 찾을 수 없습니다: " + base_addr_str)
        return
        
    print("[*] Base Address: {}".format(base_addr))
    
    matrix = []
    
    for i in range(67):
        # 수정됨: 외부 배열 길이(8) + 내부 배열 길이(8) = 16바이트 뒤부터 포인터 시작
        ptr_loc = base_addr.add(i * 16 + 16)
        row_ptr_val = getLong(ptr_loc)
        
        if row_ptr_val < 0:
            row_ptr_val = (row_ptr_val + (1 << 64)) % (1 << 64)
            
        row_addr = currentProgram.getAddressFactory().getAddress(hex(row_ptr_val).rstrip('L'))
        print("[Debug] Row {:02d} Ptr Location: {} -> Addr: {}".format(i, ptr_loc, row_addr))
        
        row_data = []
        for j in range(67):
            # 실제 데이터는 행 주소 + 8바이트(오프셋) 부터
            data_loc = row_addr.add(8 + j * 8)
            val = getLong(data_loc)
            
            if val < 0:
                val = (val + (1 << 64)) % (1 << 64)
                
            row_data.append(val)
            
        matrix.append(row_data)

    print("[*] =============== Extraction Complete ===============")
    print("matrix = [")
    for row in matrix:
        print("    {},".format(row))
    print("]")

if __name__ == "__main__":
    extract_matrix()