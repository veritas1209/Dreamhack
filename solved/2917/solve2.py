import torch
import os

def disassemble_vm(model_path):
    print(f"[DEBUG] === 5단계: 커스텀 VM 바이트코드 역어셈블 시작 ===\n")
    
    if not os.path.exists(model_path):
        print(f"[ERROR] 파일을 찾을 수 없습니다: {model_path}")
        return

    model = torch.jit.load(model_path, map_location=torch.device('cpu'))
    
    # 누락되었던 보조 함수 a, b 코드 추출
    print("="*60)
    print("[DEBUG] 🧩 누락되었던 보조 함수 'a', 'b' 추출")
    print("="*60)
    for func_name in ['a', 'b', 'c']:
        if hasattr(model, func_name):
            print(f"--- 함수 '{func_name}' ---")
            print(getattr(model, func_name).code)
        else:
            print(f"[ERROR] 함수 '{func_name}' 를 찾을 수 없습니다.")

    print("\n" + "="*60)
    print("[DEBUG] 📜 VM 47줄 명령어 디코딩 목록")
    print("="*60)
    
    aq = model.aq.tolist()
    
    # 레지스터 초기 맵핑 정보 (r[0] ~ r[23])
    reg_names = {
        0: "x1", 1: "x2", 2: "x3", 3: "t", 4: "n(adjusted)", 
        5: "0", 6: "0", 7: "0", 8: "0", 9: "0", 10: "0", 
        11: "0", 12: "0", 13: "0", 14: "0", 15: "0", 16: "0", 
        17: "x0", 18: "0", 19: "0", 20: "0", 21: "0", 22: "0", 23: "ah"
    }

    def get_reg(idx):
        return f"r[{idx}]" # 흐름 추적을 위해 배열 형태로 출력

    print("초기 상태:")
    print("r[0~4]   =", [reg_names[i] for i in range(5)])
    print("r[17,23] =", reg_names[17], ",", reg_names[23])
    print("나머지 r은 모두 0으로 초기화됨\n")
    print("-" * 50)

    for pc, row in enumerate(aq):
        key = (pc + 1) * 73244475 + 2562088
        
        # 난독화 해제 로직 그대로 적용
        op = int(row[0]) ^ (key & 127)
        dst = int(row[1]) ^ ((key >> 7) & 31)
        lhs = int(row[2]) ^ ((key >> 12) & 31)
        rhs = int(row[3]) ^ ((key >> 17) & 31)
        imm = int(row[4]) ^ key

        # 명령어 해석
        if op == 1:
            inst = f"{get_reg(dst)} = {get_reg(lhs)}"
        elif op == 2:
            inst = f"{get_reg(dst)} = ({get_reg(lhs)} + {get_reg(rhs)}) & ak"
        elif op == 3:
            inst = f"{get_reg(dst)} = ({get_reg(lhs)} + {imm}) & ak"
        elif op == 4:
            inst = f"{get_reg(dst)} = {get_reg(lhs)} ^ {get_reg(rhs)}"
        elif op == 5:
            inst = f"{get_reg(dst)} = {get_reg(lhs)} ^ {imm}"
        elif op == 6:
            inst = f"{get_reg(dst)} = {get_reg(lhs)} & {imm}"
        elif op == 7:
            inst = f"{get_reg(dst)} = {get_reg(lhs)} >> {imm}"
        elif op == 8:
            inst = f"{get_reg(dst)} = ({get_reg(lhs)} * {imm}) & ak"
        elif op == 9:
            inst = f"{get_reg(dst)} = b({get_reg(lhs)}, {get_reg(rhs)})"
        elif op == 10:
            inst = f"{get_reg(dst)} = a({get_reg(lhs)}, {get_reg(rhs)})"
        elif op == 11:
            sbox_names = {0: "aa", 1: "ab", 2: "ac", 3: "ad", 4: "ae", 5: "af"}
            sbox = sbox_names.get(imm, f"UNKNOWN_SBOX_{imm}")
            inst = f"{get_reg(dst)} = {sbox}[{get_reg(lhs)}]"
        else:
            inst = f"{get_reg(dst)} = ({get_reg(lhs)} + ({get_reg(rhs)} ^ {imm})) & ak"

        print(f"PC[{pc:02d}]: {inst}")

    print("-" * 50)
    print("반환값: (r[18], r[19], r[20], r[21] & ak)")

if __name__ == "__main__":
    disassemble_vm("model.pt")