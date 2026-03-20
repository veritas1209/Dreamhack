from z3 import *
import re
import sys

# Z3 Solver 초기화
s = Solver()

regs = {
    'rax': BitVecVal(0, 64),
    'rdx': BitVecVal(0, 64),
    'rcx': BitVecVal(0, 64)
}

mem_state = {} 
flag_vars = {} 

def get_mem_key(op):
    match = re.search(r'\[(.*?)\]', op)
    if match:
        return match.group(1).strip()
    return None

def read_mem(key, size_bits):
    if key not in mem_state:
        # Z3 변수명에 공백이나 특수문자가 들어가면 꼬일 수 있으므로 치환
        safe_key = key.replace(" ", "_").replace("+", "p").replace("-", "m")
        var = BitVec(f'mem_{safe_key}', 64)
        mem_state[key] = var
        flag_vars[key] = var
        
    val = mem_state[key]
    if val.size() > size_bits:
        return Extract(size_bits - 1, 0, val)
    elif val.size() < size_bits:
        return ZeroExt(size_bits - val.size(), val)
    return val

def write_mem(key, val, size_bits):
    if key not in mem_state:
        safe_key = key.replace(" ", "_").replace("+", "p").replace("-", "m")
        var = BitVec(f'mem_{safe_key}', 64)
        mem_state[key] = var
        flag_vars[key] = var
        
    current = mem_state[key]
    
    if val.size() < size_bits:
         val = ZeroExt(size_bits - val.size(), val)
    elif val.size() > size_bits:
         val = Extract(size_bits - 1, 0, val)
         
    if size_bits == 64:
         mem_state[key] = val
    elif size_bits == 32:
         mem_state[key] = Concat(Extract(63, 32, current), val)
    elif size_bits == 16:
         mem_state[key] = Concat(Extract(63, 16, current), val)
    elif size_bits == 8:
         mem_state[key] = Concat(Extract(63, 8, current), val)

def get_reg_info(reg_name):
    if reg_name in ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9']:
        return reg_name, 64
    elif reg_name in ['eax', 'edx', 'ecx', 'ebx', 'esi', 'edi', 'ebp', 'esp', 'r8d', 'r9d']:
        return 'r' + reg_name[1:] if reg_name.startswith('e') else reg_name[:-1], 32
    elif reg_name in ['ax', 'dx', 'cx', 'bx', 'si', 'di', 'bp', 'sp', 'r8w', 'r9w']:
        return 'r' + reg_name if len(reg_name)==2 else reg_name[:-1], 16
    elif reg_name in ['al', 'dl', 'cl', 'bl', 'sil', 'dil', 'bpl', 'spl', 'r8b', 'r9b']:
        return 'r' + reg_name[0] + 'x' if len(reg_name)==2 else reg_name[:-1], 8
    return reg_name, 64

def get_reg_val(reg_name):
    base_reg, size = get_reg_info(reg_name)
    val = regs.get(base_reg, BitVecVal(0, 64))
    if size < 64:
        return Extract(size - 1, 0, val)
    return val

def set_reg_val(reg_name, val):
    base_reg, size = get_reg_info(reg_name)
    if val.size() < size: val = ZeroExt(size - val.size(), val)
    elif val.size() > size: val = Extract(size - 1, 0, val)

    if size == 64: regs[base_reg] = val
    elif size == 32: regs[base_reg] = ZeroExt(32, val) 
    elif size == 16: regs[base_reg] = Concat(Extract(63, 16, regs.get(base_reg, BitVecVal(0, 64))), val)
    elif size == 8: regs[base_reg] = Concat(Extract(63, 8, regs.get(base_reg, BitVecVal(0, 64))), val)

def parse_operand(op):
    op = op.strip()
    if op.startswith('0x') or op.isdigit() or (op.startswith('-') and op[1:].isdigit()) or op.startswith('-0x'):
        return BitVecVal(int(op, 0), 64)
        
    if 'ptr' in op:
        size_bits = 64
        if 'dword' in op: size_bits = 32
        elif 'word' in op: size_bits = 16
        elif 'byte' in op: size_bits = 8
        
        key = get_mem_key(op)
        if key: return read_mem(key, size_bits)
        else: return BitVecVal(0, size_bits)
        
    return get_reg_val(op)

def set_operand_val(op, val):
    op = op.strip()
    if 'ptr' in op:
        size_bits = 64
        if 'dword' in op: size_bits = 32
        elif 'word' in op: size_bits = 16
        elif 'byte' in op: size_bits = 8
        
        key = get_mem_key(op)
        if key: write_mem(key, val, size_bits)
        return
    set_reg_val(op, val)

try:
    with open('vm_parsed.txt', 'r', encoding='UTF-8') as f:
        lines = f.read().splitlines()
except FileNotFoundError:
    print("vm_parsed.txt 파일이 필요합니다.")
    sys.exit(1)

for i, line in enumerate(lines):
    if ':' not in line: continue
        
    insn_part = line.split(':\t')[1].strip()
    if '<--' in insn_part:
        insn_part = insn_part.split('<--')[0].strip()
        
    parts = insn_part.split(maxsplit=1)
    if len(parts) < 2: continue
        
    op = parts[0].strip()
    args = [arg.strip() for arg in parts[1].split(',')]
    
    if op in ['movabs', 'mov']:
        dest = args[0]
        src_val = parse_operand(args[1])
        set_operand_val(dest, src_val)
        
    elif op == 'xor':
        dest = args[0]
        dest_val = parse_operand(dest)
        src_val = parse_operand(args[1])
        target_size = dest_val.size()
        if src_val.size() > target_size: src_val = Extract(target_size - 1, 0, src_val)
        elif src_val.size() < target_size: src_val = ZeroExt(target_size - src_val.size(), src_val)
        set_operand_val(dest, dest_val ^ src_val)
        
    elif op == 'sub':
        dest = args[0]
        dest_val = parse_operand(dest)
        src_val = parse_operand(args[1])
        target_size = dest_val.size()
        if src_val.size() > target_size: src_val = Extract(target_size - 1, 0, src_val)
        elif src_val.size() < target_size: src_val = ZeroExt(target_size - src_val.size(), src_val)
        set_operand_val(dest, dest_val - src_val)

    elif op == 'add':
        dest = args[0]
        dest_val = parse_operand(dest)
        src_val = parse_operand(args[1])
        target_size = dest_val.size()
        if src_val.size() > target_size: src_val = Extract(target_size - 1, 0, src_val)
        elif src_val.size() < target_size: src_val = ZeroExt(target_size - src_val.size(), src_val)
        set_operand_val(dest, dest_val + src_val)
            
    # 💡 [핵심 돌파구] test 명령어는 상태 갱신용 더미이므로 완전히 무시하고, cmp만 플래그 검증으로 사용합니다!
    elif op == 'cmp':
        val1 = parse_operand(args[0])
        val2 = parse_operand(args[1])
        target_size = val1.size()
        
        if val2.size() > target_size: val2 = Extract(target_size - 1, 0, val2)
        elif val2.size() < target_size: val2 = ZeroExt(target_size - val2.size(), val2)
            
        condition = (val1 == val2)
        
        s.push()
        s.add(condition)
        if s.check() == unsat:
            s.pop() # 만약 루프 카운터 검사 등 플래그와 무관한 cmp라서 모순이 나면 버림
        else:
            s.pop()
            s.add(condition)

print("\n[*] Z3 제약 조건 최종 해결 중...")
if s.check() == sat:
    print("[+] SAT! 플래그 복원 성공!")
    m = s.model()
    
    print("\n[🚀] 메모리 블록별 데이터 확인:")
    
    mem_blocks = []
    for key, bitvec in flag_vars.items():
        if 'rbp - ' in key:
            try:
                offset = int(key.split('-')[1].strip(), 16)
                val = m[bitvec]
                if val is not None:
                    # 8바이트(64비트) 리틀 엔디안으로 변환
                    val_bytes = val.as_long().to_bytes(8, byteorder='little')
                    mem_blocks.append((offset, key, val_bytes))
            except Exception as e:
                continue
                
    # offset 내림차순 정렬 (스택 구조상 rbp에서 빼는 값이 클수록 문자열의 앞부분)
    mem_blocks.sort(key=lambda x: x[0], reverse=True)
    
    flag_assembled = ""
    for offset, key, val_bytes in mem_blocks:
        block_str = ""
        for b in val_bytes:
            if 32 <= b <= 126: # 읽을 수 있는 아스키코드만 추출
                block_str += chr(b)
                
        # 가비지가 아닌 문자가 하나라도 있으면 출력
        if len(block_str) > 0:
            print(f"[{key:>14}] : {val_bytes} -> '{block_str}'")
            flag_assembled += block_str
                
    print(f"\n[💡] 추출된 전체 문자열: {flag_assembled}")
    print("\n(위 출력된 블록의 문자열들을 조합하여 DH{...} 플래그를 완성하세요!)")
else:
    print("[-] UNSAT: 그래도 해결되지 않았습니다.")