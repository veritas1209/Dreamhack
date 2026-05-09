import os
import glob
import sys
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

def build_graph(lib_dir="lib"):
    graph = {}
    so_files = glob.glob(os.path.join(lib_dir, "*.so"))
    print(f"[DEBUG] '{lib_dir}' 디렉토리에서 총 {len(so_files)}개의 .so 파일을 찾았습니다.")
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    for idx, so_path in enumerate(so_files):
        so_name = os.path.basename(so_path)
        graph[so_name] = {}
        
        try:
            with open(so_path, "rb") as f:
                elf = ELFFile(f)
                rodata_sec = elf.get_section_by_name('.rodata')
                text_sec = elf.get_section_by_name('.text')
                symbols = elf.get_section_by_name('.symtab') or elf.get_section_by_name('.dynsym')
                
                if not text_sec or not symbols:
                    continue
                    
                rodata_data = rodata_sec.data() if rodata_sec else b""
                rodata_addr = rodata_sec['sh_addr'] if rodata_sec else 0
                text_data = text_sec.data()
                text_addr = text_sec['sh_addr']
                
                for hex_val in range(16):
                    hex_char = hex(hex_val)[2:]
                    func_name = f"f_{hex_char}"
                    
                    syms = symbols.get_symbol_by_name(func_name)
                    if not syms:
                        continue
                    
                    sym = syms[0]
                    func_addr = sym['st_value']
                    func_size = sym['st_size'] if sym['st_size'] > 0 else 0x100
                    
                    offset_in_text = func_addr - text_addr
                    func_bytes = text_data[offset_in_text : offset_in_text + func_size]
                    
                    next_so = None
                    is_success = False
                    
                    for insn in md.disasm(func_bytes, func_addr):
                        # 1. 중간 노드: 다음 .so 파일 로드 여부 확인
                        if insn.mnemonic == 'lea' and rodata_data:
                            if len(insn.operands) == 2 and insn.operands[1].type == X86_OP_MEM:
                                mem = insn.operands[1].mem
                                if mem.base == X86_REG_RIP:
                                    target_addr = insn.address + insn.size + mem.disp
                                    if rodata_addr <= target_addr < rodata_addr + len(rodata_data):
                                        str_offset = target_addr - rodata_addr
                                        end_idx = rodata_data.find(b'\x00', str_offset)
                                        if end_idx != -1:
                                            extracted_str = rodata_data[str_offset:end_idx].decode('ascii', errors='ignore')
                                            if extracted_str.startswith("lib/") and extracted_str.endswith(".so"):
                                                next_so = extracted_str.split('/')[-1]
                                                break
                                                
                        # 2. 마지막 출구 노드: return 1 (성공) 여부 확인
                        if insn.mnemonic == 'mov':
                            # 보통 mov eax, 1 형태로 리턴값을 세팅함
                            if insn.op_str.startswith('eax, ') or insn.op_str.startswith('rax, '):
                                val = insn.op_str.split(',')[1].strip()
                                if val in ('1', '0x1'):
                                    is_success = True
                                    
                    if next_so:
                        graph[so_name][hex_char] = next_so
                    elif is_success:
                        # 더 이상 .so를 로드하지 않고 1을 반환하면 여기가 64번째 출구!
                        graph[so_name][hex_char] = "SUCCESS"

        except Exception as e:
            print(f"  [ERROR] {so_name} 분석 중 예외 발생: {e}")
            
    return graph

def solve(graph, current_node="start.so", current_flag="", depth=0, visited=None):
    if visited is None:
        visited = set()
        
    state = (current_node, depth)
    
    if state in visited:
        return False
        
    # 성공 노드에 도달했거나, 정확히 깊이 64에서 끝났다면 정답
    if depth == 64 or current_node == "SUCCESS":
        print("\n" + "="*55)
        print(f" [*** 플래그 획득 성공! ***] 깊이 {depth} 도달")
        print(f" FLAG : DH{{{current_flag}}}")
        print("="*55 + "\n")
        return True
        
    if current_node not in graph:
        visited.add(state)
        return False
        
    transitions = graph[current_node]
    if not transitions:
        visited.add(state)
        return False
        
    for hex_char, next_node in transitions.items():
        # 디버깅 편의를 위해 깊이 60 이상이거나, 중요한 흐름일 때 출력
        if depth >= 60:
            print(f"[TRACE] 깊이 {depth:02d} | {current_node} --('{hex_char}')--> {next_node}")
            
        if solve(graph, next_node, current_flag + hex_char, depth + 1, visited):
            return True
            
    # 현재 노드에서 뻗어나가는 모든 길이 실패했음을 영구 기록 (가지치기)
    visited.add(state)
    return False

if __name__ == "__main__":
    print("[DEBUG] 스크립트 실행을 시작합니다...")
    target_dir = "1347/lib" # 필요에 따라 경로 수정
    
    print("\n[DEBUG] --- 1단계: 바이너리 정적 분석 및 그래프 구축 ---")
    maze_graph = build_graph(target_dir)
    print(f"[DEBUG] 그래프 구축 완료! 총 {len(maze_graph)}개의 노드가 생성되었습니다.")
    
    print("\n[DEBUG] --- 2단계: 64자리 플래그 DFS 경로 탐색 시작 ---")
    start_point = "start.so"
    
    if start_point not in maze_graph:
        print(f"[ERROR] 시작점인 '{start_point}'를 찾을 수 없습니다. 경로를 확인해주세요.")
    else:
        success = solve(maze_graph, start_point, "", 0)
        if not success:
            print("\n[FAIL] 경로를 찾지 못했습니다. 미로의 구조가 예상과 다르거나 끊어져 있습니다.")