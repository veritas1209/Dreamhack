import gdb
import json
import os

# ================= 설정 =================
LOG_FILE = "optimized_trace.jsonl"  # JSON Lines 포맷

# 추적할 레지스터 목록 (플래그 레지스터 제외, 데이터 관련만)
TARGET_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip"
]
# AVX 레지스터가 필요하면 주석 해제 (데이터 양 증가 주의)
# TARGET_REGS += [f"zmm{i}" for i in range(32)]

# 코드 영역 (Text Segment) - 이 밖으로 나가면 기록 안 함
# (이전에 info proc mappings로 확인한 주소 대입)
CODE_START = 0x7ffff7fb1000
CODE_END   = 0x7ffff7fb9000

MAX_STEPS = 1000000  # 최대 실행 명령어 수 (안전장치)
# =======================================

class OptimizedTrace(gdb.Command):
    def __init__(self):
        super(OptimizedTrace, self).__init__("start_opt_trace", gdb.COMMAND_USER)

    def get_registers(self):
        """현재 레지스터 값을 딕셔너리로 가져옴"""
        regs = {}
        for reg in TARGET_REGS:
            try:
                # 16진수 문자열로 저장
                val = gdb.parse_and_eval(f"${reg}")
                regs[reg] = int(val) # 정수형으로 저장
            except:
                pass
        return regs

    def invoke(self, arg, from_tty):
        gdb.execute("set pagination off")
        
        print(f"[*] Starting Optimized Trace -> {LOG_FILE}")
        
        last_regs = {}
        count = 0
        
        with open(LOG_FILE, "w") as f:
            try:
                while count < MAX_STEPS:
                    # 1. 현재 PC 확인
                    frame = gdb.selected_frame()
                    rip = frame.pc()
                    
                    # 2. 코드 영역 밖(라이브러리)이면 탈출
                    if not (CODE_START <= rip <= CODE_END):
                        try:
                            gdb.execute("finish", to_string=True)
                        except:
                            gdb.execute("si", to_string=True)
                        continue

                    # 3. 현재 레지스터 상태 캡처
                    current_regs = self.get_registers()
                    
                    # 4. 변경된 레지스터 찾기 (Differential)
                    diff = {}
                    if count == 0:
                        # 첫 단계는 모든 레지스터 기록
                        diff = current_regs
                    else:
                        for reg, val in current_regs.items():
                            old_val = last_regs.get(reg)
                            if val != old_val:
                                diff[reg] = val # 변경된 값만 저장
                    
                    # 5. 명령어 가져오기
                    inst_str = gdb.execute("x/i $pc", to_string=True).strip()
                    
                    # 6. 로그 저장 (JSON)
                    if diff: # 변경사항이 있을 때만
                        log_entry = {
                            "step": count,
                            "pc": hex(rip),
                            "inst": inst_str,
                            "diff": {k: hex(v) for k, v in diff.items()} # Hex 문자열로 변환
                        }
                        f.write(json.dumps(log_entry) + "\n")
                    
                    # 7. 상태 업데이트 및 진행
                    last_regs = current_regs
                    gdb.execute("si", to_string=True)
                    count += 1
                    
                    if count % 5000 == 0:
                        print(f"[*] Processed {count} steps...")

            except KeyboardInterrupt:
                print("\n[!] Stopped by user.")
            except Exception as e:
                print(f"\n[!] Error: {e}")
        
        print(f"[*] Done. Saved {count} steps to {LOG_FILE}")

OptimizedTrace()