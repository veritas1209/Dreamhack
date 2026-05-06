from pwn import *
from z3 import *
import sys

sys.setrecursionlimit(10000)

def solve_type(type_idx, outputs, skip_count):
    degrees = [1, 7, 15, 31, 63]
    seps = [0, 3, 1, 3, 1]

    deg = degrees[type_idx]
    sep = seps[type_idx]

    solver = Solver()
    
    if type_idx == 0:
        initial_states = [BitVec(f's_{i}', 32) for i in range(deg)]
        solver.add(initial_states[0] & 0x80000000 == 0)
        state = initial_states[0]
        
        for _ in range(skip_count):
            state = (state * 1103515245 + 12345)
            
        for out_val in outputs:
            state = (state * 1103515245 + 12345)
            solver.add((state & 0x7FFFFFFF) == out_val)
            
        if solver.check() == sat:
            m = solver.model()
            return [m[initial_states[0]].as_long()]
        return None
        
    else:
        # 1. Z3로는 '스킵이 끝난 직후(출력이 시작되는 시점)'의 상태만 구합니다.
        S = [BitVec(f's_{i}', 32) for i in range(deg)]
        current_S = list(S)
        
        f = (sep + skip_count) % deg
        r = skip_count % deg
        
        # [수정됨] 출력을 자르지 않고 전부 제약 조건으로 사용합니다.
        # 가짜 상태(Spurious State)가 도출되는 것을 막고 완벽한 유일해를 찾습니다.
        for out_val in outputs:
            new_val = current_S[f] + current_S[r]
            current_S[f] = new_val
            solver.add(LShR(new_val, 1) == out_val)
            f = (f + 1) % deg
            r = (r + 1) % deg

        if solver.check() == sat:
            m = solver.model()
            recovered_S = [m[S[i]].as_long() for i in range(deg)]
            
            # 2. 구한 상태에서 스킵 횟수만큼 역연산(Rollback)하여 초기 상태를 찾습니다.
            state = list(recovered_S)
            f = (sep + skip_count) % deg
            r = skip_count % deg
            
            for _ in range(skip_count):
                f = (f - 1) % deg
                r = (r - 1) % deg
                # 덧셈 전이의 역연산은 뺄셈입니다.
                state[f] = (state[f] - state[r]) & 0xFFFFFFFF
                
            return state
        else:
            return None

def main():
    r = remote('localhost', 5000)

    challenges = [
        (100, 1),
        (350, 35),
        (750, 75),
        (1550, 310),
        (3150, 630)
    ]

    for type_idx in range(5):
        log.info(f"Processing Type {type_idx}...")
        r.recvuntil(f"Guess type {type_idx}!\n".encode())

        outputs = []
        req_outputs = challenges[type_idx][1]

        while len(outputs) < req_outputs:
            line = r.recvline().decode().strip()
            outputs.extend([int(x) for x in line.split()])
        
        r.recvuntil(b"required)\n")
        
        skip_count = challenges[type_idx][0]
        
        log.info(f"Solving Z3... (Skipping {skip_count}, matching {req_outputs} outputs)")
        ans = solve_type(type_idx, outputs, skip_count)

        if not ans:
            log.error("Failed to recover initial state.")
            return

        log.success("Initial state recovered. Sending payload...")
        r.sendline(" ".join(map(str, ans)).encode())
        
        res = r.recvline().decode().strip()
        log.info(f"Response: {res}")

    r.recvuntil(b"flag: ")
    flag = r.recvline().decode().strip()
    log.success(f"FLAG: {flag}")

if __name__ == '__main__':
    main()