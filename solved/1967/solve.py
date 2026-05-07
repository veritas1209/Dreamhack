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
        # 1. 32비트 덧셈 모델링을 완전히 버리고, 수학적 특성을 이용한 1비트(LSB) 방정식으로 변환
        L = [BitVec(f'L_{i}', 1) for i in range(len(outputs))]
        
        for k in range(deg, len(outputs)):
            # diff는 이미 알고 있는 출력값들만으로 계산 가능
            diff = (outputs[k] - outputs[k - deg] - outputs[k - sep]) % (1 << 31)
            
            if diff == 1:
                # 올림수(Carry)가 발생한 경우: 세 비트의 값이 완전히 확정됨
                solver.add(L[k - deg] == 1)
                solver.add(L[k - sep] == 1)
                solver.add(L[k] == 0)
            elif diff == 0:
                # 올림수가 없는 경우: 완벽한 선형 XOR 관계로 떨어짐
                solver.add(L[k] == L[k - deg] ^ L[k - sep])
            else:
                log.error(f"Mathematical anomaly at {k}: diff = {diff}")
                return None
                
        if solver.check() == sat:
            m = solver.model()
            
            # 처음 deg개의 상태 복구
            state = [0] * deg
            f_0 = (sep + skip_count) % deg
            r_0 = skip_count % deg
            
            for k in range(deg):
                lsb = m[L[k]].as_long()
                idx = (f_0 + k) % deg
                state[idx] = (outputs[k] << 1) | lsb
                
            # 2. 역연산(Rollback) 진행
            total_rollbacks = skip_count + deg
            f = f_0
            r = r_0
            
            for _ in range(total_rollbacks):
                f = (f - 1) % deg
                r = (r - 1) % deg
                state[f] = (state[f] - state[r]) & 0xFFFFFFFF
                
            return state
        else:
            return None

def main():
    r = remote('host8.dreamhack.games', 24086)

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