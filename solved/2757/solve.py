from z3 import *

# 기드라에서 추출한 데이터 배열
DAT_00108020 = [
    0xe5, 0x5f, 0xa6, 0xfc, 0xfa, 0x04, 0xc7, 0x87, 0x6e, 0x75, 0xb0, 0x24, 0x8f, 0x8d, 0x95, 0x13,
    0xc4, 0x27, 0xf6, 0xd2, 0x1d, 0xb6, 0xbd, 0xee, 0x10, 0xa5, 0xfb, 0x45, 0xbb, 0x86, 0x0c, 0xed,
    0xa8, 0xa0, 0x1e, 0x4b, 0x28, 0xe3, 0xcf, 0x54, 0x6f, 0x97, 0xf1, 0x36, 0xaf, 0xb3, 0xa3, 0x83,
    0xa4, 0xf5, 0x4a, 0x1a, 0x55, 0xa7, 0x72, 0x61, 0xb7, 0xe6, 0x29, 0x68, 0xc2, 0x50, 0x80, 0x60
]

DAT_00105020 = [
    0x0d, 0xc0, 0x42, 0x77, 0x8b, 0xd3, 0xf8, 0x6a, 0x29, 0x82, 0xe3, 0xbe, 0x97, 0x8a, 0xc3, 0x75,
    0x08, 0xd4, 0x5c, 0x67, 0x4e, 0x85, 0x87, 0x0c, 0xe4, 0x7c, 0x41, 0x7e, 0x0c, 0x2b, 0x3f, 0x82,
    0x29, 0xa1, 0x92, 0x0d, 0x54, 0x93, 0x1d, 0x4b, 0x26, 0xf3, 0x2d, 0x7e, 0xda, 0xe1, 0x48, 0x06,
    0xab, 0xf0, 0x8f, 0x86, 0xd9, 0x9f, 0x83, 0xd9, 0x2a, 0x21, 0x4b, 0x2a, 0x8d, 0x30, 0xaa, 0x66
]

DAT_00105060 = [
    0x18, 0xa1, 0x27, 0x48, 0x81, 0x4b, 0x60, 0x51, 0x2b, 0x5d, 0x3e, 0x6c, 0x6f, 0x30, 0x15, 0x33
]

# 8비트 좌측 회전(ROL8) 함수 구현
def FUN_00102429(val, shift):
    shift_amt = shift & 7
    return RotateLeft(val, shift_amt)

def main():
    solver = Solver()
    
    # 64바이트 입력 플래그 (각 바이트를 8비트 벡터로 생성)
    flag = [BitVec(f"b_{i}", 8) for i in range(64)]
    
    # 보통 CTF 플래그는 출력 가능한 아스키(ASCII) 범위에 있으므로 조건 추가 (연산 속도 향상)
    for b in flag:
        solver.add(b >= 0x20, b <= 0x7e)
        
    buf = flag[:] # 연산용 버퍼 복사

    # [Phase 1] 1차 변환
    for local_50 in range(64):
        idx1 = (local_50 * 3 + 5) & 0x3f
        idx2 = local_50 & 0xf
        buf[local_50] = buf[local_50] ^ DAT_00108020[idx1] ^ DAT_00105060[idx2]

    # [Phase 2] 메인 난독화 라운드 (6회 반복)
    for local_48 in range(6):
        iVar10 = local_48
        bVar1 = DAT_00105060[((local_48 << 2) + iVar10) & 0xf]
        bVar2 = DAT_00108020[((local_48 << 3) + iVar10) & 0x3f]
        
        for local_40 in range(64):
            iVar9 = local_40
            
            uVar8 = buf[(local_48 + 0x3f) % 0x40]
            uVar3 = buf[(local_48 + 1) % 0x40]
            current_byte = buf[local_48]
            
            val_to_rotate = current_byte + DAT_00105060[(iVar9 + iVar10) & 0xf]
            bVar5 = FUN_00102429(val_to_rotate, (iVar9 + iVar10) & 7)
            bVar4 = DAT_00108020[((local_40 << 2) * 2 + iVar9 * 3 + iVar10 * 7) & 0x3f]
            bVar6 = FUN_00102429(uVar8, 3)
            bVar7 = FUN_00102429(uVar3, 5)
            
            buf[local_48] = bVar7 ^ bVar6 ^ bVar5 ^ bVar4 ^ bVar2 ^ bVar1
            
        # Swap Phase (배열 원소 맞바꾸기)
        for local_38 in range(0x20):
            idx1 = (local_38 * 0x11 + local_48 * 0xd) % 0x40
            idx2 = local_38
            buf[idx2], buf[idx1] = buf[idx1], buf[idx2]

    # [Phase 3] 최종 섞기
    for local_30 in range(64):
        idx = ((local_30 << 2) * 2 + local_30 * 3) & 0xf
        val_to_rotate = DAT_00105060[idx] ^ buf[local_30] ^ 0xa5
        buf[local_30] = FUN_00102429(val_to_rotate, 3)

    # [Phase 4] 타겟 배열(정답)과 동일한지 제약 조건 추가
    for i in range(64):
        solver.add(buf[i] == DAT_00105020[i])

    print("[*] Z3 연산 중... (수식 복잡도에 따라 수 초 ~ 수 분이 걸릴 수 있습니다)")
    
    if solver.check() == sat:
        m = solver.model()
        result = "".join([chr(m[flag[i]].as_long()) for i in range(64)])
        print(f"\n🎉 성공! 알아낸 Flag:\n{result}")
    else:
        print("\n❌ 만족하는 해가 없습니다 (Unsat). C 코드의 형변환 규칙이나 Swap 함수(FUN_0010339e) 내부 로직을 다시 살펴봐야 할 수 있습니다.")

if __name__ == '__main__':
    main()