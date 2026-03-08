def ror8(val, shift):
    """8비트 순환 우측 시프트 (Rotate Right)"""
    return ((val >> shift) | (val << (8 - shift))) & 0xFF

def next_rand(seed):
    """VM 내부의 고정 시드 난수 생성기 (Xorshift32)"""
    seed ^= (seed << 13) & 0xFFFFFFFF
    seed ^= (seed >> 17) & 0xFFFFFFFF
    seed ^= (seed << 5)  & 0xFFFFFFFF
    return seed

# 1. 타겟 배열 56바이트 (합쳐서 가져왔습니다!)
target_hex = "ffedef7620d18679d1c0eeccc8c416fafafccb5a0cfa70c09b9e95ca0dfa55d1ce6414c8e8c12e16c2d8efd2dffa5dc952d8a5a5a5a5a5a5"

# 2. 아까 복사하신 1040바이트짜리 VM 바이트코드를 여기에 붙여넣으세요! 
# (공백이나 줄바꿈 없이 쭉 이어진 문자열이어야 합니다)
vm_code_hex = "fbaa106cfe3e1420ff12d8d4fc265c08fdfa80bcef0e8470ef624864ff76cc58feca30ccff5e3480fbb2f8b4ff467ce8fd1aa01cfbaea4d0ff8268c4fc96ec38fe6ad0acfefed460fcd29814efe61c48efba40fcfece44b0fb2208a4ef368c98fd8af00cfd1ef4c0fd72b8f4fc063c28fbda605cfd6e6410fb422804ff56ac78fd2a90ecfdbe94a0fe925854fca6dc88fb7a003cfd8e04f0fee2c8e4eff64cd8fb4ab04cffdeb400ff327834fcc6fc68fc9a209cff2e2450fe02e844fc166cb8efea502cff7e54e0ff521894fb669cc8fe3ac07cfd4ec430fea28824fbb60c18ff0a708cff9e7440fff23874fb86bca8ff5ae0dcfdeee490ffc2a884fbd62cf8fbaa106cff3e1420fb12d8d4fc265c08fefa80bcfe0e8470fc624864ff76cc58efca30ccff5e3480fcb2f8b4ff467ce8fc1aa01cfdaea4d0ff8268c4fb96ec38fd6ad0acfbfed460fed29814fee61c48feba40fcfece44b0ef2208a4fb368c98ff8af00cff1ef4c0fb72b8f4ff063c28ffda605cfb6e6410fc422804fb56ac78fc2a90ecfebe94a0fc925854ffa6dc88fe7a003cfd8e04f0fee2c8e4fcf64cd8fd4ab04cfedeb400ff327834ffc6fc68ff9a209cfe2e2450fb02e844fd166cb8feea502cfd7e54e0ff521894ff669cc8fb3ac07cfd4ec430fba28824fcb60c18fe0a708cfb9e7440fdf23874ef86bca8fb5ae0dcfdeee490fdc2a884fed62cf8ffaa106cfe3e1420fd12d8d4fe265c08fdfa80bcfd0e8470ff624864ef76cc58fdca30ccfe5e3480fdb2f8b4ff467ce8ff1aa01cffaea4d0fd8268c4fd96ec38ff6ad0acfcfed460fed29814fbe61c48fcba40fcffce44b0ef2208a4fc368c98ff8af00cfd1ef4c0fc72b8f4fe063c28ffda605cfe6e6410ef422804fe56ac78ff2a90ecefbe94a0fb925854fea6dc88ef7a003cfd8e04f0fde2c8e4fbf64cd8fc4ab04cfbdeb400ff327834fdc6fc68fe9a209cfc2e2450fe02e844ff166cb8fcea502cfe7e54e0fe521894fc669cc8ff3ac07cfe4ec430fba28824fbb60c18ff0a708cfe9e7440eff23874fe86bca8fe5ae0dcffeee490ffc2a884fcd62cf8fdaa106cfb3e1420fd12d8d4fe265c08fefa80bcff0e8470fd624864ff76cc58ffca30ccfb5e3480fbb2f8b4ff467ce8ff1aa01cfcaea4d0fd8268c4fe96ec38ff6ad0acfffed460fbd29814fde61c48fcba40fcfcce44b0fe2208a4ff368c98fe8af00cef1ef4c0ff72b8f4ef063c28fbda605cfc6e6410fe422804fc56ac78ff2a90ecfbbe94a0ef925854ffa6dc88fb7a003cfe8e04f0fde2c8e4fef64cd8ef4ab04cefdeb400fe327834fdc6fc68ef9a209cfe2e2450ff02e844ef166cb8fdea502cff7e54e0fb521894fb669cc8fc3ac07cfe4ec430fba28824fcb60c18fb0a708cff9e7440fff23874fd86bca8ff5ae0dcfbeee490fcc2a884fed62cf8ffaa106cfb3e1420ff12d8d4ff265c0800000000000000000000000000000000"

target_raw = bytes.fromhex(target_hex)
vm_raw = bytes.fromhex(vm_code_hex)

# 3. 타겟 배열 XOR 역연산 (0xa5a5a5a5a5a5a5a5)
target = bytearray()
for i in range(0, 56, 8):
    chunk = int.from_bytes(target_raw[i:i+8], 'little')
    chunk ^= 0xa5a5a5a5a5a5a5a5
    target.extend(chunk.to_bytes(8, 'little'))

# 비교는 50바이트(0x32)까지만 이루어지므로 자릅니다.
target = bytearray(target[:50])

# 4. VM 명령어 배열 복원 (0xdeadbeef XOR) 및 PRNG 트레이스 수집
trace = []
seed = 0xa1b2c3d4

for i in range(0, 0x104 * 4, 4):
    inst = int.from_bytes(vm_raw[i:i+4], 'little')
    inst ^= 0xdeadbeef
    
    opcode = inst & 0xFF
    idx = ((inst >> 8) & 0xFF) % 0x32
    val1 = (inst >> 16) & 0xFF
    val2 = (inst >> 24) & 0xFF
    
    rand8 = 0
    # 명령어가 0x12(단순 ROL)가 아닐 때만 난수를 생성합니다.
    if opcode in (0x10, 0x11, 0x13, 0x14):
        seed = next_rand(seed)
        rand8 = (seed >> 24) & 0xFF
        
    # 명령어 실행 기록 저장
    trace.append((opcode, idx, val1, val2, rand8))

# 5. 역연산 진행 (VM 실행의 역순으로 되돌리기!)
for opcode, idx, val1, val2, rand8 in reversed(trace):
    if opcode == 0x10:
        target[idx] = (target[idx] ^ val1 ^ rand8) & 0xFF
    elif opcode == 0x11:
        target[idx] = (target[idx] - (val1 ^ rand8)) & 0xFF
    elif opcode == 0x12:
        target[idx] = ror8(target[idx], val2 & 7)
    elif opcode == 0x13:
        idx2 = (val1 ^ rand8) % 0x32
        target[idx], target[idx2] = target[idx2], target[idx]
    elif opcode == 0x14:
        tmp = ror8(target[idx], val2 & 7)
        target[idx] = ((tmp - val1) & 0xFF) ^ rand8

# 결과 출력!
print("🎉 FLAG:", target.decode('ascii'))