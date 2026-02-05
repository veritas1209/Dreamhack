from z3 import *
import re
import struct

# =========================================================
# 1. Configuration & Helper Functions
# =========================================================

# 64비트 회전 연산 (Rotate Left/Right) 구현
def rotate_left(val, r, width=64):
    return ((val << (r % width)) | LShR(val, (width - (r % width)))) & ((1 << width) - 1)

def rotate_right(val, r, width=64):
    return (LShR(val, (r % width)) | (val << (width - (r % width)))) & ((1 << width) - 1)

# ebx 오프셋에 따른 연산 매핑 (덤프 분석 결과)
# 예: lea eax,[ebx-0x3e6e] -> 0x3e6e
OP_MAP = {
    0x3e6e: "ADD",
    0x3e19: "MUL",
    0x3ce4: "XOR",
    0x3d8d: "AND",
    0x3d4c: "OR",
    0x3d0b: "MOV",
    0x3dd1: "NOT",
    0x3b54: "SHL",
    0x3b8a: "SHR",
    0x3c06: "ROL",
    0x3bca: "ROR",
    0x3bc5: "DIV", # 추정
    0x3b85: "MOD", # 추정 (나머지)
    0x3b4f: "INC"
}

# =========================================================
# 2. Data Parsing & Z3 Setup
# =========================================================

# Z3 초기화
solver = Solver()
memory = {}  # ebp 오프셋(int) -> Z3 BitVec
registers = {} # cpu 레지스터 -> 현재 들고 있는 값/포인터
stack = []

# 8개의 입력값(Flag) 변수 생성 (ebp-0x2c0 부터 0x2f8까지 8바이트 단위)
# 덤프의 0x804954d: lea eax,[ebp-0x2c0] 가 입력 버퍼의 시작점
INPUT_BASE = 0x2c0
flags = [BitVec(f"flag_{i}", 64) for i in range(8)]
for i in range(8):
    offset = INPUT_BASE - (i * 8) # 스택은 아래로 자라지만 ebp 오프셋 숫자는 커짐
    memory[offset] = flags[i]

# =========================================================
# 3. Parse Dump Text (Constants & Instructions)
# =========================================================

# 사용자가 제공한 덤프 텍스트 (파일에서 읽거나 여기에 붙여넣기)
# 실제 실행시는 'dump.txt'에 위 내용을 저장하고 실행하세요.
dump_content = """
   0x080494e7:	lea    ecx,[esp+0x4]
   0x080494eb:	and    esp,0xfffffff0
   0x080494ee:	push   DWORD PTR [ecx-0x4]
   0x080494f1:	push   ebp
   0x080494f2:	mov    ebp,esp
   0x080494f4:	push   edi
   0x080494f5:	push   esi
   0x080494f6:	push   ebx
   0x080494f7:	push   ecx
   0x080494f8:	sub    esp,0x838
   0x080494fe:	call   0x80490c0
   0x08049503:	add    ebx,0x3af1
   0x08049509:	mov    eax,DWORD PTR [ebx-0x4]
   0x0804950f:	mov    eax,DWORD PTR [eax]
   0x08049511:	push   eax
   0x08049512:	push   0x40
   0x08049514:	push   0x1
   0x08049516:	lea    eax,[ebp-0x280]
   0x0804951c:	push   eax
   0x0804951d:	call   0x8049050 <fread@plt>
   0x08049522:	add    esp,0x10
   0x08049525:	cmp    eax,0x40
   0x08049528:	je     0x8049534
   0x0804952a:	mov    eax,0x1
   0x0804952f:	jmp    0x804ae0f
   0x08049534:	mov    DWORD PTR [ebp-0x1c],0x0
   0x0804953b:	jmp    0x804956e
   0x0804953d:	mov    eax,DWORD PTR [ebp-0x1c]
   0x08049540:	shl    eax,0x3
   0x08049543:	mov    edx,eax
   0x08049545:	lea    eax,[ebp-0x280]
   0x0804954b:	add    edx,eax
   0x0804954d:	lea    eax,[ebp-0x2c0]
   0x08049553:	mov    ecx,DWORD PTR [ebp-0x1c]
   0x08049556:	shl    ecx,0x3
   0x08049559:	add    eax,ecx
   0x0804955b:	sub    esp,0x4
   0x0804955e:	push   0x8
   0x08049560:	push   edx
   0x08049561:	push   eax
   0x08049562:	call   0x8049040 <memcpy@plt>
   0x08049567:	add    esp,0x10
   0x0804956a:	add    DWORD PTR [ebp-0x1c],0x1
   0x0804956e:	cmp    DWORD PTR [ebp-0x1c],0x7
   0x08049572:	jle    0x804953d
   0x08049574:	mov    DWORD PTR [ebp-0x300],0x89abcdef
   0x0804957e:	mov    DWORD PTR [ebp-0x2fc],0x1234567
   0x08049588:	mov    DWORD PTR [ebp-0x2f8],0xb0a0908
   0x08049592:	mov    DWORD PTR [ebp-0x2f4],0xf0e0d0c
   0x0804959c:	mov    DWORD PTR [ebp-0x2f0],0x11111111
   0x080495a6:	mov    DWORD PTR [ebp-0x2ec],0x11111111
   0x080495b0:	mov    DWORD PTR [ebp-0x2e8],0x22222222
   0x080495ba:	mov    DWORD PTR [ebp-0x2e4],0x22222222
   0x080495c4:	mov    DWORD PTR [ebp-0x2e0],0x33333333
   0x080495ce:	mov    DWORD PTR [ebp-0x2dc],0x33333333
   0x080495d8:	mov    DWORD PTR [ebp-0x2d8],0x44444444
   0x080495e2:	mov    DWORD PTR [ebp-0x2d4],0x44444444
   0x080495ec:	mov    DWORD PTR [ebp-0x2d0],0x55555555
   0x080495f6:	mov    DWORD PTR [ebp-0x2cc],0x55555555
   0x08049600:	mov    DWORD PTR [ebp-0x2c8],0x66666666
   0x0804960a:	mov    DWORD PTR [ebp-0x2c4],0x66666666
   0x08049614:	mov    DWORD PTR [ebp-0x340],0x87654321
   0x0804961e:	mov    DWORD PTR [ebp-0x33c],0xfedcba09
   0x08049628:	mov    DWORD PTR [ebp-0x338],0x1234567
   0x08049632:	mov    DWORD PTR [ebp-0x334],0x89abcdef
   0x0804963c:	mov    DWORD PTR [ebp-0x330],0xdeadbeef
   0x08049646:	mov    DWORD PTR [ebp-0x32c],0xcafebabe
   0x08049650:	mov    DWORD PTR [ebp-0x328],0xdeadc0de
   0x0804965a:	mov    DWORD PTR [ebp-0x324],0xbadf00d
   0x08049664:	mov    DWORD PTR [ebp-0x320],0x2468ace0
   0x0804966e:	mov    DWORD PTR [ebp-0x31c],0x13579bdf
   0x08049678:	mov    DWORD PTR [ebp-0x318],0x12345678
   0x08049682:	mov    DWORD PTR [ebp-0x314],0xcafeface
   0x0804968c:	mov    DWORD PTR [ebp-0x310],0xf0f0f0f
   0x08049696:	mov    DWORD PTR [ebp-0x30c],0xf0f0f0f
   0x080496a0:	mov    DWORD PTR [ebp-0x308],0xf0f0f0f0
   0x080496aa:	mov    DWORD PTR [ebp-0x304],0xf0f0f0f0
   0x080496b4:	mov    DWORD PTR [ebp-0x380],0xa0a0a0a
   0x080496be:	mov    DWORD PTR [ebp-0x37c],0xa0a0a0a
   0x080496c8:	mov    DWORD PTR [ebp-0x378],0x1b1b1b1b
   0x080496d2:	mov    DWORD PTR [ebp-0x374],0x1b1b1b1b
   0x080496dc:	mov    DWORD PTR [ebp-0x370],0x2c2c2c2c
   0x080496e6:	mov    DWORD PTR [ebp-0x36c],0x2c2c2c2c
   0x080496f0:	mov    DWORD PTR [ebp-0x368],0x3d3d3d3d
   0x080496fa:	mov    DWORD PTR [ebp-0x364],0x3d3d3d3d
   0x08049704:	mov    DWORD PTR [ebp-0x360],0x4e4e4e4e
   0x0804970e:	mov    DWORD PTR [ebp-0x35c],0x4e4e4e4e
   0x08049718:	mov    DWORD PTR [ebp-0x358],0x5f5f5f5f
   0x08049722:	mov    DWORD PTR [ebp-0x354],0x5f5f5f5f
   0x0804972c:	mov    DWORD PTR [ebp-0x350],0x60606060
   0x08049736:	mov    DWORD PTR [ebp-0x34c],0x60606060
   0x08049740:	mov    DWORD PTR [ebp-0x348],0x71717171
   0x0804974a:	mov    DWORD PTR [ebp-0x344],0x71717171
   0x08049754:	mov    DWORD PTR [ebp-0x3c0],0x13
   0x0804975e:	mov    DWORD PTR [ebp-0x3bc],0x0
   0x08049768:	mov    DWORD PTR [ebp-0x3b8],0x15
   0x08049772:	mov    DWORD PTR [ebp-0x3b4],0x0
   0x0804977c:	mov    DWORD PTR [ebp-0x3b0],0x17
   0x08049786:	mov    DWORD PTR [ebp-0x3ac],0x0
   0x08049790:	mov    DWORD PTR [ebp-0x3a8],0x19
   0x0804979a:	mov    DWORD PTR [ebp-0x3a4],0x0
   0x080497a4:	mov    DWORD PTR [ebp-0x3a0],0x1b
   0x080497ae:	mov    DWORD PTR [ebp-0x39c],0x0
   0x080497b8:	mov    DWORD PTR [ebp-0x398],0x1d
   0x080497c2:	mov    DWORD PTR [ebp-0x394],0x0
   0x080497cc:	mov    DWORD PTR [ebp-0x390],0x1f
   0x080497d6:	mov    DWORD PTR [ebp-0x38c],0x0
   0x080497e0:	mov    DWORD PTR [ebp-0x388],0x21
   0x080497ea:	mov    DWORD PTR [ebp-0x384],0x0
   0x080497f4:	mov    DWORD PTR [ebp-0x400],0x31
   0x080497fe:	mov    DWORD PTR [ebp-0x3fc],0x0
   0x08049808:	mov    DWORD PTR [ebp-0x3f8],0x33
   0x08049812:	mov    DWORD PTR [ebp-0x3f4],0x0
   0x0804981c:	mov    DWORD PTR [ebp-0x3f0],0x35
   0x08049826:	mov    DWORD PTR [ebp-0x3ec],0x0
   0x08049830:	mov    DWORD PTR [ebp-0x3e8],0x37
   0x0804983a:	mov    DWORD PTR [ebp-0x3e4],0x0
   0x08049844:	mov    DWORD PTR [ebp-0x3e0],0x39
   0x0804984e:	mov    DWORD PTR [ebp-0x3dc],0x0
   0x08049858:	mov    DWORD PTR [ebp-0x3d8],0x3b
   0x08049862:	mov    DWORD PTR [ebp-0x3d4],0x0
   0x0804986c:	mov    DWORD PTR [ebp-0x3d0],0x3d
   0x08049876:	mov    DWORD PTR [ebp-0x3cc],0x0
   0x08049880:	mov    DWORD PTR [ebp-0x3c8],0x3f
   0x0804988a:	mov    DWORD PTR [ebp-0x3c4],0x0
   0x08049894:	mov    DWORD PTR [ebp-0x420],0x5
   0x0804989e:	mov    DWORD PTR [ebp-0x41c],0xb
   0x080498a8:	mov    DWORD PTR [ebp-0x418],0x11
   0x080498b2:	mov    DWORD PTR [ebp-0x414],0x17
   0x080498bc:	mov    DWORD PTR [ebp-0x410],0x1d
   0x080498c6:	mov    DWORD PTR [ebp-0x40c],0x3
   0x080498d0:	mov    DWORD PTR [ebp-0x408],0x7
   0x080498da:	mov    DWORD PTR [ebp-0x404],0xd
   0x080498e4:	mov    DWORD PTR [ebp-0x440],0x8
   0x080498ee:	mov    DWORD PTR [ebp-0x43c],0x10
   0x080498f8:	mov    DWORD PTR [ebp-0x438],0x18
   0x08049902:	mov    DWORD PTR [ebp-0x434],0x20
   0x0804990c:	mov    DWORD PTR [ebp-0x430],0x4
   0x08049916:	mov    DWORD PTR [ebp-0x42c],0xc
   0x08049920:	mov    DWORD PTR [ebp-0x428],0x14
   0x0804992a:	mov    DWORD PTR [ebp-0x424],0x1c
   0x08049934:	mov    DWORD PTR [ebp-0x480],0x11
   0x0804993e:	mov    DWORD PTR [ebp-0x47c],0x0
   0x08049948:	mov    DWORD PTR [ebp-0x478],0x13
   0x08049952:	mov    DWORD PTR [ebp-0x474],0x0
   0x0804995c:	mov    DWORD PTR [ebp-0x470],0x17
   0x08049966:	mov    DWORD PTR [ebp-0x46c],0x0
   0x08049970:	mov    DWORD PTR [ebp-0x468],0x1d
   0x0804997a:	mov    DWORD PTR [ebp-0x464],0x0
   0x08049984:	mov    DWORD PTR [ebp-0x460],0x21
   0x0804998e:	mov    DWORD PTR [ebp-0x45c],0x0
   0x08049998:	mov    DWORD PTR [ebp-0x458],0x27
   0x080499a2:	mov    DWORD PTR [ebp-0x454],0x0
   0x080499ac:	mov    DWORD PTR [ebp-0x450],0x2b
   0x080499b6:	mov    DWORD PTR [ebp-0x44c],0x0
   0x080499c0:	mov    DWORD PTR [ebp-0x448],0x2f
   0x080499ca:	mov    DWORD PTR [ebp-0x444],0x0
   0x080499d4:	mov    DWORD PTR [ebp-0x4c0],0xa0a0a0a
   0x080499de:	mov    DWORD PTR [ebp-0x4bc],0xa0a0a0a
   0x080499e8:	mov    DWORD PTR [ebp-0x4b8],0x1b1b1b1b
   0x080499f2:	mov    DWORD PTR [ebp-0x4b4],0x1b1b1b1b
   0x080499fc:	mov    DWORD PTR [ebp-0x4b0],0x2c2c2c2c
   0x08049a06:	mov    DWORD PTR [ebp-0x4ac],0x2c2c2c2c
   0x08049a10:	mov    DWORD PTR [ebp-0x4a8],0x3d3d3d3d
   0x08049a1a:	mov    DWORD PTR [ebp-0x4a4],0x3d3d3d3d
   0x08049a24:	mov    DWORD PTR [ebp-0x4a0],0x4e4e4e4e
   0x08049a2e:	mov    DWORD PTR [ebp-0x49c],0x4e4e4e4e
   0x08049a38:	mov    DWORD PTR [ebp-0x498],0x5f5f5f5f
   0x08049a42:	mov    DWORD PTR [ebp-0x494],0x5f5f5f5f
   0x08049a4c:	mov    DWORD PTR [ebp-0x490],0x60606060
   0x08049a56:	mov    DWORD PTR [ebp-0x48c],0x60606060
   0x08049a60:	mov    DWORD PTR [ebp-0x488],0x71717171
   0x08049a6a:	mov    DWORD PTR [ebp-0x484],0x71717171
   0x08049a74:	mov    DWORD PTR [ebp-0x500],0xf0f0f0f
   0x08049a7e:	mov    DWORD PTR [ebp-0x4fc],0xf0f0f0f
   0x08049a88:	mov    DWORD PTR [ebp-0x4f8],0xf0f0f0f0
   0x08049a92:	mov    DWORD PTR [ebp-0x4f4],0xf0f0f0f0
   0x08049a9c:	mov    DWORD PTR [ebp-0x4f0],0x55555555
   0x08049aa6:	mov    DWORD PTR [ebp-0x4ec],0xaaaaaaaa
   0x08049ab0:	mov    DWORD PTR [ebp-0x4e8],0xaaaaaaaa
   0x08049aba:	mov    DWORD PTR [ebp-0x4e4],0x55555555
   0x08049ac4:	mov    DWORD PTR [ebp-0x4e0],0x90abcdef
   0x08049ace:	mov    DWORD PTR [ebp-0x4dc],0x12345678
   0x08049ad8:	mov    DWORD PTR [ebp-0x4d8],0x76543210
   0x08049ae2:	mov    DWORD PTR [ebp-0x4d4],0xfedcba98
   0x08049aec:	mov    DWORD PTR [ebp-0x4d0],0x4b5a6978
   0x08049af6:	mov    DWORD PTR [ebp-0x4cc],0xf1e2d3c
   0x08049b00:	mov    DWORD PTR [ebp-0x4c8],0x1234567
   0x08049b0a:	mov    DWORD PTR [ebp-0x4c4],0x89abcdef
   0x08049b14:	mov    DWORD PTR [ebp-0x540],0xe5b71ca4
   0x08049b1e:	mov    DWORD PTR [ebp-0x53c],0x35ee0f56
   0x08049b28:	mov    DWORD PTR [ebp-0x538],0x6a1056fd
   0x08049b32:	mov    DWORD PTR [ebp-0x534],0x3ffd40a1
   0x08049b3c:	mov    DWORD PTR [ebp-0x530],0x2c5ba31a
   0x08049b46:	mov    DWORD PTR [ebp-0x52c],0xca5272e5
   0x08049b50:	mov    DWORD PTR [ebp-0x528],0x92a71b25
   0x08049b5a:	mov    DWORD PTR [ebp-0x524],0x6bc3120b
   0x08049b64:	mov    DWORD PTR [ebp-0x520],0xc2b935a3
   0x08049b6e:	mov    DWORD PTR [ebp-0x51c],0x104fd2f6
   0x08049b78:	mov    DWORD PTR [ebp-0x518],0x63b1b1d6
   0x08049b82:	mov    DWORD PTR [ebp-0x514],0xf1b5ca36
   0x08049b8c:	mov    DWORD PTR [ebp-0x510],0xdad2aa08
   0x08049b96:	mov    DWORD PTR [ebp-0x50c],0xcae30b30
   0x08049ba0:	mov    DWORD PTR [ebp-0x508],0xc13d6ebe
   0x08049baa:	mov    DWORD PTR [ebp-0x504],0x7586bb8d
   0x08049bb4:	mov    DWORD PTR [ebp-0x20],0x0
   0x08049bbb:	jmp    0x8049bf3
   0x08049bbd:	mov    eax,DWORD PTR [ebp-0x20]
   0x08049bc0:	mov    eax,DWORD PTR [ebp+eax*4-0x420]
   0x08049bc7:	mov    ecx,eax
   0x08049bc9:	lea    edx,[ebp-0x808]
   0x08049bcf:	mov    eax,DWORD PTR [ebp-0x20]
   0x08049bd2:	add    eax,edx
   0x08049bd4:	mov    BYTE PTR [eax],cl
   0x08049bd6:	mov    eax,DWORD PTR [ebp-0x20]
   0x08049bd9:	mov    eax,DWORD PTR [ebp+eax*4-0x440]
   0x08049be0:	mov    ecx,eax
   0x08049be2:	lea    edx,[ebp-0x810]
   0x08049be8:	mov    eax,DWORD PTR [ebp-0x20]
   0x08049beb:	add    eax,edx
   0x08049bed:	mov    BYTE PTR [eax],cl
   0x08049bef:	add    DWORD PTR [ebp-0x20],0x1
   0x08049bf3:	cmp    DWORD PTR [ebp-0x20],0x7
   0x08049bf7:	jle    0x8049bbd
   0x08049bf9:	mov    DWORD PTR [ebp-0x24],0x0
   0x08049c00:	jmp    0x804a0f6
   0x08049c05:	lea    eax,[ebp-0x300]
   0x08049c0b:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049c0e:	shl    edx,0x3
   0x08049c11:	add    eax,edx
   0x08049c13:	mov    ecx,eax
   0x08049c15:	lea    eax,[ebp-0x2c0]
   0x08049c1b:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049c1e:	shl    edx,0x3
   0x08049c21:	add    eax,edx
   0x08049c23:	mov    esi,eax
   0x08049c25:	lea    eax,[ebp-0x580]
   0x08049c2b:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049c2e:	shl    edx,0x3
   0x08049c31:	add    eax,edx
   0x08049c33:	mov    edx,eax
   0x08049c35:	lea    eax,[ebx-0x3e6e]
   0x08049c3b:	mov    DWORD PTR [ebp-0xc4],eax
   0x08049c41:	mov    DWORD PTR [ebp-0xc8],edx
   0x08049c47:	mov    DWORD PTR [ebp-0xcc],esi
   0x08049c4d:	mov    DWORD PTR [ebp-0xd0],ecx
   0x08049c53:	push   eax
   0x08049c54:	push   ebx
   0x08049c55:	push   ecx
   0x08049c56:	push   edx
   0x08049c57:	push   esi
   0x08049c58:	push   edi
   0x08049c59:	push   ebp
   0x08049c5a:	nop
   0x08049c5b:	mov    eax,DWORD PTR [ebp-0xc4]
   0x08049c61:	mov    DWORD PTR [ebp-0xd4],eax
   0x08049c67:	mov    eax,DWORD PTR [ebp-0xc8]
   0x08049c6d:	mov    DWORD PTR [ebp-0xd8],eax
   0x08049c73:	mov    eax,DWORD PTR [ebp-0xcc]
   0x08049c79:	mov    DWORD PTR [ebp-0xdc],eax
   0x08049c7f:	mov    eax,DWORD PTR [ebp-0xd0]
   0x08049c85:	mov    DWORD PTR [ebp-0xe0],eax
   0x08049c8b:	mov    eax,DWORD PTR [ebp-0xd4]
   0x08049c91:	mov    esi,DWORD PTR [ebp-0xd8]
   0x08049c97:	mov    edx,DWORD PTR [ebp-0xdc]
   0x08049c9d:	mov    ecx,DWORD PTR [ebp-0xe0]
   0x08049ca3:	sub    esp,0x8
   0x08049ca6:	xor    ebx,ebx
   0x08049ca8:	mov    bl,0x3
   0x08049caa:	shl    ebx,1
   0x08049cac:	shl    ebx,0x2
   0x08049caf:	add    ebx,0x1a
   0x08049cb2:	inc    ebx
   0x08049cb3:	lea    edi,[esp+0x4]
   0x08049cb7:	or     ebx,0x0
   0x08049cba:	nop
   0x08049cbb:	test   ebx,ebx
   0x08049cbd:	nop
   0x08049cbe:	mov    DWORD PTR [edi],ebx
   0x08049cc0:	mov    DWORD PTR [esp],eax
   0x08049cc3:	mov    edi,0x8049cc9
   0x08049cc8:	retf
   0x08049cc9:	dec    eax
   0x08049cca:	sub    esp,0x8
   0x08049ccd:	dec    ebp
   0x08049cce:	xor    ecx,ecx
   0x08049cd0:	inc    ecx
   0x08049cd1:	mov    cl,0x23
   0x08049cd3:	dec    ecx
   0x08049cd4:	shl    ecx,0x0
   0x08049cd7:	dec    ecx
   0x08049cd8:	add    ecx,0x0
   0x08049cdb:	dec    esp
   0x08049cdc:	lea    eax,[esp+0x4]
   0x08049ce0:	dec    ebp
   0x08049ce1:	mov    edx,ecx
   0x08049ce3:	dec    ecx
   0x08049ce4:	shl    edx,1
   0x08049ce6:	dec    ecx
   0x08049ce7:	shr    edx,1
   0x08049ce9:	dec    ebp
   0x08049cea:	xor    ebx,ebx
   0x08049cec:	dec    ecx
   0x08049ced:	inc    ebx
   0x08049cef:	dec    ecx
   0x08049cf0:	dec    ebx
   0x08049cf2:	dec    ebp
   0x08049cf3:	xchg   esp,esp
   0x08049cf5:	inc    ebp
   0x08049cf6:	mov    DWORD PTR [eax],ecx
   0x08049cf8:	mov    DWORD PTR [esp],0x8049d00
   0x08049cff:	retf
   0x08049d00:	nop
   0x08049d01:	pop    ebp
   0x08049d02:	pop    edi
   0x08049d03:	pop    esi
   0x08049d04:	pop    edx
   0x08049d05:	pop    ecx
   0x08049d06:	pop    ebx
   0x08049d07:	pop    eax
   0x08049d08:	nop
   0x08049d09:	nop
   0x08049d0a:	mov    eax,DWORD PTR [ebp-0x24]
   0x08049d0d:	mov    esi,DWORD PTR [ebp+eax*8-0x580]
   0x08049d14:	mov    edi,DWORD PTR [ebp+eax*8-0x57c]
   0x08049d1b:	mov    eax,DWORD PTR [ebp-0x24]
   0x08049d1e:	mov    edx,DWORD PTR [ebp+eax*8-0x33c]
   0x08049d25:	mov    eax,DWORD PTR [ebp+eax*8-0x340]
   0x08049d2c:	xor    eax,esi
   0x08049d2e:	xor    edx,edi
   0x08049d30:	mov    ecx,DWORD PTR [ebp-0x24]
   0x08049d33:	mov    DWORD PTR [ebp+ecx*8-0x5c0],eax
   0x08049d3a:	mov    DWORD PTR [ebp+ecx*8-0x5bc],edx
   0x08049d41:	lea    edx,[ebp-0x808]
   0x08049d47:	mov    eax,DWORD PTR [ebp-0x24]
   0x08049d4a:	add    eax,edx
   0x08049d4c:	mov    ecx,eax
   0x08049d4e:	lea    eax,[ebp-0x5c0]
   0x08049d54:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049d57:	shl    edx,0x3
   0x08049d5a:	add    eax,edx
   0x08049d5c:	mov    esi,eax
   0x08049d5e:	lea    eax,[ebp-0x600]
   0x08049d64:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049d67:	shl    edx,0x3
   0x08049d6a:	add    eax,edx
   0x08049d6c:	mov    edx,eax
   0x08049d6e:	lea    eax,[ebx-0x3c42]
   0x08049d74:	mov    DWORD PTR [ebp-0xa4],eax
   0x08049d7a:	mov    DWORD PTR [ebp-0xa8],edx
   0x08049d80:	mov    DWORD PTR [ebp-0xac],esi
   0x08049d86:	mov    DWORD PTR [ebp-0xb0],ecx
   0x08049d8c:	push   eax
   0x08049d8d:	push   ebx
   0x08049d8e:	push   ecx
   0x08049d8f:	push   edx
   0x08049d90:	push   esi
   0x08049d91:	push   edi
   0x08049d92:	push   ebp
   0x08049d93:	nop
   0x08049d94:	mov    eax,DWORD PTR [ebp-0xa4]
   0x08049d9a:	mov    DWORD PTR [ebp-0xb4],eax
   0x08049da0:	mov    eax,DWORD PTR [ebp-0xa8]
   0x08049da6:	mov    DWORD PTR [ebp-0xb8],eax
   0x08049dac:	mov    eax,DWORD PTR [ebp-0xac]
   0x08049db2:	mov    DWORD PTR [ebp-0xbc],eax
   0x08049db8:	mov    eax,DWORD PTR [ebp-0xb0]
   0x08049dbe:	mov    DWORD PTR [ebp-0xc0],eax
   0x08049dc4:	mov    eax,DWORD PTR [ebp-0xb4]
   0x08049dca:	mov    esi,DWORD PTR [ebp-0xb8]
   0x08049dd0:	mov    edx,DWORD PTR [ebp-0xbc]
   0x08049dd6:	mov    ecx,DWORD PTR [ebp-0xc0]
   0x08049ddc:	sub    esp,0x8
   0x08049ddf:	xor    ebx,ebx
   0x08049de1:	mov    bl,0x3
   0x08049de3:	shl    ebx,1
   0x08049de5:	shl    ebx,0x2
   0x08049de8:	add    ebx,0x1a
   0x08049deb:	inc    ebx
   0x08049dec:	lea    edi,[esp+0x4]
   0x08049df0:	or     ebx,0x0
   0x08049df3:	nop
   0x08049df4:	test   ebx,ebx
   0x08049df6:	nop
   0x08049df7:	mov    DWORD PTR [edi],ebx
   0x08049df9:	mov    DWORD PTR [esp],eax
   0x08049dfc:	mov    edi,0x8049e02
   0x08049e01:	retf
   0x08049e02:	dec    eax
   0x08049e03:	sub    esp,0x8
   0x08049e06:	dec    ebp
   0x08049e07:	xor    ecx,ecx
   0x08049e09:	inc    ecx
   0x08049e0a:	mov    cl,0x23
   0x08049e0c:	dec    ecx
   0x08049e0d:	shl    ecx,0x0
   0x08049e10:	dec    ecx
   0x08049e11:	add    ecx,0x0
   0x08049e14:	dec    esp
   0x08049e15:	lea    eax,[esp+0x4]
   0x08049e19:	dec    ebp
   0x08049e1a:	mov    edx,ecx
   0x08049e1c:	dec    ecx
   0x08049e1d:	shl    edx,1
   0x08049e1f:	dec    ecx
   0x08049e20:	shr    edx,1
   0x08049e22:	dec    ebp
   0x08049e23:	xor    ebx,ebx
   0x08049e25:	dec    ecx
   0x08049e26:	inc    ebx
   0x08049e28:	dec    ecx
   0x08049e29:	dec    ebx
   0x08049e2b:	dec    ebp
   0x08049e2c:	xchg   esp,esp
   0x08049e2e:	inc    ebp
   0x08049e2f:	mov    DWORD PTR [eax],ecx
   0x08049e31:	mov    DWORD PTR [esp],0x8049e39
   0x08049e38:	retf
   0x08049e39:	nop
   0x08049e3a:	pop    ebp
   0x08049e3b:	pop    edi
   0x08049e3c:	pop    esi
   0x08049e3d:	pop    edx
   0x08049e3e:	pop    ecx
   0x08049e3f:	pop    ebx
   0x08049e40:	pop    eax
   0x08049e41:	nop
   0x08049e42:	nop
   0x08049e43:	lea    eax,[ebp-0x3c0]
   0x08049e49:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049e4c:	shl    edx,0x3
   0x08049e4f:	add    eax,edx
   0x08049e51:	mov    ecx,eax
   0x08049e53:	lea    eax,[ebp-0x600]
   0x08049e59:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049e5c:	shl    edx,0x3
   0x08049e5f:	add    eax,edx
   0x08049e61:	mov    esi,eax
   0x08049e63:	lea    eax,[ebp-0x640]
   0x08049e69:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049e6c:	shl    edx,0x3
   0x08049e6f:	add    eax,edx
   0x08049e71:	mov    edx,eax
   0x08049e73:	lea    eax,[ebx-0x3e19]
   0x08049e79:	mov    DWORD PTR [ebp-0x84],eax
   0x08049e7f:	mov    DWORD PTR [ebp-0x88],edx
   0x08049e85:	mov    DWORD PTR [ebp-0x8c],esi
   0x08049e8b:	mov    DWORD PTR [ebp-0x90],ecx
   0x08049e91:	push   eax
   0x08049e92:	push   ebx
   0x08049e93:	push   ecx
   0x08049e94:	push   edx
   0x08049e95:	push   esi
   0x08049e96:	push   edi
   0x08049e97:	push   ebp
   0x08049e98:	nop
   0x08049e99:	mov    eax,DWORD PTR [ebp-0x84]
   0x08049e9f:	mov    DWORD PTR [ebp-0x94],eax
   0x08049ea5:	mov    eax,DWORD PTR [ebp-0x88]
   0x08049eab:	mov    DWORD PTR [ebp-0x98],eax
   0x08049eb1:	mov    eax,DWORD PTR [ebp-0x8c]
   0x08049eb7:	mov    DWORD PTR [ebp-0x9c],eax
   0x08049ebd:	mov    eax,DWORD PTR [ebp-0x90]
   0x08049ec3:	mov    DWORD PTR [ebp-0xa0],eax
   0x08049ec9:	mov    eax,DWORD PTR [ebp-0x94]
   0x08049ecf:	mov    esi,DWORD PTR [ebp-0x98]
   0x08049ed5:	mov    edx,DWORD PTR [ebp-0x9c]
   0x08049edb:	mov    ecx,DWORD PTR [ebp-0xa0]
   0x08049ee1:	sub    esp,0x8
   0x08049ee4:	xor    ebx,ebx
   0x08049ee6:	mov    bl,0x3
   0x08049ee8:	shl    ebx,1
   0x08049eea:	shl    ebx,0x2
   0x08049eed:	add    ebx,0x1a
   0x08049ef0:	inc    ebx
   0x08049ef1:	lea    edi,[esp+0x4]
   0x08049ef5:	or     ebx,0x0
   0x08049ef8:	nop
   0x08049ef9:	test   ebx,ebx
   0x08049efb:	nop
   0x08049efc:	mov    DWORD PTR [edi],ebx
   0x08049efe:	mov    DWORD PTR [esp],eax
   0x08049f01:	mov    edi,0x8049f07
   0x08049f06:	retf
   0x08049f07:	dec    eax
   0x08049f08:	sub    esp,0x8
   0x08049f0b:	dec    ebp
   0x08049f0c:	xor    ecx,ecx
   0x08049f0e:	inc    ecx
   0x08049f0f:	mov    cl,0x23
   0x08049f11:	dec    ecx
   0x08049f12:	shl    ecx,0x0
   0x08049f15:	dec    ecx
   0x08049f16:	add    ecx,0x0
   0x08049f19:	dec    esp
   0x08049f1a:	lea    eax,[esp+0x4]
   0x08049f1e:	dec    ebp
   0x08049f1f:	mov    edx,ecx
   0x08049f21:	dec    ecx
   0x08049f22:	shl    edx,1
   0x08049f24:	dec    ecx
   0x08049f25:	shr    edx,1
   0x08049f27:	dec    ebp
   0x08049f28:	xor    ebx,ebx
   0x08049f2a:	dec    ecx
   0x08049f2b:	inc    ebx
   0x08049f2d:	dec    ecx
   0x08049f2e:	dec    ebx
   0x08049f30:	dec    ebp
   0x08049f31:	xchg   esp,esp
   0x08049f33:	inc    ebp
   0x08049f34:	mov    DWORD PTR [eax],ecx
   0x08049f36:	mov    DWORD PTR [esp],0x8049f3e
   0x08049f3d:	retf
   0x08049f3e:	nop
   0x08049f3f:	pop    ebp
   0x08049f40:	pop    edi
   0x08049f41:	pop    esi
   0x08049f42:	pop    edx
   0x08049f43:	pop    ecx
   0x08049f44:	pop    ebx
   0x08049f45:	pop    eax
   0x08049f46:	nop
   0x08049f47:	nop
   0x08049f48:	lea    eax,[ebp-0x640]
   0x08049f4e:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049f51:	shl    edx,0x3
   0x08049f54:	add    eax,edx
   0x08049f56:	mov    ecx,eax
   0x08049f58:	lea    eax,[ebp-0x640]
   0x08049f5e:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049f61:	shl    edx,0x3
   0x08049f64:	add    eax,edx
   0x08049f66:	mov    esi,eax
   0x08049f68:	lea    eax,[ebp-0x680]
   0x08049f6e:	mov    edx,DWORD PTR [ebp-0x24]
   0x08049f71:	shl    edx,0x3
   0x08049f74:	add    eax,edx
   0x08049f76:	mov    edx,eax
   0x08049f78:	lea    eax,[ebx-0x3ce4]
   0x08049f7e:	mov    DWORD PTR [ebp-0x64],eax
   0x08049f81:	mov    DWORD PTR [ebp-0x68],edx
   0x08049f84:	mov    DWORD PTR [ebp-0x6c],esi
   0x08049f87:	mov    DWORD PTR [ebp-0x70],ecx
   0x08049f8a:	push   eax
   0x08049f8b:	push   ebx
   0x08049f8c:	push   ecx
   0x08049f8d:	push   edx
   0x08049f8e:	push   esi
   0x08049f8f:	push   edi
   0x08049f90:	push   ebp
   0x08049f91:	nop
   0x08049f92:	mov    eax,DWORD PTR [ebp-0x64]
   0x08049f95:	mov    DWORD PTR [ebp-0x74],eax
   0x08049f98:	mov    eax,DWORD PTR [ebp-0x68]
   0x08049f9b:	mov    DWORD PTR [ebp-0x78],eax
   0x08049f9e:	mov    eax,DWORD PTR [ebp-0x6c]
   0x08049fa1:	mov    DWORD PTR [ebp-0x7c],eax
   0x08049fa4:	mov    eax,DWORD PTR [ebp-0x70]
   0x08049fa7:	mov    DWORD PTR [ebp-0x80],eax
   0x08049faa:	mov    eax,DWORD PTR [ebp-0x74]
   0x08049fad:	mov    esi,DWORD PTR [ebp-0x78]
   0x08049fb0:	mov    edx,DWORD PTR [ebp-0x7c]
   0x08049fb3:	mov    ecx,DWORD PTR [ebp-0x80]
   0x08049fb6:	sub    esp,0x8
   0x08049fb9:	xor    ebx,ebx
   0x08049fbb:	mov    bl,0x3
   0x08049fbd:	shl    ebx,1
   0x08049fbf:	shl    ebx,0x2
   0x08049fc2:	add    ebx,0x1a
   0x08049fc5:	inc    ebx
   0x08049fc6:	lea    edi,[esp+0x4]
   0x08049fca:	or     ebx,0x0
   0x08049fcd:	nop
   0x08049fce:	test   ebx,ebx
   0x08049fd0:	nop
   0x08049fd1:	mov    DWORD PTR [edi],ebx
   0x08049fd3:	mov    DWORD PTR [esp],eax
   0x08049fd6:	mov    edi,0x8049fdc
   0x08049fdb:	retf
   0x08049fdc:	dec    eax
   0x08049fdd:	sub    esp,0x8
   0x08049fe0:	dec    ebp
   0x08049fe1:	xor    ecx,ecx
   0x08049fe3:	inc    ecx
   0x08049fe4:	mov    cl,0x23
   0x08049fe6:	dec    ecx
   0x08049fe7:	shl    ecx,0x0
   0x08049fea:	dec    ecx
   0x08049feb:	add    ecx,0x0
   0x08049fee:	dec    esp
   0x08049fef:	lea    eax,[esp+0x4]
   0x08049ff3:	dec    ebp
   0x08049ff4:	mov    edx,ecx
   0x08049ff6:	dec    ecx
   0x08049ff7:	shl    edx,1
   0x08049ff9:	dec    ecx
   0x08049ffa:	shr    edx,1
   0x08049ffc:	dec    ebp
   0x08049ffd:	xor    ebx,ebx
   0x08049fff:	dec    ecx
   0x0804a000:	inc    ebx
   0x0804a002:	dec    ecx
   0x0804a003:	dec    ebx
   0x0804a005:	dec    ebp
   0x0804a006:	xchg   esp,esp
   0x0804a008:	inc    ebp
   0x0804a009:	mov    DWORD PTR [eax],ecx
   0x0804a00b:	mov    DWORD PTR [esp],0x804a013
   0x0804a012:	retf
   0x0804a013:	nop
   0x0804a014:	pop    ebp
   0x0804a015:	pop    edi
   0x0804a016:	pop    esi
   0x0804a017:	pop    edx
   0x0804a018:	pop    ecx
   0x0804a019:	pop    ebx
   0x0804a01a:	pop    eax
   0x0804a01b:	nop
   0x0804a01c:	nop
   0x0804a01d:	lea    eax,[ebp-0x680]
   0x0804a023:	mov    edx,DWORD PTR [ebp-0x24]
   0x0804a026:	shl    edx,0x3
   0x0804a029:	add    eax,edx
   0x0804a02b:	mov    ecx,eax
   0x0804a02d:	lea    eax,[ebp-0x680]
   0x0804a033:	mov    edx,DWORD PTR [ebp-0x24]
   0x0804a036:	shl    edx,0x3
   0x0804a039:	add    eax,edx
   0x0804a03b:	mov    esi,eax
   0x0804a03d:	lea    eax,[ebp-0x6c0]
   0x0804a043:	mov    edx,DWORD PTR [ebp-0x24]
   0x0804a046:	shl    edx,0x3
   0x0804a049:	add    eax,edx
   0x0804a04b:	mov    edx,eax
   0x0804a04d:	lea    eax,[ebx-0x3d0b]
   0x0804a053:	mov    DWORD PTR [ebp-0x44],eax
   0x0804a056:	mov    DWORD PTR [ebp-0x48],edx
   0x0804a059:	mov    DWORD PTR [ebp-0x4c],esi
   0x0804a05c:	mov    DWORD PTR [ebp-0x50],ecx
   0x0804a05f:	push   eax
   0x0804a060:	push   ebx
   0x0804a061:	push   ecx
   0x0804a062:	push   edx
   0x0804a063:	push   esi
   0x0804a064:	push   edi
   0x0804a065:	push   ebp
   0x0804a066:	nop
   0x0804a067:	mov    eax,DWORD PTR [ebp-0x44]
   0x0804a06a:	mov    DWORD PTR [ebp-0x54],eax
   0x0804a06d:	mov    eax,DWORD PTR [ebp-0x48]
   0x0804a070:	mov    DWORD PTR [ebp-0x58],eax
   0x0804a073:	mov    eax,DWORD PTR [ebp-0x4c]
   0x0804a076:	mov    DWORD PTR [ebp-0x5c],eax
   0x0804a079:	mov    eax,DWORD PTR [ebp-0x50]
   0x0804a07c:	mov    DWORD PTR [ebp-0x60],eax
   0x0804a07f:	mov    eax,DWORD PTR [ebp-0x54]
   0x0804a082:	mov    esi,DWORD PTR [ebp-0x58]
   0x0804a085:	mov    edx,DWORD PTR [ebp-0x5c]
   0x0804a088:	mov    ecx,DWORD PTR [ebp-0x60]
   0x0804a08b:	sub    esp,0x8
   0x0804a08e:	xor    ebx,ebx
   0x0804a090:	mov    bl,0x3
   0x0804a092:	shl    ebx,1
   0x0804a094:	shl    ebx,0x2
   0x0804a097:	add    ebx,0x1a
   0x0804a09a:	inc    ebx
   0x0804a09b:	lea    edi,[esp+0x4]
   0x0804a09f:	or     ebx,0x0
   0x0804a0a2:	nop
   0x0804a0a3:	test   ebx,ebx
   0x0804a0a5:	nop
   0x0804a0a6:	mov    DWORD PTR [edi],ebx
   0x0804a0a8:	mov    DWORD PTR [esp],eax
   0x0804a0ab:	mov    edi,0x804a0b1
   0x0804a0b0:	retf
   0x0804a0b1:	dec    eax
   0x0804a0b2:	sub    esp,0x8
   0x0804a0b5:	dec    ebp
   0x0804a0b6:	xor    ecx,ecx
   0x0804a0b8:	inc    ecx
   0x0804a0b9:	mov    cl,0x23
   0x0804a0bb:	dec    ecx
   0x0804a0bc:	shl    ecx,0x0
   0x0804a0bf:	dec    ecx
   0x0804a0c0:	add    ecx,0x0
   0x0804a0c3:	dec    esp
   0x0804a0c4:	lea    eax,[esp+0x4]
   0x0804a0c8:	dec    ebp
   0x0804a0c9:	mov    edx,ecx
   0x0804a0cb:	dec    ecx
   0x0804a0cc:	shl    edx,1
   0x0804a0ce:	dec    ecx
   0x0804a0cf:	shr    edx,1
   0x0804a0d1:	dec    ebp
   0x0804a0d2:	xor    ebx,ebx
   0x0804a0d4:	dec    ecx
   0x0804a0d5:	inc    ebx
   0x0804a0d7:	dec    ecx
   0x0804a0d8:	dec    ebx
   0x0804a0da:	dec    ebp
   0x0804a0db:	xchg   esp,esp
   0x0804a0dd:	inc    ebp
   0x0804a0de:	mov    DWORD PTR [eax],ecx
   0x0804a0e0:	mov    DWORD PTR [esp],0x804a0e8
   0x0804a0e7:	retf
   0x0804a0e8:	nop
   0x0804a0e9:	pop    ebp
   0x0804a0ea:	pop    edi
   0x0804a0eb:	pop    esi
   0x0804a0ec:	pop    edx
   0x0804a0ed:	pop    ecx
   0x0804a0ee:	pop    ebx
   0x0804a0ef:	pop    eax
   0x0804a0f0:	nop
   0x0804a0f1:	nop
   0x0804a0f2:	add    DWORD PTR [ebp-0x24],0x1
   0x0804a0f6:	cmp    DWORD PTR [ebp-0x24],0x7
   0x0804a0fa:	jle    0x8049c05
   0x0804a100:	mov    DWORD PTR [ebp-0x818],0xaaaaaaaa
   0x0804a10a:	mov    DWORD PTR [ebp-0x814],0xaaaaaaaa
   0x0804a114:	mov    eax,DWORD PTR [ebp-0x818]
   0x0804a11a:	mov    edx,DWORD PTR [ebp-0x814]
   0x0804a120:	not    eax
   0x0804a122:	not    edx
   0x0804a124:	mov    DWORD PTR [ebp-0x40],eax
   0x0804a127:	mov    DWORD PTR [ebp-0x3c],edx
   0x0804a12a:	mov    DWORD PTR [ebp-0x28],0x0
   0x0804a131:	jmp    0x804a59d
   0x0804a136:	mov    DWORD PTR [ebp-0x820],0x0
   0x0804a140:	mov    DWORD PTR [ebp-0x81c],0x0
   0x0804a14a:	mov    DWORD PTR [ebp-0x828],0x0
   0x0804a154:	mov    DWORD PTR [ebp-0x824],0x0
   0x0804a15e:	mov    DWORD PTR [ebp-0x830],0x0
   0x0804a168:	mov    DWORD PTR [ebp-0x82c],0x0
   0x0804a172:	mov    DWORD PTR [ebp-0x838],0x0
   0x0804a17c:	mov    DWORD PTR [ebp-0x834],0x0
   0x0804a186:	lea    eax,[ebp-0x818]
   0x0804a18c:	lea    edx,[ebp-0x6c0]
   0x0804a192:	mov    ecx,DWORD PTR [ebp-0x28]
   0x0804a195:	shl    ecx,0x3
   0x0804a198:	add    edx,ecx
   0x0804a19a:	mov    esi,edx
   0x0804a19c:	lea    edx,[ebp-0x820]
   0x0804a1a2:	lea    ecx,[ebx-0x3d8d]
   0x0804a1a8:	mov    DWORD PTR [ebp-0x144],ecx
   0x0804a1ae:	mov    DWORD PTR [ebp-0x148],edx
   0x0804a1b4:	mov    DWORD PTR [ebp-0x14c],esi
   0x0804a1ba:	mov    DWORD PTR [ebp-0x150],eax
   0x0804a1c0:	push   eax
   0x0804a1c1:	push   ebx
   0x0804a1c2:	push   ecx
   0x0804a1c3:	push   edx
   0x0804a1c4:	push   esi
   0x0804a1c5:	push   edi
   0x0804a1c6:	push   ebp
   0x0804a1c7:	nop
   0x0804a1c8:	mov    eax,DWORD PTR [ebp-0x144]
   0x0804a1ce:	mov    DWORD PTR [ebp-0x154],eax
   0x0804a1d4:	mov    eax,DWORD PTR [ebp-0x148]
   0x0804a1da:	mov    DWORD PTR [ebp-0x158],eax
   0x0804a1e0:	mov    eax,DWORD PTR [ebp-0x14c]
   0x0804a1e6:	mov    DWORD PTR [ebp-0x15c],eax
   0x0804a1ec:	mov    eax,DWORD PTR [ebp-0x150]
   0x0804a1f2:	mov    DWORD PTR [ebp-0x160],eax
   0x0804a1f8:	mov    eax,DWORD PTR [ebp-0x154]
   0x0804a1fe:	mov    esi,DWORD PTR [ebp-0x158]
   0x0804a204:	mov    edx,DWORD PTR [ebp-0x15c]
   0x0804a20a:	mov    ecx,DWORD PTR [ebp-0x160]
   0x0804a210:	sub    esp,0x8
   0x0804a213:	xor    ebx,ebx
   0x0804a215:	mov    bl,0x3
   0x0804a217:	shl    ebx,1
   0x0804a219:	shl    ebx,0x2
   0x0804a21c:	add    ebx,0x1a
   0x0804a21f:	inc    ebx
   0x0804a220:	lea    edi,[esp+0x4]
   0x0804a224:	or     ebx,0x0
   0x0804a227:	nop
   0x0804a228:	test   ebx,ebx
   0x0804a22a:	nop
   0x0804a22b:	mov    DWORD PTR [edi],ebx
   0x0804a22d:	mov    DWORD PTR [esp],eax
   0x0804a230:	mov    edi,0x804a236
   0x0804a235:	retf
   0x0804a236:	dec    eax
   0x0804a237:	sub    esp,0x8
   0x0804a23a:	dec    ebp
   0x0804a23b:	xor    ecx,ecx
   0x0804a23d:	inc    ecx
   0x0804a23e:	mov    cl,0x23
   0x0804a240:	dec    ecx
   0x0804a241:	shl    ecx,0x0
   0x0804a244:	dec    ecx
   0x0804a245:	add    ecx,0x0
   0x0804a248:	dec    esp
   0x0804a249:	lea    eax,[esp+0x4]
   0x0804a24d:	dec    ebp
   0x0804a24e:	mov    edx,ecx
   0x0804a250:	dec    ecx
   0x0804a251:	shl    edx,1
   0x0804a253:	dec    ecx
   0x0804a254:	shr    edx,1
   0x0804a256:	dec    ebp
   0x0804a257:	xor    ebx,ebx
   0x0804a259:	dec    ecx
   0x0804a25a:	inc    ebx
   0x0804a25c:	dec    ecx
   0x0804a25d:	dec    ebx
   0x0804a25f:	dec    ebp
   0x0804a260:	xchg   esp,esp
   0x0804a262:	inc    ebp
   0x0804a263:	mov    DWORD PTR [eax],ecx
   0x0804a265:	mov    DWORD PTR [esp],0x804a26d
   0x0804a26c:	retf
   0x0804a26d:	nop
   0x0804a26e:	pop    ebp
   0x0804a26f:	pop    edi
   0x0804a270:	pop    esi
   0x0804a271:	pop    edx
   0x0804a272:	pop    ecx
   0x0804a273:	pop    ebx
   0x0804a274:	pop    eax
   0x0804a275:	nop
   0x0804a276:	nop
   0x0804a277:	mov    eax,DWORD PTR [ebp-0x28]
   0x0804a27a:	add    eax,0x1
   0x0804a27d:	mov    edx,DWORD PTR [ebp+eax*8-0x6bc]
   0x0804a284:	mov    eax,DWORD PTR [ebp+eax*8-0x6c0]
   0x0804a28b:	and    eax,DWORD PTR [ebp-0x40]
   0x0804a28e:	and    edx,DWORD PTR [ebp-0x3c]
   0x0804a291:	mov    DWORD PTR [ebp-0x828],eax
   0x0804a297:	mov    DWORD PTR [ebp-0x824],edx
   0x0804a29d:	lea    eax,[ebp-0x828]
   0x0804a2a3:	lea    edx,[ebp-0x820]
   0x0804a2a9:	lea    ecx,[ebp-0x6c0]
   0x0804a2af:	mov    esi,DWORD PTR [ebp-0x28]
   0x0804a2b2:	shl    esi,0x3
   0x0804a2b5:	add    ecx,esi
   0x0804a2b7:	mov    esi,ecx
   0x0804a2b9:	lea    ecx,[ebx-0x3d4c]
   0x0804a2bf:	mov    DWORD PTR [ebp-0x124],ecx
   0x0804a2c5:	mov    DWORD PTR [ebp-0x128],esi
   0x0804a2cb:	mov    DWORD PTR [ebp-0x12c],edx
   0x0804a2d1:	mov    DWORD PTR [ebp-0x130],eax
   0x0804a2d7:	push   eax
   0x0804a2d8:	push   ebx
   0x0804a2d9:	push   ecx
   0x0804a2da:	push   edx
   0x0804a2db:	push   esi
   0x0804a2dc:	push   edi
   0x0804a2dd:	push   ebp
   0x0804a2de:	nop
   0x0804a2df:	mov    eax,DWORD PTR [ebp-0x124]
   0x0804a2e5:	mov    DWORD PTR [ebp-0x134],eax
   0x0804a2eb:	mov    eax,DWORD PTR [ebp-0x128]
   0x0804a2f1:	mov    DWORD PTR [ebp-0x138],eax
   0x0804a2f7:	mov    eax,DWORD PTR [ebp-0x12c]
   0x0804a2fd:	mov    DWORD PTR [ebp-0x13c],eax
   0x0804a303:	mov    eax,DWORD PTR [ebp-0x130]
   0x0804a309:	mov    DWORD PTR [ebp-0x140],eax
   0x0804a30f:	mov    eax,DWORD PTR [ebp-0x134]
   0x0804a315:	mov    esi,DWORD PTR [ebp-0x138]
   0x0804a31b:	mov    edx,DWORD PTR [ebp-0x13c]
   0x0804a321:	mov    ecx,DWORD PTR [ebp-0x140]
   0x0804a327:	sub    esp,0x8
   0x0804a32a:	xor    ebx,ebx
   0x0804a32c:	mov    bl,0x3
   0x0804a32e:	shl    ebx,1
   0x0804a330:	shl    ebx,0x2
   0x0804a333:	add    ebx,0x1a
   0x0804a336:	inc    ebx
   0x0804a337:	lea    edi,[esp+0x4]
   0x0804a33b:	or     ebx,0x0
   0x0804a33e:	nop
   0x0804a33f:	test   ebx,ebx
   0x0804a341:	nop
   0x0804a342:	mov    DWORD PTR [edi],ebx
   0x0804a344:	mov    DWORD PTR [esp],eax
   0x0804a347:	mov    edi,0x804a34d
   0x0804a34c:	retf
   0x0804a34d:	dec    eax
   0x0804a34e:	sub    esp,0x8
   0x0804a351:	dec    ebp
   0x0804a352:	xor    ecx,ecx
   0x0804a354:	inc    ecx
   0x0804a355:	mov    cl,0x23
   0x0804a357:	dec    ecx
   0x0804a358:	shl    ecx,0x0
   0x0804a35b:	dec    ecx
   0x0804a35c:	add    ecx,0x0
   0x0804a35f:	dec    esp
   0x0804a360:	lea    eax,[esp+0x4]
   0x0804a364:	dec    ebp
   0x0804a365:	mov    edx,ecx
   0x0804a367:	dec    ecx
   0x0804a368:	shl    edx,1
   0x0804a36a:	dec    ecx
   0x0804a36b:	shr    edx,1
   0x0804a36d:	dec    ebp
   0x0804a36e:	xor    ebx,ebx
   0x0804a370:	dec    ecx
   0x0804a371:	inc    ebx
   0x0804a373:	dec    ecx
   0x0804a374:	dec    ebx
   0x0804a376:	dec    ebp
   0x0804a377:	xchg   esp,esp
   0x0804a379:	inc    ebp
   0x0804a37a:	mov    DWORD PTR [eax],ecx
   0x0804a37c:	mov    DWORD PTR [esp],0x804a384
   0x0804a383:	retf
   0x0804a384:	nop
   0x0804a385:	pop    ebp
   0x0804a386:	pop    edi
   0x0804a387:	pop    esi
   0x0804a388:	pop    edx
   0x0804a389:	pop    ecx
   0x0804a38a:	pop    ebx
   0x0804a38b:	pop    eax
   0x0804a38c:	nop
   0x0804a38d:	nop
   0x0804a38e:	mov    eax,DWORD PTR [ebp-0x28]
   0x0804a391:	mov    edx,DWORD PTR [ebp+eax*8-0x67c]
   0x0804a398:	mov    eax,DWORD PTR [ebp+eax*8-0x680]
   0x0804a39f:	and    eax,DWORD PTR [ebp-0x40]
   0x0804a3a2:	and    edx,DWORD PTR [ebp-0x3c]
   0x0804a3a5:	mov    DWORD PTR [ebp-0x830],eax
   0x0804a3ab:	mov    DWORD PTR [ebp-0x82c],edx
   0x0804a3b1:	lea    eax,[ebp-0x818]
   0x0804a3b7:	mov    edx,DWORD PTR [ebp-0x28]
   0x0804a3ba:	lea    ecx,[edx+0x1]
   0x0804a3bd:	lea    edx,[ebp-0x680]
   0x0804a3c3:	shl    ecx,0x3
   0x0804a3c6:	add    edx,ecx
   0x0804a3c8:	mov    esi,edx
   0x0804a3ca:	lea    edx,[ebp-0x838]
   0x0804a3d0:	lea    ecx,[ebx-0x3d8d]
   0x0804a3d6:	mov    DWORD PTR [ebp-0x104],ecx
   0x0804a3dc:	mov    DWORD PTR [ebp-0x108],edx
   0x0804a3e2:	mov    DWORD PTR [ebp-0x10c],esi
   0x0804a3e8:	mov    DWORD PTR [ebp-0x110],eax
   0x0804a3ee:	push   eax
   0x0804a3ef:	push   ebx
   0x0804a3f0:	push   ecx
   0x0804a3f1:	push   edx
   0x0804a3f2:	push   esi
   0x0804a3f3:	push   edi
   0x0804a3f4:	push   ebp
   0x0804a3f5:	nop
   0x0804a3f6:	mov    eax,DWORD PTR [ebp-0x104]
   0x0804a3fc:	mov    DWORD PTR [ebp-0x114],eax
   0x0804a402:	mov    eax,DWORD PTR [ebp-0x108]
   0x0804a408:	mov    DWORD PTR [ebp-0x118],eax
   0x0804a40e:	mov    eax,DWORD PTR [ebp-0x10c]
   0x0804a414:	mov    DWORD PTR [ebp-0x11c],eax
   0x0804a41a:	mov    eax,DWORD PTR [ebp-0x110]
   0x0804a420:	mov    DWORD PTR [ebp-0x120],eax
   0x0804a426:	mov    eax,DWORD PTR [ebp-0x114]
   0x0804a42c:	mov    esi,DWORD PTR [ebp-0x118]
   0x0804a432:	mov    edx,DWORD PTR [ebp-0x11c]
   0x0804a438:	mov    ecx,DWORD PTR [ebp-0x120]
   0x0804a43e:	sub    esp,0x8
   0x0804a441:	xor    ebx,ebx
   0x0804a443:	mov    bl,0x3
   0x0804a445:	shl    ebx,1
   0x0804a447:	shl    ebx,0x2
   0x0804a44a:	add    ebx,0x1a
   0x0804a44d:	inc    ebx
   0x0804a44e:	lea    edi,[esp+0x4]
   0x0804a452:	or     ebx,0x0
   0x0804a455:	nop
   0x0804a456:	test   ebx,ebx
   0x0804a458:	nop
   0x0804a459:	mov    DWORD PTR [edi],ebx
   0x0804a45b:	mov    DWORD PTR [esp],eax
   0x0804a45e:	mov    edi,0x804a464
   0x0804a463:	retf
   0x0804a464:	dec    eax
   0x0804a465:	sub    esp,0x8
   0x0804a468:	dec    ebp
   0x0804a469:	xor    ecx,ecx
   0x0804a46b:	inc    ecx
   0x0804a46c:	mov    cl,0x23
   0x0804a46e:	dec    ecx
   0x0804a46f:	shl    ecx,0x0
   0x0804a472:	dec    ecx
   0x0804a473:	add    ecx,0x0
   0x0804a476:	dec    esp
   0x0804a477:	lea    eax,[esp+0x4]
   0x0804a47b:	dec    ebp
   0x0804a47c:	mov    edx,ecx
   0x0804a47e:	dec    ecx
   0x0804a47f:	shl    edx,1
   0x0804a481:	dec    ecx
   0x0804a482:	shr    edx,1
   0x0804a484:	dec    ebp
   0x0804a485:	xor    ebx,ebx
   0x0804a487:	dec    ecx
   0x0804a488:	inc    ebx
   0x0804a48a:	dec    ecx
   0x0804a48b:	dec    ebx
   0x0804a48d:	dec    ebp
   0x0804a48e:	xchg   esp,esp
   0x0804a490:	inc    ebp
   0x0804a491:	mov    DWORD PTR [eax],ecx
   0x0804a493:	mov    DWORD PTR [esp],0x804a49b
   0x0804a49a:	retf
   0x0804a49b:	nop
   0x0804a49c:	pop    ebp
   0x0804a49d:	pop    edi
   0x0804a49e:	pop    esi
   0x0804a49f:	pop    edx
   0x0804a4a0:	pop    ecx
   0x0804a4a1:	pop    ebx
   0x0804a4a2:	pop    eax
   0x0804a4a3:	nop
   0x0804a4a4:	nop
   0x0804a4a5:	lea    eax,[ebp-0x838]
   0x0804a4ab:	lea    edx,[ebp-0x830]
   0x0804a4b1:	mov    ecx,DWORD PTR [ebp-0x28]
   0x0804a4b4:	lea    esi,[ecx+0x1]
   0x0804a4b7:	lea    ecx,[ebp-0x6c0]
   0x0804a4bd:	shl    esi,0x3
   0x0804a4c0:	add    ecx,esi
   0x0804a4c2:	mov    esi,ecx
   0x0804a4c4:	lea    ecx,[ebx-0x3d4c]
   0x0804a4ca:	mov    DWORD PTR [ebp-0xe4],ecx
   0x0804a4d0:	mov    DWORD PTR [ebp-0xe8],esi
   0x0804a4d6:	mov    DWORD PTR [ebp-0xec],edx
   0x0804a4dc:	mov    DWORD PTR [ebp-0xf0],eax
   0x0804a4e2:	push   eax
   0x0804a4e3:	push   ebx
   0x0804a4e4:	push   ecx
   0x0804a4e5:	push   edx
   0x0804a4e6:	push   esi
   0x0804a4e7:	push   edi
   0x0804a4e8:	push   ebp
   0x0804a4e9:	nop
   0x0804a4ea:	mov    eax,DWORD PTR [ebp-0xe4]
   0x0804a4f0:	mov    DWORD PTR [ebp-0xf4],eax
   0x0804a4f6:	mov    eax,DWORD PTR [ebp-0xe8]
   0x0804a4fc:	mov    DWORD PTR [ebp-0xf8],eax
   0x0804a502:	mov    eax,DWORD PTR [ebp-0xec]
   0x0804a508:	mov    DWORD PTR [ebp-0xfc],eax
   0x0804a50e:	mov    eax,DWORD PTR [ebp-0xf0]
   0x0804a514:	mov    DWORD PTR [ebp-0x100],eax
   0x0804a51a:	mov    eax,DWORD PTR [ebp-0xf4]
   0x0804a520:	mov    esi,DWORD PTR [ebp-0xf8]
   0x0804a526:	mov    edx,DWORD PTR [ebp-0xfc]
   0x0804a52c:	mov    ecx,DWORD PTR [ebp-0x100]
   0x0804a532:	sub    esp,0x8
   0x0804a535:	xor    ebx,ebx
   0x0804a537:	mov    bl,0x3
   0x0804a539:	shl    ebx,1
   0x0804a53b:	shl    ebx,0x2
   0x0804a53e:	add    ebx,0x1a
   0x0804a541:	inc    ebx
   0x0804a542:	lea    edi,[esp+0x4]
   0x0804a546:	or     ebx,0x0
   0x0804a549:	nop
   0x0804a54a:	test   ebx,ebx
   0x0804a54c:	nop
   0x0804a54d:	mov    DWORD PTR [edi],ebx
   0x0804a54f:	mov    DWORD PTR [esp],eax
   0x0804a552:	mov    edi,0x804a558
   0x0804a557:	retf
   0x0804a558:	dec    eax
   0x0804a559:	sub    esp,0x8
   0x0804a55c:	dec    ebp
   0x0804a55d:	xor    ecx,ecx
   0x0804a55f:	inc    ecx
   0x0804a560:	mov    cl,0x23
   0x0804a562:	dec    ecx
   0x0804a563:	shl    ecx,0x0
   0x0804a566:	dec    ecx
   0x0804a567:	add    ecx,0x0
   0x0804a56a:	dec    esp
   0x0804a56b:	lea    eax,[esp+0x4]
   0x0804a56f:	dec    ebp
   0x0804a570:	mov    edx,ecx
   0x0804a572:	dec    ecx
   0x0804a573:	shl    edx,1
   0x0804a575:	dec    ecx
   0x0804a576:	shr    edx,1
   0x0804a578:	dec    ebp
   0x0804a579:	xor    ebx,ebx
   0x0804a57b:	dec    ecx
   0x0804a57c:	inc    ebx
   0x0804a57e:	dec    ecx
   0x0804a57f:	dec    ebx
   0x0804a581:	dec    ebp
   0x0804a582:	xchg   esp,esp
   0x0804a584:	inc    ebp
   0x0804a585:	mov    DWORD PTR [eax],ecx
   0x0804a587:	mov    DWORD PTR [esp],0x804a58f
   0x0804a58e:	retf
   0x0804a58f:	nop
   0x0804a590:	pop    ebp
   0x0804a591:	pop    edi
   0x0804a592:	pop    esi
   0x0804a593:	pop    edx
   0x0804a594:	pop    ecx
   0x0804a595:	pop    ebx
   0x0804a596:	pop    eax
   0x0804a597:	nop
   0x0804a598:	nop
   0x0804a599:	add    DWORD PTR [ebp-0x28],0x2
   0x0804a59d:	cmp    DWORD PTR [ebp-0x28],0x7
   0x0804a5a1:	jle    0x804a136
   0x0804a5a7:	mov    DWORD PTR [ebp-0x2c],0x0
   0x0804a5ae:	jmp    0x804ad6d
   0x0804a5b3:	lea    eax,[ebp-0x380]
   0x0804a5b9:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a5bc:	shl    edx,0x3
   0x0804a5bf:	add    eax,edx
   0x0804a5c1:	mov    ecx,eax
   0x0804a5c3:	lea    eax,[ebp-0x6c0]
   0x0804a5c9:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a5cc:	shl    edx,0x3
   0x0804a5cf:	add    eax,edx
   0x0804a5d1:	mov    esi,eax
   0x0804a5d3:	lea    eax,[ebp-0x7c0]
   0x0804a5d9:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a5dc:	shl    edx,0x3
   0x0804a5df:	add    eax,edx
   0x0804a5e1:	mov    edx,eax
   0x0804a5e3:	lea    eax,[ebx-0x3e6e]
   0x0804a5e9:	mov    DWORD PTR [ebp-0x224],eax
   0x0804a5ef:	mov    DWORD PTR [ebp-0x228],edx
   0x0804a5f5:	mov    DWORD PTR [ebp-0x22c],esi
   0x0804a5fb:	mov    DWORD PTR [ebp-0x230],ecx
   0x0804a601:	push   eax
   0x0804a602:	push   ebx
   0x0804a603:	push   ecx
   0x0804a604:	push   edx
   0x0804a605:	push   esi
   0x0804a606:	push   edi
   0x0804a607:	push   ebp
   0x0804a608:	nop
   0x0804a609:	mov    eax,DWORD PTR [ebp-0x224]
   0x0804a60f:	mov    DWORD PTR [ebp-0x234],eax
   0x0804a615:	mov    eax,DWORD PTR [ebp-0x228]
   0x0804a61b:	mov    DWORD PTR [ebp-0x238],eax
   0x0804a621:	mov    eax,DWORD PTR [ebp-0x22c]
   0x0804a627:	mov    DWORD PTR [ebp-0x23c],eax
   0x0804a62d:	mov    eax,DWORD PTR [ebp-0x230]
   0x0804a633:	mov    DWORD PTR [ebp-0x240],eax
   0x0804a639:	mov    eax,DWORD PTR [ebp-0x234]
   0x0804a63f:	mov    esi,DWORD PTR [ebp-0x238]
   0x0804a645:	mov    edx,DWORD PTR [ebp-0x23c]
   0x0804a64b:	mov    ecx,DWORD PTR [ebp-0x240]
   0x0804a651:	sub    esp,0x8
   0x0804a654:	xor    ebx,ebx
   0x0804a656:	mov    bl,0x3
   0x0804a658:	shl    ebx,1
   0x0804a65a:	shl    ebx,0x2
   0x0804a65d:	add    ebx,0x1a
   0x0804a660:	inc    ebx
   0x0804a661:	lea    edi,[esp+0x4]
   0x0804a665:	or     ebx,0x0
   0x0804a668:	nop
   0x0804a669:	test   ebx,ebx
   0x0804a66b:	nop
   0x0804a66c:	mov    DWORD PTR [edi],ebx
   0x0804a66e:	mov    DWORD PTR [esp],eax
   0x0804a671:	mov    edi,0x804a677
   0x0804a676:	retf
   0x0804a677:	dec    eax
   0x0804a678:	sub    esp,0x8
   0x0804a67b:	dec    ebp
   0x0804a67c:	xor    ecx,ecx
   0x0804a67e:	inc    ecx
   0x0804a67f:	mov    cl,0x23
   0x0804a681:	dec    ecx
   0x0804a682:	shl    ecx,0x0
   0x0804a685:	dec    ecx
   0x0804a686:	add    ecx,0x0
   0x0804a689:	dec    esp
   0x0804a68a:	lea    eax,[esp+0x4]
   0x0804a68e:	dec    ebp
   0x0804a68f:	mov    edx,ecx
   0x0804a691:	dec    ecx
   0x0804a692:	shl    edx,1
   0x0804a694:	dec    ecx
   0x0804a695:	shr    edx,1
   0x0804a697:	dec    ebp
   0x0804a698:	xor    ebx,ebx
   0x0804a69a:	dec    ecx
   0x0804a69b:	inc    ebx
   0x0804a69d:	dec    ecx
   0x0804a69e:	dec    ebx
   0x0804a6a0:	dec    ebp
   0x0804a6a1:	xchg   esp,esp
   0x0804a6a3:	inc    ebp
   0x0804a6a4:	mov    DWORD PTR [eax],ecx
   0x0804a6a6:	mov    DWORD PTR [esp],0x804a6ae
   0x0804a6ad:	retf
   0x0804a6ae:	nop
   0x0804a6af:	pop    ebp
   0x0804a6b0:	pop    edi
   0x0804a6b1:	pop    esi
   0x0804a6b2:	pop    edx
   0x0804a6b3:	pop    ecx
   0x0804a6b4:	pop    ebx
   0x0804a6b5:	pop    eax
   0x0804a6b6:	nop
   0x0804a6b7:	nop
   0x0804a6b8:	lea    eax,[ebp-0x480]
   0x0804a6be:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a6c1:	shl    edx,0x3
   0x0804a6c4:	add    eax,edx
   0x0804a6c6:	mov    ecx,eax
   0x0804a6c8:	lea    eax,[ebp-0x7c0]
   0x0804a6ce:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a6d1:	shl    edx,0x3
   0x0804a6d4:	add    eax,edx
   0x0804a6d6:	mov    esi,eax
   0x0804a6d8:	lea    eax,[ebp-0x700]
   0x0804a6de:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a6e1:	shl    edx,0x3
   0x0804a6e4:	add    eax,edx
   0x0804a6e6:	mov    edx,eax
   0x0804a6e8:	lea    eax,[ebx-0x3bca]
   0x0804a6ee:	mov    DWORD PTR [ebp-0x204],eax
   0x0804a6f4:	mov    DWORD PTR [ebp-0x208],edx
   0x0804a6fa:	mov    DWORD PTR [ebp-0x20c],esi
   0x0804a700:	mov    DWORD PTR [ebp-0x210],ecx
   0x0804a706:	push   eax
   0x0804a707:	push   ebx
   0x0804a708:	push   ecx
   0x0804a709:	push   edx
   0x0804a70a:	push   esi
   0x0804a70b:	push   edi
   0x0804a70c:	push   ebp
   0x0804a70d:	nop
   0x0804a70e:	mov    eax,DWORD PTR [ebp-0x204]
   0x0804a714:	mov    DWORD PTR [ebp-0x214],eax
   0x0804a71a:	mov    eax,DWORD PTR [ebp-0x208]
   0x0804a720:	mov    DWORD PTR [ebp-0x218],eax
   0x0804a726:	mov    eax,DWORD PTR [ebp-0x20c]
   0x0804a72c:	mov    DWORD PTR [ebp-0x21c],eax
   0x0804a732:	mov    eax,DWORD PTR [ebp-0x210]
   0x0804a738:	mov    DWORD PTR [ebp-0x220],eax
   0x0804a73e:	mov    eax,DWORD PTR [ebp-0x214]
   0x0804a744:	mov    esi,DWORD PTR [ebp-0x218]
   0x0804a74a:	mov    edx,DWORD PTR [ebp-0x21c]
   0x0804a750:	mov    ecx,DWORD PTR [ebp-0x220]
   0x0804a756:	sub    esp,0x8
   0x0804a759:	xor    ebx,ebx
   0x0804a75b:	mov    bl,0x3
   0x0804a75d:	shl    ebx,1
   0x0804a75f:	shl    ebx,0x2
   0x0804a762:	add    ebx,0x1a
   0x0804a765:	inc    ebx
   0x0804a766:	lea    edi,[esp+0x4]
   0x0804a76a:	or     ebx,0x0
   0x0804a76d:	nop
   0x0804a76e:	test   ebx,ebx
   0x0804a770:	nop
   0x0804a771:	mov    DWORD PTR [edi],ebx
   0x0804a773:	mov    DWORD PTR [esp],eax
   0x0804a776:	mov    edi,0x804a77c
   0x0804a77b:	retf
   0x0804a77c:	dec    eax
   0x0804a77d:	sub    esp,0x8
   0x0804a780:	dec    ebp
   0x0804a781:	xor    ecx,ecx
   0x0804a783:	inc    ecx
   0x0804a784:	mov    cl,0x23
   0x0804a786:	dec    ecx
   0x0804a787:	shl    ecx,0x0
   0x0804a78a:	dec    ecx
   0x0804a78b:	add    ecx,0x0
   0x0804a78e:	dec    esp
   0x0804a78f:	lea    eax,[esp+0x4]
   0x0804a793:	dec    ebp
   0x0804a794:	mov    edx,ecx
   0x0804a796:	dec    ecx
   0x0804a797:	shl    edx,1
   0x0804a799:	dec    ecx
   0x0804a79a:	shr    edx,1
   0x0804a79c:	dec    ebp
   0x0804a79d:	xor    ebx,ebx
   0x0804a79f:	dec    ecx
   0x0804a7a0:	inc    ebx
   0x0804a7a2:	dec    ecx
   0x0804a7a3:	dec    ebx
   0x0804a7a5:	dec    ebp
   0x0804a7a6:	xchg   esp,esp
   0x0804a7a8:	inc    ebp
   0x0804a7a9:	mov    DWORD PTR [eax],ecx
   0x0804a7ab:	mov    DWORD PTR [esp],0x804a7b3
   0x0804a7b2:	retf
   0x0804a7b3:	nop
   0x0804a7b4:	pop    ebp
   0x0804a7b5:	pop    edi
   0x0804a7b6:	pop    esi
   0x0804a7b7:	pop    edx
   0x0804a7b8:	pop    ecx
   0x0804a7b9:	pop    ebx
   0x0804a7ba:	pop    eax
   0x0804a7bb:	nop
   0x0804a7bc:	nop
   0x0804a7bd:	lea    eax,[ebp-0x480]
   0x0804a7c3:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a7c6:	shl    edx,0x3
   0x0804a7c9:	add    eax,edx
   0x0804a7cb:	mov    ecx,eax
   0x0804a7cd:	lea    eax,[ebp-0x7c0]
   0x0804a7d3:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a7d6:	shl    edx,0x3
   0x0804a7d9:	add    eax,edx
   0x0804a7db:	mov    esi,eax
   0x0804a7dd:	lea    eax,[ebp-0x740]
   0x0804a7e3:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a7e6:	shl    edx,0x3
   0x0804a7e9:	add    eax,edx
   0x0804a7eb:	mov    edx,eax
   0x0804a7ed:	lea    eax,[ebx-0x3b8a]
   0x0804a7f3:	mov    DWORD PTR [ebp-0x1e4],eax
   0x0804a7f9:	mov    DWORD PTR [ebp-0x1e8],edx
   0x0804a7ff:	mov    DWORD PTR [ebp-0x1ec],esi
   0x0804a805:	mov    DWORD PTR [ebp-0x1f0],ecx
   0x0804a80b:	push   eax
   0x0804a80c:	push   ebx
   0x0804a80d:	push   ecx
   0x0804a80e:	push   edx
   0x0804a80f:	push   esi
   0x0804a810:	push   edi
   0x0804a811:	push   ebp
   0x0804a812:	nop
   0x0804a813:	mov    eax,DWORD PTR [ebp-0x1e4]
   0x0804a819:	mov    DWORD PTR [ebp-0x1f4],eax
   0x0804a81f:	mov    eax,DWORD PTR [ebp-0x1e8]
   0x0804a825:	mov    DWORD PTR [ebp-0x1f8],eax
   0x0804a82b:	mov    eax,DWORD PTR [ebp-0x1ec]
   0x0804a831:	mov    DWORD PTR [ebp-0x1fc],eax
   0x0804a837:	mov    eax,DWORD PTR [ebp-0x1f0]
   0x0804a83d:	mov    DWORD PTR [ebp-0x200],eax
   0x0804a843:	mov    eax,DWORD PTR [ebp-0x1f4]
   0x0804a849:	mov    esi,DWORD PTR [ebp-0x1f8]
   0x0804a84f:	mov    edx,DWORD PTR [ebp-0x1fc]
   0x0804a855:	mov    ecx,DWORD PTR [ebp-0x200]
   0x0804a85b:	sub    esp,0x8
   0x0804a85e:	xor    ebx,ebx
   0x0804a860:	mov    bl,0x3
   0x0804a862:	shl    ebx,1
   0x0804a864:	shl    ebx,0x2
   0x0804a867:	add    ebx,0x1a
   0x0804a86a:	inc    ebx
   0x0804a86b:	lea    edi,[esp+0x4]
   0x0804a86f:	or     ebx,0x0
   0x0804a872:	nop
   0x0804a873:	test   ebx,ebx
   0x0804a875:	nop
   0x0804a876:	mov    DWORD PTR [edi],ebx
   0x0804a878:	mov    DWORD PTR [esp],eax
   0x0804a87b:	mov    edi,0x804a881
   0x0804a880:	retf
   0x0804a881:	dec    eax
   0x0804a882:	sub    esp,0x8
   0x0804a885:	dec    ebp
   0x0804a886:	xor    ecx,ecx
   0x0804a888:	inc    ecx
   0x0804a889:	mov    cl,0x23
   0x0804a88b:	dec    ecx
   0x0804a88c:	shl    ecx,0x0
   0x0804a88f:	dec    ecx
   0x0804a890:	add    ecx,0x0
   0x0804a893:	dec    esp
   0x0804a894:	lea    eax,[esp+0x4]
   0x0804a898:	dec    ebp
   0x0804a899:	mov    edx,ecx
   0x0804a89b:	dec    ecx
   0x0804a89c:	shl    edx,1
   0x0804a89e:	dec    ecx
   0x0804a89f:	shr    edx,1
   0x0804a8a1:	dec    ebp
   0x0804a8a2:	xor    ebx,ebx
   0x0804a8a4:	dec    ecx
   0x0804a8a5:	inc    ebx
   0x0804a8a7:	dec    ecx
   0x0804a8a8:	dec    ebx
   0x0804a8aa:	dec    ebp
   0x0804a8ab:	xchg   esp,esp
   0x0804a8ad:	inc    ebp
   0x0804a8ae:	mov    DWORD PTR [eax],ecx
   0x0804a8b0:	mov    DWORD PTR [esp],0x804a8b8
   0x0804a8b7:	retf
   0x0804a8b8:	nop
   0x0804a8b9:	pop    ebp
   0x0804a8ba:	pop    edi
   0x0804a8bb:	pop    esi
   0x0804a8bc:	pop    edx
   0x0804a8bd:	pop    ecx
   0x0804a8be:	pop    ebx
   0x0804a8bf:	pop    eax
   0x0804a8c0:	nop
   0x0804a8c1:	nop
   0x0804a8c2:	lea    eax,[ebp-0x480]
   0x0804a8c8:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a8cb:	shl    edx,0x3
   0x0804a8ce:	add    eax,edx
   0x0804a8d0:	mov    ecx,eax
   0x0804a8d2:	lea    eax,[ebp-0x700]
   0x0804a8d8:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a8db:	shl    edx,0x3
   0x0804a8de:	add    eax,edx
   0x0804a8e0:	mov    esi,eax
   0x0804a8e2:	lea    eax,[ebp-0x780]
   0x0804a8e8:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804a8eb:	shl    edx,0x3
   0x0804a8ee:	add    eax,edx
   0x0804a8f0:	mov    edx,eax
   0x0804a8f2:	lea    eax,[ebx-0x3e19]
   0x0804a8f8:	mov    DWORD PTR [ebp-0x1c4],eax
   0x0804a8fe:	mov    DWORD PTR [ebp-0x1c8],edx
   0x0804a904:	mov    DWORD PTR [ebp-0x1cc],esi
   0x0804a90a:	mov    DWORD PTR [ebp-0x1d0],ecx
   0x0804a910:	push   eax
   0x0804a911:	push   ebx
   0x0804a912:	push   ecx
   0x0804a913:	push   edx
   0x0804a914:	push   esi
   0x0804a915:	push   edi
   0x0804a916:	push   ebp
   0x0804a917:	nop
   0x0804a918:	mov    eax,DWORD PTR [ebp-0x1c4]
   0x0804a91e:	mov    DWORD PTR [ebp-0x1d4],eax
   0x0804a924:	mov    eax,DWORD PTR [ebp-0x1c8]
   0x0804a92a:	mov    DWORD PTR [ebp-0x1d8],eax
   0x0804a930:	mov    eax,DWORD PTR [ebp-0x1cc]
   0x0804a936:	mov    DWORD PTR [ebp-0x1dc],eax
   0x0804a93c:	mov    eax,DWORD PTR [ebp-0x1d0]
   0x0804a942:	mov    DWORD PTR [ebp-0x1e0],eax
   0x0804a948:	mov    eax,DWORD PTR [ebp-0x1d4]
   0x0804a94e:	mov    esi,DWORD PTR [ebp-0x1d8]
   0x0804a954:	mov    edx,DWORD PTR [ebp-0x1dc]
   0x0804a95a:	mov    ecx,DWORD PTR [ebp-0x1e0]
   0x0804a960:	sub    esp,0x8
   0x0804a963:	xor    ebx,ebx
   0x0804a965:	mov    bl,0x3
   0x0804a967:	shl    ebx,1
   0x0804a969:	shl    ebx,0x2
   0x0804a96c:	add    ebx,0x1a
   0x0804a96f:	inc    ebx
   0x0804a970:	lea    edi,[esp+0x4]
   0x0804a974:	or     ebx,0x0
   0x0804a977:	nop
   0x0804a978:	test   ebx,ebx
   0x0804a97a:	nop
   0x0804a97b:	mov    DWORD PTR [edi],ebx
   0x0804a97d:	mov    DWORD PTR [esp],eax
   0x0804a980:	mov    edi,0x804a986
   0x0804a985:	retf
   0x0804a986:	dec    eax
   0x0804a987:	sub    esp,0x8
   0x0804a98a:	dec    ebp
   0x0804a98b:	xor    ecx,ecx
   0x0804a98d:	inc    ecx
   0x0804a98e:	mov    cl,0x23
   0x0804a990:	dec    ecx
   0x0804a991:	shl    ecx,0x0
   0x0804a994:	dec    ecx
   0x0804a995:	add    ecx,0x0
   0x0804a998:	dec    esp
   0x0804a999:	lea    eax,[esp+0x4]
   0x0804a99d:	dec    ebp
   0x0804a99e:	mov    edx,ecx
   0x0804a9a0:	dec    ecx
   0x0804a9a1:	shl    edx,1
   0x0804a9a3:	dec    ecx
   0x0804a9a4:	shr    edx,1
   0x0804a9a6:	dec    ebp
   0x0804a9a7:	xor    ebx,ebx
   0x0804a9a9:	dec    ecx
   0x0804a9aa:	inc    ebx
   0x0804a9ac:	dec    ecx
   0x0804a9ad:	dec    ebx
   0x0804a9af:	dec    ebp
   0x0804a9b0:	xchg   esp,esp
   0x0804a9b2:	inc    ebp
   0x0804a9b3:	mov    DWORD PTR [eax],ecx
   0x0804a9b5:	mov    DWORD PTR [esp],0x804a9bd
   0x0804a9bc:	retf
   0x0804a9bd:	nop
   0x0804a9be:	pop    ebp
   0x0804a9bf:	pop    edi
   0x0804a9c0:	pop    esi
   0x0804a9c1:	pop    edx
   0x0804a9c2:	pop    ecx
   0x0804a9c3:	pop    ebx
   0x0804a9c4:	pop    eax
   0x0804a9c5:	nop
   0x0804a9c6:	nop
   0x0804a9c7:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804a9ca:	mov    esi,DWORD PTR [ebp+eax*8-0x780]
   0x0804a9d1:	mov    edi,DWORD PTR [ebp+eax*8-0x77c]
   0x0804a9d8:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804a9db:	mov    edx,DWORD PTR [ebp+eax*8-0x73c]
   0x0804a9e2:	mov    eax,DWORD PTR [ebp+eax*8-0x740]
   0x0804a9e9:	add    eax,esi
   0x0804a9eb:	adc    edx,edi
   0x0804a9ed:	mov    ecx,DWORD PTR [ebp-0x2c]
   0x0804a9f0:	mov    DWORD PTR [ebp+ecx*8-0x7c0],eax
   0x0804a9f7:	mov    DWORD PTR [ebp+ecx*8-0x7bc],edx
   0x0804a9fe:	lea    edx,[ebp-0x810]
   0x0804aa04:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804aa07:	add    eax,edx
   0x0804aa09:	mov    ecx,eax
   0x0804aa0b:	lea    eax,[ebp-0x7c0]
   0x0804aa11:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804aa14:	shl    edx,0x3
   0x0804aa17:	add    eax,edx
   0x0804aa19:	mov    esi,eax
   0x0804aa1b:	lea    eax,[ebp-0x580]
   0x0804aa21:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804aa24:	shl    edx,0x3
   0x0804aa27:	add    eax,edx
   0x0804aa29:	mov    edx,eax
   0x0804aa2b:	lea    eax,[ebx-0x3c06]
   0x0804aa31:	mov    DWORD PTR [ebp-0x1a4],eax
   0x0804aa37:	mov    DWORD PTR [ebp-0x1a8],edx
   0x0804aa3d:	mov    DWORD PTR [ebp-0x1ac],esi
   0x0804aa43:	mov    DWORD PTR [ebp-0x1b0],ecx
   0x0804aa49:	push   eax
   0x0804aa4a:	push   ebx
   0x0804aa4b:	push   ecx
   0x0804aa4c:	push   edx
   0x0804aa4d:	push   esi
   0x0804aa4e:	push   edi
   0x0804aa4f:	push   ebp
   0x0804aa50:	nop
   0x0804aa51:	mov    eax,DWORD PTR [ebp-0x1a4]
   0x0804aa57:	mov    DWORD PTR [ebp-0x1b4],eax
   0x0804aa5d:	mov    eax,DWORD PTR [ebp-0x1a8]
   0x0804aa63:	mov    DWORD PTR [ebp-0x1b8],eax
   0x0804aa69:	mov    eax,DWORD PTR [ebp-0x1ac]
   0x0804aa6f:	mov    DWORD PTR [ebp-0x1bc],eax
   0x0804aa75:	mov    eax,DWORD PTR [ebp-0x1b0]
   0x0804aa7b:	mov    DWORD PTR [ebp-0x1c0],eax
   0x0804aa81:	mov    eax,DWORD PTR [ebp-0x1b4]
   0x0804aa87:	mov    esi,DWORD PTR [ebp-0x1b8]
   0x0804aa8d:	mov    edx,DWORD PTR [ebp-0x1bc]
   0x0804aa93:	mov    ecx,DWORD PTR [ebp-0x1c0]
   0x0804aa99:	sub    esp,0x8
   0x0804aa9c:	xor    ebx,ebx
   0x0804aa9e:	mov    bl,0x3
   0x0804aaa0:	shl    ebx,1
   0x0804aaa2:	shl    ebx,0x2
   0x0804aaa5:	add    ebx,0x1a
   0x0804aaa8:	inc    ebx
   0x0804aaa9:	lea    edi,[esp+0x4]
   0x0804aaad:	or     ebx,0x0
   0x0804aab0:	nop
   0x0804aab1:	test   ebx,ebx
   0x0804aab3:	nop
   0x0804aab4:	mov    DWORD PTR [edi],ebx
   0x0804aab6:	mov    DWORD PTR [esp],eax
   0x0804aab9:	mov    edi,0x804aabf
   0x0804aabe:	retf
   0x0804aabf:	dec    eax
   0x0804aac0:	sub    esp,0x8
   0x0804aac3:	dec    ebp
   0x0804aac4:	xor    ecx,ecx
   0x0804aac6:	inc    ecx
   0x0804aac7:	mov    cl,0x23
   0x0804aac9:	dec    ecx
   0x0804aaca:	shl    ecx,0x0
   0x0804aacd:	dec    ecx
   0x0804aace:	add    ecx,0x0
   0x0804aad1:	dec    esp
   0x0804aad2:	lea    eax,[esp+0x4]
   0x0804aad6:	dec    ebp
   0x0804aad7:	mov    edx,ecx
   0x0804aad9:	dec    ecx
   0x0804aada:	shl    edx,1
   0x0804aadc:	dec    ecx
   0x0804aadd:	shr    edx,1
   0x0804aadf:	dec    ebp
   0x0804aae0:	xor    ebx,ebx
   0x0804aae2:	dec    ecx
   0x0804aae3:	inc    ebx
   0x0804aae5:	dec    ecx
   0x0804aae6:	dec    ebx
   0x0804aae8:	dec    ebp
   0x0804aae9:	xchg   esp,esp
   0x0804aaeb:	inc    ebp
   0x0804aaec:	mov    DWORD PTR [eax],ecx
   0x0804aaee:	mov    DWORD PTR [esp],0x804aaf6
   0x0804aaf5:	retf
   0x0804aaf6:	nop
   0x0804aaf7:	pop    ebp
   0x0804aaf8:	pop    edi
   0x0804aaf9:	pop    esi
   0x0804aafa:	pop    edx
   0x0804aafb:	pop    ecx
   0x0804aafc:	pop    ebx
   0x0804aafd:	pop    eax
   0x0804aafe:	nop
   0x0804aaff:	nop
   0x0804ab00:	lea    eax,[ebp-0x500]
   0x0804ab06:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ab09:	shl    edx,0x3
   0x0804ab0c:	add    eax,edx
   0x0804ab0e:	mov    ecx,eax
   0x0804ab10:	lea    eax,[ebp-0x580]
   0x0804ab16:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ab19:	shl    edx,0x3
   0x0804ab1c:	add    eax,edx
   0x0804ab1e:	mov    esi,eax
   0x0804ab20:	lea    eax,[ebp-0x5c0]
   0x0804ab26:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ab29:	shl    edx,0x3
   0x0804ab2c:	add    eax,edx
   0x0804ab2e:	mov    edx,eax
   0x0804ab30:	lea    eax,[ebx-0x3dd1]
   0x0804ab36:	mov    DWORD PTR [ebp-0x184],eax
   0x0804ab3c:	mov    DWORD PTR [ebp-0x188],edx
   0x0804ab42:	mov    DWORD PTR [ebp-0x18c],esi
   0x0804ab48:	mov    DWORD PTR [ebp-0x190],ecx
   0x0804ab4e:	push   eax
   0x0804ab4f:	push   ebx
   0x0804ab50:	push   ecx
   0x0804ab51:	push   edx
   0x0804ab52:	push   esi
   0x0804ab53:	push   edi
   0x0804ab54:	push   ebp
   0x0804ab55:	nop
   0x0804ab56:	mov    eax,DWORD PTR [ebp-0x184]
   0x0804ab5c:	mov    DWORD PTR [ebp-0x194],eax
   0x0804ab62:	mov    eax,DWORD PTR [ebp-0x188]
   0x0804ab68:	mov    DWORD PTR [ebp-0x198],eax
   0x0804ab6e:	mov    eax,DWORD PTR [ebp-0x18c]
   0x0804ab74:	mov    DWORD PTR [ebp-0x19c],eax
   0x0804ab7a:	mov    eax,DWORD PTR [ebp-0x190]
   0x0804ab80:	mov    DWORD PTR [ebp-0x1a0],eax
   0x0804ab86:	mov    eax,DWORD PTR [ebp-0x194]
   0x0804ab8c:	mov    esi,DWORD PTR [ebp-0x198]
   0x0804ab92:	mov    edx,DWORD PTR [ebp-0x19c]
   0x0804ab98:	mov    ecx,DWORD PTR [ebp-0x1a0]
   0x0804ab9e:	sub    esp,0x8
   0x0804aba1:	xor    ebx,ebx
   0x0804aba3:	mov    bl,0x3
   0x0804aba5:	shl    ebx,1
   0x0804aba7:	shl    ebx,0x2
   0x0804abaa:	add    ebx,0x1a
   0x0804abad:	inc    ebx
   0x0804abae:	lea    edi,[esp+0x4]
   0x0804abb2:	or     ebx,0x0
   0x0804abb5:	nop
   0x0804abb6:	test   ebx,ebx
   0x0804abb8:	nop
   0x0804abb9:	mov    DWORD PTR [edi],ebx
   0x0804abbb:	mov    DWORD PTR [esp],eax
   0x0804abbe:	mov    edi,0x804abc4
   0x0804abc3:	retf
   0x0804abc4:	dec    eax
   0x0804abc5:	sub    esp,0x8
   0x0804abc8:	dec    ebp
   0x0804abc9:	xor    ecx,ecx
   0x0804abcb:	inc    ecx
   0x0804abcc:	mov    cl,0x23
   0x0804abce:	dec    ecx
   0x0804abcf:	shl    ecx,0x0
   0x0804abd2:	dec    ecx
   0x0804abd3:	add    ecx,0x0
   0x0804abd6:	dec    esp
   0x0804abd7:	lea    eax,[esp+0x4]
   0x0804abdb:	dec    ebp
   0x0804abdc:	mov    edx,ecx
   0x0804abde:	dec    ecx
   0x0804abdf:	shl    edx,1
   0x0804abe1:	dec    ecx
   0x0804abe2:	shr    edx,1
   0x0804abe4:	dec    ebp
   0x0804abe5:	xor    ebx,ebx
   0x0804abe7:	dec    ecx
   0x0804abe8:	inc    ebx
   0x0804abea:	dec    ecx
   0x0804abeb:	dec    ebx
   0x0804abed:	dec    ebp
   0x0804abee:	xchg   esp,esp
   0x0804abf0:	inc    ebp
   0x0804abf1:	mov    DWORD PTR [eax],ecx
   0x0804abf3:	mov    DWORD PTR [esp],0x804abfb
   0x0804abfa:	retf
   0x0804abfb:	nop
   0x0804abfc:	pop    ebp
   0x0804abfd:	pop    edi
   0x0804abfe:	pop    esi
   0x0804abff:	pop    edx
   0x0804ac00:	pop    ecx
   0x0804ac01:	pop    ebx
   0x0804ac02:	pop    eax
   0x0804ac03:	nop
   0x0804ac04:	nop
   0x0804ac05:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804ac08:	mov    esi,DWORD PTR [ebp+eax*8-0x5c0]
   0x0804ac0f:	mov    edi,DWORD PTR [ebp+eax*8-0x5bc]
   0x0804ac16:	mov    eax,DWORD PTR [ebp-0x2c]
   0x0804ac19:	mov    edx,DWORD PTR [ebp+eax*8-0x3fc]
   0x0804ac20:	mov    eax,DWORD PTR [ebp+eax*8-0x400]
   0x0804ac27:	mov    ecx,edi
   0x0804ac29:	mov    DWORD PTR [ebp-0x840],eax
   0x0804ac2f:	mov    DWORD PTR [ebp-0x83c],edx
   0x0804ac35:	mov    edx,eax
   0x0804ac37:	imul   ecx,edx
   0x0804ac3a:	mov    eax,ecx
   0x0804ac3c:	mov    ecx,DWORD PTR [ebp-0x83c]
   0x0804ac42:	imul   ecx,esi
   0x0804ac45:	add    ecx,eax
   0x0804ac47:	mov    eax,DWORD PTR [ebp-0x840]
   0x0804ac4d:	mul    esi
   0x0804ac4f:	add    ecx,edx
   0x0804ac51:	mov    edx,ecx
   0x0804ac53:	mov    ecx,DWORD PTR [ebp-0x2c]
   0x0804ac56:	mov    DWORD PTR [ebp+ecx*8-0x600],eax
   0x0804ac5d:	mov    DWORD PTR [ebp+ecx*8-0x5fc],edx
   0x0804ac64:	lea    eax,[ebp-0x4c0]
   0x0804ac6a:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ac6d:	shl    edx,0x3
   0x0804ac70:	add    eax,edx
   0x0804ac72:	mov    ecx,eax
   0x0804ac74:	lea    eax,[ebp-0x600]
   0x0804ac7a:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ac7d:	shl    edx,0x3
   0x0804ac80:	add    eax,edx
   0x0804ac82:	mov    esi,eax
   0x0804ac84:	lea    eax,[ebp-0x800]
   0x0804ac8a:	mov    edx,DWORD PTR [ebp-0x2c]
   0x0804ac8d:	shl    edx,0x3
   0x0804ac90:	add    eax,edx
   0x0804ac92:	mov    edx,eax
   0x0804ac94:	lea    eax,[ebx-0x3b54]
   0x0804ac9a:	mov    DWORD PTR [ebp-0x164],eax
   0x0804aca0:	mov    DWORD PTR [ebp-0x168],edx
   0x0804aca6:	mov    DWORD PTR [ebp-0x16c],esi
   0x0804acac:	mov    DWORD PTR [ebp-0x170],ecx
   0x0804acb2:	push   eax
   0x0804acb3:	push   ebx
   0x0804acb4:	push   ecx
   0x0804acb5:	push   edx
   0x0804acb6:	push   esi
   0x0804acb7:	push   edi
   0x0804acb8:	push   ebp
   0x0804acb9:	nop
   0x0804acba:	mov    eax,DWORD PTR [ebp-0x164]
   0x0804acc0:	mov    DWORD PTR [ebp-0x174],eax
   0x0804acc6:	mov    eax,DWORD PTR [ebp-0x168]
   0x0804accc:	mov    DWORD PTR [ebp-0x178],eax
   0x0804acd2:	mov    eax,DWORD PTR [ebp-0x16c]
   0x0804acd8:	mov    DWORD PTR [ebp-0x17c],eax
   0x0804acde:	mov    eax,DWORD PTR [ebp-0x170]
   0x0804ace4:	mov    DWORD PTR [ebp-0x180],eax
   0x0804acea:	mov    eax,DWORD PTR [ebp-0x174]
   0x0804acf0:	mov    esi,DWORD PTR [ebp-0x178]
   0x0804acf6:	mov    edx,DWORD PTR [ebp-0x17c]
   0x0804acfc:	mov    ecx,DWORD PTR [ebp-0x180]
   0x0804ad02:	sub    esp,0x8
   0x0804ad05:	xor    ebx,ebx
   0x0804ad07:	mov    bl,0x3
   0x0804ad09:	shl    ebx,1
   0x0804ad0b:	shl    ebx,0x2
   0x0804ad0e:	add    ebx,0x1a
   0x0804ad11:	inc    ebx
   0x0804ad12:	lea    edi,[esp+0x4]
   0x0804ad16:	or     ebx,0x0
   0x0804ad19:	nop
   0x0804ad1a:	test   ebx,ebx
   0x0804ad1c:	nop
   0x0804ad1d:	mov    DWORD PTR [edi],ebx
   0x0804ad1f:	mov    DWORD PTR [esp],eax
   0x0804ad22:	mov    edi,0x804ad28
   0x0804ad27:	retf
   0x0804ad28:	dec    eax
   0x0804ad29:	sub    esp,0x8
   0x0804ad2c:	dec    ebp
   0x0804ad2d:	xor    ecx,ecx
   0x0804ad2f:	inc    ecx
   0x0804ad30:	mov    cl,0x23
   0x0804ad32:	dec    ecx
   0x0804ad33:	shl    ecx,0x0
   0x0804ad36:	dec    ecx
   0x0804ad37:	add    ecx,0x0
   0x0804ad3a:	dec    esp
   0x0804ad3b:	lea    eax,[esp+0x4]
   0x0804ad3f:	dec    ebp
   0x0804ad40:	mov    edx,ecx
   0x0804ad42:	dec    ecx
   0x0804ad43:	shl    edx,1
   0x0804ad45:	dec    ecx
   0x0804ad46:	shr    edx,1
   0x0804ad48:	dec    ebp
   0x0804ad49:	xor    ebx,ebx
   0x0804ad4b:	dec    ecx
   0x0804ad4c:	inc    ebx
   0x0804ad4e:	dec    ecx
   0x0804ad4f:	dec    ebx
   0x0804ad51:	dec    ebp
   0x0804ad52:	xchg   esp,esp
   0x0804ad54:	inc    ebp
   0x0804ad55:	mov    DWORD PTR [eax],ecx
   0x0804ad57:	mov    DWORD PTR [esp],0x804ad5f
   0x0804ad5e:	retf
   0x0804ad5f:	nop
   0x0804ad60:	pop    ebp
   0x0804ad61:	pop    edi
   0x0804ad62:	pop    esi
   0x0804ad63:	pop    edx
   0x0804ad64:	pop    ecx
   0x0804ad65:	pop    ebx
   0x0804ad66:	pop    eax
   0x0804ad67:	nop
   0x0804ad68:	nop
   0x0804ad69:	add    DWORD PTR [ebp-0x2c],0x1
   0x0804ad6d:	cmp    DWORD PTR [ebp-0x2c],0x7
   0x0804ad71:	jle    0x804a5b3
   0x0804ad77:	mov    DWORD PTR [ebp-0x30],0x1
   0x0804ad7e:	mov    DWORD PTR [ebp-0x34],0x0
   0x0804ad85:	jmp    0x804add8
   0x0804ad87:	mov    eax,DWORD PTR [ebp-0x34]
   0x0804ad8a:	mov    esi,DWORD PTR [ebp+eax*8-0x800]
   0x0804ad91:	mov    edi,DWORD PTR [ebp+eax*8-0x7fc]
   0x0804ad98:	mov    eax,DWORD PTR [ebp-0x34]
   0x0804ad9b:	mov    edx,DWORD PTR [ebp+eax*8-0x53c]
   0x0804ada2:	mov    eax,DWORD PTR [ebp+eax*8-0x540]
   0x0804ada9:	mov    DWORD PTR [ebp-0x840],esi
   0x0804adaf:	mov    DWORD PTR [ebp-0x844],eax
   0x0804adb5:	mov    ecx,edi
   0x0804adb7:	mov    eax,DWORD PTR [ebp-0x840]
   0x0804adbd:	mov    edi,DWORD PTR [ebp-0x844]
   0x0804adc3:	xor    eax,edi
   0x0804adc5:	xor    edx,ecx
   0x0804adc7:	or     eax,edx
   0x0804adc9:	je     0x804add4
   0x0804adcb:	mov    DWORD PTR [ebp-0x30],0x0
   0x0804add2:	jmp    0x804adde
   0x0804add4:	add    DWORD PTR [ebp-0x34],0x1
   0x0804add8:	cmp    DWORD PTR [ebp-0x34],0x7
   0x0804addc:	jle    0x804ad87
   0x0804adde:	cmp    DWORD PTR [ebp-0x30],0x0
   0x0804ade2:	je     0x804adf8
   0x0804ade4:	sub    esp,0xc
   0x0804ade7:	lea    eax,[ebx-0x1fec]
   0x0804aded:	push   eax
   0x0804adee:	call   0x8049060 <puts@plt>
   0x0804adf3:	add    esp,0x10
   0x0804adf6:	jmp    0x804ae0a
   0x0804adf8:	sub    esp,0xc
   0x0804adfb:	lea    eax,[ebx-0x1fe4]
   0x0804ae01:	push   eax
   0x0804ae02:	call   0x8049060 <puts@plt>
   0x0804ae07:	add    esp,0x10
   0x0804ae0a:	mov    eax,0x0
   0x0804ae0f:	lea    esp,[ebp-0x10]
   0x0804ae12:	pop    ecx
   0x0804ae13:	pop    ebx
   0x0804ae14:	pop    esi
   0x0804ae15:	pop    edi
   0x0804ae16:	pop    ebp
   0x0804ae17:	lea    esp,[ecx-0x4]
"""
# (NOTE: 위 dump_content 변수에는 0x8049574 ~ 0x804974a 까지의 상수 초기화 부분만 넣으면 됩니다.
# 실제 파싱은 파일을 읽어서 처리하는 것이 좋습니다.)

# 임시 상수 저장소 (32비트 조각 모음)
const_parts = {}

def parse_line(line):
    line = line.strip().replace('\t', ' ')
    
    # 1. 상수 초기화 파싱 (mov DWORD PTR [ebp-0x300],0x89abcdef)
    m_const = re.search(r'mov\s+DWORD PTR \[ebp-(0x[0-9a-f]+)\],(0x[0-9a-f]+)', line)
    if m_const:
        offset = int(m_const.group(1), 16)
        val = int(m_const.group(2), 16)
        
        # 64비트 정수로 합치기 (Little Endian: 낮은 주소가 하위 4바이트)
        # ebp-0x300 (Low), ebp-0x2fc (High) -> ebp-0x300이 Base
        base_offset = offset if (offset % 8 == 0) else offset + 4
        
        if base_offset not in const_parts:
            const_parts[base_offset] = {}
        
        if offset % 8 == 0: # 8로 나누어 떨어지면 보통 Low part (ebp 오프셋 특성상 주의 필요)
             # EBP 오프셋은 음수 개념이라, 숫자가 클수록 낮은 주소일 수 있음.
             # ebp-0x300 (addr X), ebp-0x2fc (addr X+4)
             # 여기서 0x300 > 0x2fc. 즉 0x300이 더 낮은 주소(Low bytes)가 아님!
             # Stack grows down. [ebp-0x300] is Lower Address than [ebp-0x2fc].
             # Wait, 0x300 is numerically larger than 0x2fc.
             # Address: EBP - 0x300 < EBP - 0x2fc.
             # So [ebp-0x300] is Low 32-bit.
             const_parts[base_offset]['low'] = val
        else:
             const_parts[base_offset]['high'] = val

        if 'low' in const_parts[base_offset] and 'high' in const_parts[base_offset]:
            full_val = (const_parts[base_offset]['high'] << 32) | const_parts[base_offset]['low']
            memory[base_offset] = BitVecVal(full_val, 64)
        return

    # 2. 포인터 로드 (lea reg, [ebp-offset])
    m_lea = re.search(r'lea\s+(eax|ebx|ecx|edx|esi|edi),\[ebp-(0x[0-9a-f]+)\]', line)
    if m_lea:
        reg = m_lea.group(1)
        offset = int(m_lea.group(2), 16)
        registers[reg] = offset # 레지스터가 해당 메모리 오프셋(키)을 가리킴
        return

    # 3. 함수 주소 로드 (lea eax, [ebx-offset])
    m_func = re.search(r'lea\s+eax,\[ebx-(0x[0-9a-f]+)\]', line)
    if m_func:
        func_offset = int(m_func.group(1), 16)
        if func_offset in OP_MAP:
            registers['eax'] = OP_MAP[func_offset] # eax에 연산 이름 저장
        return

    # 4. 스택 푸시 (push reg)
    m_push = re.search(r'push\s+(eax|ebx|ecx|edx|esi|edi)', line)
    if m_push:
        reg = m_push.group(1)
        if reg in registers:
            stack.append(registers[reg])
        else:
            stack.append(None) # ebp, edi 등 관련 없는 푸시
        return

    # 5. 실행 (retf) - 여기가 핵심
    if 'retf' in line:
        # Stack에서 인자 팝 (Calling convention 확인: PUSH Func, PUSH Op1, PUSH Op2, PUSH Dest ...)
        # 덤프 패턴:
        # push eax (Func Addr) -> Stack Top
        # push ebx
        # push ecx (Op Dest)
        # push edx (Op 2)
        # push esi (Op 1)
        # push edi
        # push ebp
        
        # 순서가 복잡하므로 덤프의 push 순서를 역추적해야 함.
        # 일반적인 Heaven's Gate 호출 패턴:
        # PUSH FuncAddr
        # ... args ...
        # RETF (pops IP and CS)
        
        # 덤프의 PUSH 순서:
        # push eax (Func)
        # push ebx
        # push ecx (Arg 3 / Dest?)
        # push edx (Arg 2)
        # push esi (Arg 1)
        # ...
        
        # 스택의 맨 위(마지막 append)가 Function Name
        # 그 아래로 인자들이 깔려있음.
        
        # Stack 상태 (Last In): [..., Arg1, Arg2, Dest, Junk, FuncName]
        # script logic needs to identify which is which based on the trace.
        # Let's verify with the "ADD" trace at 0x8049186.
        # 0x08049c9d: mov ecx,DWORD PTR [ebp-0xe0] (Dest)
        # ...
        # push eax (Func)
        # push ebx
        # push ecx (Dest)
        # push edx (Op2)
        # push esi (Op1)
        
        if len(stack) < 5: return # 안전장치

        # 스택에서 꺼내기 (역순)
        # EBP, EDI, ESI(Op1), EDX(Op2), ECX(Dest), EBX, EAX(Func)
        _ = stack.pop() # ebp
        _ = stack.pop() # edi
        op1_off = stack.pop() # esi
        op2_off = stack.pop() # edx
        dst_off = stack.pop() # ecx
        _ = stack.pop() # ebx
        func_name = stack.pop() # eax

        if isinstance(func_name, str) and func_name in ["ADD", "MUL", "XOR", "AND", "OR", "MOV", "NOT", "SHL", "SHR", "ROL", "ROR", "DIV", "MOD", "INC"]:
            
            # Z3 변수 가져오기 (없으면 0으로 초기화)
            v1 = memory.get(op1_off, BitVecVal(0, 64))
            v2 = memory.get(op2_off, BitVecVal(0, 64))
            
            res = None
            
            if func_name == "ADD": res = v1 + v2
            elif func_name == "MUL": res = v1 * v2
            elif func_name == "XOR": res = v1 ^ v2
            elif func_name == "AND": res = v1 & v2
            elif func_name == "OR":  res = v1 | v2
            elif func_name == "MOV": res = v1
            elif func_name == "NOT": res = ~v1
            elif func_name == "SHL": res = v1 << (v2 & 63)
            elif func_name == "SHR": res = LShR(v1, (v2 & 63))
            elif func_name == "ROL": res = rotate_left(v1, v2)
            elif func_name == "ROR": res = rotate_right(v1, v2)
            elif func_name == "INC": res = v1 + 1
            # DIV/MOD는 0나누기 예외 처리 필요할 수 있으나 CTF에서는 보통 안전
            elif func_name == "DIV": res = UDiv(v1, v2) 
            elif func_name == "MOD": res = URem(v1, v2)

            if res is not None:
                # 결과 저장
                memory[dst_off] = res
        
        # 스택 초기화 (다음 블록을 위해)
        stack.clear()


# 실제 파일 파싱 실행
# 제공된 text 전체를 'dump.txt'에 저장했다고 가정
try:
    with open('dump.txt', 'r') as f:
        for line in f:
            parse_line(line)
except FileNotFoundError:
    print("Error: 'dump.txt' not found. Please save the text dump to this file.")
    exit()

# =========================================================
# 4. Target Verification & Solving
# =========================================================

# Stack Dump에서 추출한 최종 타겟 값 (Little Endian 64-bit Hex)
targets = [
    0x35ee0f56e5b71ca4,
    0x3ffd40a16a1056fd,
    0xca5272e52c5ba31a,
    0x6bc3120b92a71b25,
    0x104fd2f6c2b935a3,
    0xf1b5ca3663b1b1d6,
    0xcae30b30dad2aa08,
    0x7586bb8dc13d6ebe
]

print("adding constraints...")
# 최종 비교는 [ebp-0x840]과 [ebp-0x844]를 XOR/OR 해서 0인지 확인하는 루프에서 일어남.
# 덤프 분석상 ebp-0x840이 계산된 값이고, ebp-0x844가 타겟값일 확률이 높음.
# 하지만 루프는 입력값 변수(Input Buffer) 자체를 변형시켰을 가능성이 큼.
# VM 명령어는 memory 딕셔너리의 상태를 계속 업데이트 했으므로,
# 입력 버퍼 위치(Input Flags)의 최종 상태가 Targets와 같아야 함.

for i in range(8):
    # INPUT_BASE (0x2c0) 부터 시작하는 8개 변수의 *최종 상태* 가져오기
    # 주의: 초기 memory[offset]은 BitVec('flag')였지만, 
    # parse_line을 거치며 memory[offset]은 거대한 Z3 Expression 트리로 변함.
    final_val = memory[INPUT_BASE - (i * 8)]
    solver.add(final_val == targets[i])

print("checking...")
if solver.check() == sat:
    m = solver.model()
    result = b""
    for i in range(8):
        val = m[flags[i]].as_long()
        result += struct.pack('<Q', val)
    print("Flag found!")
    print(result)
else:
    print("unsat")