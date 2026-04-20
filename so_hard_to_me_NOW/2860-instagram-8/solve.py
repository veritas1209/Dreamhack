import frida
import subprocess
import sys
import time

# =====================================================================
# [Frida Injection JavaScript - 메모리 스캐너 & 파일 완벽 차단]
# =====================================================================
JS_CODE = """
// 1. 스냅샷 파일(txt) 생성 완벽 차단 (디스크 병목 제거)
var pCreateFileW = Module.findExportByName("kernel32.dll", "CreateFileW");
if (pCreateFileW) {
    Interceptor.attach(pCreateFileW, {
        onEnter: function (args) {
            try {
                // Windows CreateFileW는 UTF-16 문자열을 사용합니다.
                var filename = args[0].readUtf16String();
                if (filename && filename.indexOf("feed_snapshot") !== -1) {
                    this.block = true;
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.block) {
                // INVALID_HANDLE_VALUE(-1) 리턴으로 파일 생성 완벽 무효화
                retval.replace(ptr("-1")); 
            }
        }
    });
}

// 2. 바이너리 내부 32바이트 플래그 조립 버퍼 스캔 (FUN_140031e40)
// [수정] 오타 없이 안전한 Process.getModuleByName 사용
var baseAddr = Process.getModuleByName("instagram.exe").base;
var targetFunc = baseAddr.add(0x31E40); 

var flagBuf = null;
var is_last_rank = false;

Interceptor.attach(targetFunc, {
    onEnter: function (args) {
        flagBuf = args[0]; // param_1 (32-byte array)
        var rank = args[2].toInt32();
        is_last_rank = (rank === 29); // 30번째 게시물(마지막 조립) 감지
    },
    onLeave: function (retval) {
        if (is_last_rank && flagBuf) {
            try {
                var str = flagBuf.readUtf8String(32);
                send({ type: "state", data: str });
                
                // DH{ 로 시작하면 플래그로 간주
                if (str.indexOf("DH{") === 0) {
                    send({ type: "flag", data: str });
                }
            } catch (e) {}
        }
    }
});
"""

# =====================================================================
# [Python Controller]
# =====================================================================
round_count = 0
start_time = 0

def on_message(message, data):
    global round_count, start_time
    
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload['type']
            
        if msg_type == 'state':
            round_count += 1
            # 1000 라운드 단위로 스캔 상태 및 속도 브리핑
            if round_count % 1000 == 0:
                elapsed = time.time() - start_time
                rps = int(1000 / elapsed) if elapsed > 0 else 0
                print(f"[ROUND {round_count:06d}] 메모리 버퍼: {payload['data'][:15]}... (속도: {rps} rounds/sec)")
                start_time = time.time()
                
        elif msg_type == 'flag':
            print("\n" + "="*60)
            print(f"🔥 [CRITICAL BINGO] DH{{ 포맷 메모리 조립 감지!!! (Round {round_count})")
            print(f"🚩 EXPORTED FLAG: {payload['data']}")
            print("="*60 + "\n")
            
            # 사용자님이 말씀하신 7800번대의 가짜 플래그를 지나쳐 
            # 진짜를 찾기 위해 스크립트를 강제 종료하지 않습니다.
            print("[*] (가짜 플래그일 가능성을 대비해 스캔을 계속 진행합니다. 멈추려면 Ctrl+C)")
            
    elif message['type'] == 'error':
        print(f"\n[!] Frida 에러 발생:\n{message['stack']}")
        sys.exit(1)

def main():
    global start_time
    print("[*] 🚀 네이티브 인메모리 에뮬레이터 런칭 중...")
    
    # 프로세스를 백그라운드로 띄웁니다 (출력 무시로 속도 극대화)
    p = subprocess.Popen(
        ["instagram.exe"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL, 
        text=True, 
        bufsize=1
    )
    time.sleep(1) # 모듈이 메모리에 올라갈 때까지 대기
    
    try:
        session = frida.attach(p.pid)
    except Exception as e:
        print(f"[!] Frida 연결 실패: {e}")
        p.kill()
        sys.exit(1)
        
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()
    
    print("\n[*] ================== [엔진 가동 준비 완료] ==================")
    print("[*] 파일 생성을 완벽히 차단했습니다. 이제 하드디스크는 평화롭습니다.")
    print("[*] 무한 스캔을 시작합니다...\n")
    
    start_time = time.time()
    
    try:
        while True:
            # refresh 로 스탯을 올리고, export 로 메모리 조립(FUN_140031e40)을 트리거합니다.
            p.stdin.write("refresh\nexport\n")
            p.stdin.flush()
            
    except KeyboardInterrupt:
        print(f"\n[*] 사용자에 의해 중단되었습니다. (최종 라운드: {round_count})")
        p.kill()
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Python 컨트롤러 에러: {e}")
        p.kill()
        sys.exit(1)

if __name__ == '__main__':
    main()