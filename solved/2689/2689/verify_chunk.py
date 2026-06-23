#!/usr/bin/env python3
# 복원한 8바이트가 해당 bin을 exit 0 으로 통과시키는지 네이티브 실행으로 검증.
# 사용: python3 verify_chunk.py ./bin_0 <hex16>
import subprocess, sys, os
b, h = sys.argv[1], sys.argv[2]
a = bytes.fromhex(h)
# argv[0]은 임의(슬래시 유무가 VM 트리거에 영향 줄 수 있으니 둘 다 시도)
for argv0 in (os.path.basename(b), os.path.abspath(b)):
    p = subprocess.run([b, a], executable=b, capture_output=True)
    print(f"argv0~{argv0}: exit={p.returncode} {'PASS' if p.returncode==0 else ''}")
