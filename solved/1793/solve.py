import sys, socket, subprocess, re, json

CUBES = [
    ([7, 14, 19, 20, 50], 1 << 51),
    ([7, 8, 9, 40, 50],   1 << 52),
    ([16, 18, 19, 49, 50],1 << 53),
    ([3, 8, 9, 26, 48],   1 << 54),
    ([5, 8, 9, 16, 50],   1 << 55),
]

def build_queries():
    queries, groups = [], []
    for pos, base in CUBES:
        idxs = []
        for mask in range(1 << len(pos)):
            iv = base
            for j, p in enumerate(pos):
                if (mask >> j) & 1:
                    iv |= (1 << p)
            idxs.append(len(queries)); queries.append(iv)
        groups.append(idxs)
    return queries, groups

QUERIES, GROUPS = build_queries()

# ---------- minimal tube ----------
class Tube:
    def __init__(self): self.buf = b""
    def _read(self, n): raise NotImplementedError
    def _write(self, b): raise NotImplementedError
    def recvuntil(self, delim):
        delim = delim if isinstance(delim, bytes) else delim.encode()
        while delim not in self.buf:
            chunk = self._read(4096)
            if not chunk:
                raise EOFError(self.buf)
            self.buf += chunk
        i = self.buf.index(delim) + len(delim)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out
    def sendline(self, s):
        s = s if isinstance(s, bytes) else s.encode()
        self._write(s + b"\n")

class RemoteTube(Tube):
    def __init__(self, host, port):
        super().__init__()
        self.s = socket.create_connection((host, port))
    def _read(self, n): return self.s.recv(n)
    def _write(self, b): self.s.sendall(b)

class LocalTube(Tube):
    def __init__(self, argv):
        super().__init__()
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    def _read(self, n): return self.p.stdout.read1(n) if hasattr(self.p.stdout,'read1') else self.p.stdout.read(n)
    def _write(self, b):
        self.p.stdin.write(b); self.p.stdin.flush()

# ---------- solver ----------
def solve_stage(io):
    results = []
    for iv in QUERIES:
        io.recvuntil(b"iv > ")
        io.sendline(str(iv))
        io.recvuntil(b"result = ")
        line = io.recvuntil(b"\n").strip()
        results.append(int(line))
    # break out of the query loop
    io.recvuntil(b"iv > ")
    io.sendline("-1")

    nonzero = 0
    for idxs in GROUPS:
        acc = 0
        for i in idxs:
            acc ^= results[i]
        nonzero += bin(acc).count("1")

    is_urandom_guess = (nonzero > 1)   # <=1 -> NFSR
    io.recvuntil(b"Is this urandom? (y/n) ")
    io.sendline("y" if is_urandom_guess else "n")
    return is_urandom_guess

def main():
    if len(sys.argv) >= 3 and sys.argv[1] != "--local":
        io = RemoteTube(sys.argv[1], int(sys.argv[2]))
    else:
        io = LocalTube(["python3", "-u", "chal.py"])  # local test

    for stage in range(50):
        io.recvuntil(b"]")  # consume "[STAGE k]"
        g = solve_stage(io)
        print(f"[stage {stage+1:2d}] guessed {'urandom' if g else 'NFSR'}")

    # read the rest (flag or failure)
    try:
        tail = io.recvuntil(b"\n", )
    except EOFError as e:
        tail = e.args[0]
    rest = b""
    try:
        while True:
            c = io._read(4096)
            if not c: break
            rest += c
    except Exception:
        pass
    out = (io.buf + tail + rest)
    print(out.decode(errors="replace"))

if __name__ == "__main__":
    main()