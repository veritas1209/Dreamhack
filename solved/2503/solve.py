#!/usr/bin/env python3
from pwn import *
from Crypto.Util.Padding import unpad
import os

context.log_level = "info"   # 자세히 보려면 "debug"

HOST = "host3.dreamhack.games"
PORT = 23946


def menu(io, c):
    io.sendlineafter(b"Menu >> ", str(c).encode())


def get_token_ct(io):
    """Menu 1: IV || C1 || C2 (token 16B -> pad -> 2 blocks)"""
    menu(io, 1)
    data = bytes.fromhex(io.recvline().strip().decode())
    iv, c1, c2 = data[:16], data[16:32], data[32:48]
    return iv, c1, c2


def query(io, iv_block, ct_block):
    """iv_block||ct_block 1회 질의 -> True / False / None"""
    menu(io, 2)
    io.sendlineafter(b"Ciphertext (hex) >> ", (iv_block + ct_block).hex().encode())
    resp = io.recvline().strip().decode()
    if resp == "True":
        return True
    if resp == "False":
        return False
    return None   # 오라클 침묵


def oracle(io, iv_block, ct_block, free_idx):
    """
    확실한 True/False 를 얻을 때까지 free_idx 보다 앞쪽(0..free_idx-1) 바이트를
    랜덤화하며 재질의한다. free_idx 이후 바이트는 패딩을 위해 고정되어 있으므로
    앞쪽 랜덤화는 unpad 결과에 영향을 주지 않고 give_or_not 캐시만 회피한다.
    free_idx == 0 이면 흔들 바이트가 없으므로 사용하면 안 된다(별도 처리).
    """
    iv = bytearray(iv_block)
    while True:
        res = query(io, bytes(iv), ct_block)
        if res is not None:
            return res
        for j in range(free_idx):
            iv[j] = os.urandom(1)[0]


def recover_intermediate(io, ct_block):
    """D(ct_block) 16바이트 복구. byte[0]은 캐시에 잠기면 예외로 재연결 유도."""
    inter = bytearray(16)

    for k in range(1, 17):
        idx = 16 - k
        pad_val = k

        # ---- 마지막 바이트(idx=0): 앞쪽에 흔들 바이트가 없음 ----
        if idx == 0:
            candidates = []
            for guess in range(256):
                iv = bytearray(16)
                for j in range(1, 16):
                    iv[j] = inter[j] ^ pad_val
                iv[0] = guess
                if query(io, bytes(iv), ct_block) is True:
                    candidates.append(guess)

            if len(candidates) == 1:
                inter[0] = candidates[0] ^ pad_val
            elif len(candidates) == 0:
                # 정답 guess 가 give_or_not 의 None 에 걸려 영원히 숨겨짐
                raise RuntimeError("byte[0] hidden by oracle -> reconnect")
            else:
                # \x10\x10... 같은 가짜 후보가 섞인 경우(드묾): 검증
                real = None
                for g in candidates:
                    iv = bytearray(16)
                    for j in range(2, 16):
                        iv[j] = inter[j] ^ pad_val
                    iv[1] ^= 0xff           # idx=1 바이트를 흔들어 진짜 검증
                    iv[0] = g
                    r = query(io, bytes(iv), ct_block)
                    if r is True:
                        real = g
                        break
                    if r is None:
                        raise RuntimeError("byte[0] verify hidden -> reconnect")
                if real is None:
                    raise RuntimeError("byte[0] verify failed -> reconnect")
                inter[0] = real ^ pad_val

            log.info(f"byte[0] = {inter[0]:02x}")
            break

        # ---- idx >= 1: 앞쪽 랜덤화로 캐시 회피 가능 ----
        found = False
        for guess in range(256):
            iv = bytearray(16)
            for j in range(idx + 1, 16):
                iv[j] = inter[j] ^ pad_val
            iv[idx] = guess
            if oracle(io, bytes(iv), ct_block, idx):
                # 마지막에서 두 번째 바이트 아님, k==1 가짜 후보 검증
                if k == 1:
                    iv2 = bytearray(iv)
                    iv2[idx - 1] ^= 0xff
                    if not oracle(io, bytes(iv2), ct_block, idx - 1):
                        continue
                inter[idx] = guess ^ pad_val
                found = True
                log.info(f"byte[{idx}] = {inter[idx]:02x}")
                break
        assert found, f"byte {idx} not found"

    return bytes(inter)


def attempt():
    """한 번의 연결로 토큰 복구 시도. 성공 시 (io, token) 반환, 실패 시 None."""
    io = remote(HOST, PORT)
    try:
        iv, c1, c2 = get_token_ct(io)
        log.info(f"IV = {iv.hex()}")
        log.info(f"C1 = {c1.hex()}")

        d_c1 = recover_intermediate(io, c1)
        token = bytes(a ^ b for a, b in zip(d_c1, iv))
        log.success(f"token = {token.hex()}")
        return io, token
    except RuntimeError as e:
        log.warning(f"{e}")
        io.close()
        return None


def main():
    io = token = None
    tries = 0
    while io is None:
        tries += 1
        log.info(f"=== attempt #{tries} ===")
        r = attempt()
        if r is not None:
            io, token = r

    # Menu 3: 한 번만 제출 가능
    menu(io, 3)
    io.sendlineafter(b"Answer (hex) >> ", token.hex().encode())
    print(io.recvline().decode())
    io.interactive()


if __name__ == "__main__":
    main()