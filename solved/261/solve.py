import requests
import ast
import hashlib
import binascii

URL = "http://host8.dreamhack.games:13365"

# 비트코인 방식의 더블 SHA256 해시 함수 (Little Endian 처리)
def hash2(a, b):
    a = binascii.unhexlify(a)[::-1]
    b = binascii.unhexlify(b)[::-1]
    h = hashlib.sha256(hashlib.sha256(a + b).digest()).digest()
    return h[::-1].hex()

# 서버와 동일한 머클 루트 계산 로직
def calculate_merkle_root(tx_hashes):
    if len(tx_hashes) == 1:
        return tx_hashes[0]
    next_layer = []
    for i in range(0, len(tx_hashes), 2):
        if i + 1 == len(tx_hashes):
            next_layer.append(hash2(tx_hashes[i], tx_hashes[i]))
        else:
            next_layer.append(hash2(tx_hashes[i], tx_hashes[i+1]))
    return calculate_merkle_root(next_layer)

def solve():
    print("[*] 1. 서버에서 데이터 로드 중...")
    r = requests.get(URL + "/")
    data = r.text.split("\n")
    
    # 데이터 파싱
    mr = ast.literal_eval(data[0])[1]
    tx_hashes = ast.literal_eval(data[1].replace("tx list:", ""))
    target_idx = tx_hashes.index("?" * 64)
    
    print(f"[+] Target Merkle Root: {mr}")
    print(f"[+] Missing Index: {target_idx}")
    
    print("\n[*] 2. 로컬에서 65536개의 가능한 해시 브루트포스 진행 중 (약 1초 소요)...")
    
    # 0부터 65535까지 2바이트로 만들 수 있는 모든 경우의 수 탐색
    for i in range(65536):
        # 2바이트 시드 생성
        seed = i.to_bytes(2, byteorder='big') 
        # 서버와 동일한 방식으로 리프 노드(트랜잭션) 해시 생성
        candidate_hash = hashlib.sha256(seed).digest()[::-1].hex()
        
        # 빈칸에 임시로 넣고 머클 루트 계산
        tx_hashes[target_idx] = candidate_hash
        calculated_mr = calculate_merkle_root(tx_hashes)
        
        # 계산된 머클 루트가 서버가 준 타겟과 일치하면 정답!
        if calculated_mr == mr:
            print(f"[🎉] 정답 해시값을 찾았습니다!: {candidate_hash}")
            
            print("\n[*] 3. 서버에 정답 제출 중...")
            res = requests.get(URL + f"/check/{candidate_hash}")
            print(f"[+] 서버 응답: {res.text}")
            break

if __name__ == "__main__":
    solve()