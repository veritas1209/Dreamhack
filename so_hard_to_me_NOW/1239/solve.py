import re
from collections import defaultdict

def main():
    # 앞서 추출한 패킷 텍스트 파일을 읽어옵니다. (파일명은 상황에 맞게 수정)
    try:
        with open('packets.json', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("[!] packets.txt 파일이 없습니다. 기존 스크립트 출력을 파일로 저장해주세요.")
        print("예: python extract_pcap.py > packets.txt")
        return

    # IP 쌍(Pair)별로 패킷을 그룹화합니다.
    ip_pairs = defaultdict(list)
    for line in lines:
        line = line.strip()
        if not line.startswith('['):
            continue
            
        m = re.match(r'\[(.*?) \-\> (.*?)\] (.*)', line)
        if m:
            src, dst, payload = m.groups()
            # 중복 패킷은 제외하고 고유한 페이로드만 저장
            payload_bytes = bytes.fromhex(payload)
            if payload_bytes not in ip_pairs[(src, dst)]:
                ip_pairs[(src, dst)].append(payload_bytes)

    # 우리가 알고 있는 평문 앞부분 (10바이트)
    known_plain = b"Query is: "

    print("[*] KPA (기지 평문 공격) 분석 시작...\n")
    
    # 처음 몇 개의 통신 쌍만 테스트로 출력해봅니다.
    for pair, payloads in list(ip_pairs.items())[:5]:
        print(f"=== 통신 쌍: {pair[0]} -> {pair[1]} ===")
        
        for i, p in enumerate(payloads[:3]): # 각 쌍별로 처음 3개의 고유 패킷만 확인
            # 암호문 앞 10바이트와 평문 10바이트를 XOR 연산하여 키스트림 추출
            keystream_prefix = bytes(c ^ k for c, k in zip(p[:10], known_plain))
            
            print(f"  패킷 {i+1} 원본(Hex): {p.hex()[:32]}...")
            print(f"  -> 추출된 Keystream: {keystream_prefix.hex()}")
        print("")

if __name__ == "__main__":
    main()