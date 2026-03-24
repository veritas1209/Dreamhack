import struct
import hashlib
from collections import defaultdict

def solve():
    print("[*] PCAP 패킷 직접 파싱 중 (scapy 불필요)...")
    payloads = []
    
    try:
        with open('tcpdump.pcap', 'rb') as f:
            pcap_header = f.read(24)
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16: break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
                pkt_data = f.read(incl_len)
                
                # SLL(Linux cooked) 헤더 파싱 및 IPv4 UDP 필터링
                eth_type = struct.unpack('>H', pkt_data[14:16])[0]
                if eth_type == 0x0800: # IPv4
                    ip_header_start = 16
                    ihl = pkt_data[ip_header_start] & 0x0F
                    ip_len = ihl * 4
                    protocol = pkt_data[ip_header_start + 9]
                    
                    if protocol == 17: # UDP
                        src_ip = ".".join(map(str, pkt_data[ip_header_start + 12 : ip_header_start + 16]))
                        dst_ip = ".".join(map(str, pkt_data[ip_header_start + 16 : ip_header_start + 20]))
                        udp_start = ip_header_start + ip_len
                        dst_port = struct.unpack('>H', pkt_data[udp_start+2 : udp_start+4])[0]
                        
                        if dst_port == 13337:
                            payload = pkt_data[udp_start+8:]
                            if len(payload) == 32:
                                payloads.append((src_ip, dst_ip, payload[:16], payload[16:32]))
    except Exception as e:
        print(f"[-] PCAP 읽기 에러: {e}")
        return

    print(f"[*] 총 {len(payloads)}개의 통신 패킷 추출 완료.")

    # 각 Guesser가 받은 응답(Answer) 패킷 분류
    answers_to_G = defaultdict(list)
    for src, dst, b1, b2 in payloads:
        src_id = int(src.split('.')[-1])
        dst_id = int(dst.split('.')[-1])
        # 자신에게 보낸 것이 아니면 응답(Answer)으로 간주
        if src_id != dst_id:
            answers_to_G[dst_id].append((src_id, b1, b2))

    all_unique_b2s = set()
    target_higher_b2s_case1 = defaultdict(set)
    target_higher_b2s_case2 = defaultdict(set)

    print("[*] 통계적 군집화를 통한 암호문 의미(Higher/Lower) 유추 중...")
    
    for g in range(1, 33):
        if g not in answers_to_G: continue
        
        # Guesser G가 받은 B1 암호문들의 출처(Target) 개수 세기
        b1_src_counts = defaultdict(set)
        for t, b1, b2 in answers_to_G[g]:
            b1_src_counts[b1].add(t)
            all_unique_b2s.add(b2)
            
        # 다양한 Target(최소 5개 이상)으로부터 받은 B1이 실제 응답용 B1 암호문 (보통 4개)
        answer_b1s = [b1 for b1, srcs in b1_src_counts.items() if len(srcs) > 5]
        
        if len(answer_b1s) != 4:
            continue

        # 각 B1별로 Target들이 몇 번 사용했는지 벡터화
        v_dict = defaultdict(lambda: defaultdict(int))
        for t, b1, b2 in answers_to_G[g]:
            if b1 in answer_b1s:
                v_dict[b1][t] += 1

        # 두 B1 암호문 쌍의 상관관계(Dot Product) 계산
        best_pair = None
        max_score = -1
        for i in range(4):
            for j in range(i+1, 4):
                score = sum(v_dict[answer_b1s[i]][t] * v_dict[answer_b1s[j]][t] for t in range(1, 33))
                if score > max_score:
                    max_score = score
                    best_pair = (i, j)
                    
        # 상관관계가 가장 높은 쌍을 한 그룹으로 묶음
        group1 = {answer_b1s[best_pair[0]], answer_b1s[best_pair[1]]}
        group2 = {b1 for b1 in answer_b1s if b1 not in group1}

        # Case 1: Group 1이 "Higher"인 경우 / Case 2: Group 2가 "Higher"인 경우
        for t, b1, b2 in answers_to_G[g]:
            if b1 in group1:
                target_higher_b2s_case1[t].add(b2)
            elif b1 in group2:
                target_higher_b2s_case2[t].add(b2)

    total_b2 = len(all_unique_b2s)
    print(f"[*] 유니크 B2(Guess 숫자) 발견 개수: {total_b2}개 (최대 256개)")

    # 추출된 개수를 기반으로 각 Target의 Flag 정수값 복원
    for target_higher_b2s in [target_higher_b2s_case1, target_higher_b2s_case2]:
        flags = []
        for t in range(1, 33):
            count = len(target_higher_b2s[t])
            # 유니크 B2가 256개가 안 될 경우를 대비한 스케일링 보정
            val = min(255, max(0, int(round(count * 255.0 / total_b2))))
            flags.append(val)
            
        flag_inner = "".join([f"{v:02x}" for v in flags])
        flag_str = f"DH{{{flag_inner}}}"
        
        if hashlib.md5(flag_str.encode()).hexdigest() == "a5facb6e1f01e7f1a49f82057dc91892":
            print(f"\n[+] 완벽히 일치하는 플래그를 찾았습니다!!!")
            print(f"[+] Flag: {flag_str}")
            return

    print("\n[-] MD5가 일치하지 않습니다. PCAP 캡처 손실로 인한 오차가 존재할 수 있습니다.")
    
if __name__ == '__main__':
    solve()