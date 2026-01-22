import sys

def analyze_trace_sca(filenames):
    # 1. 트레이스 로드 및 'rep movsb' 카운팅
    # rep movsb는 주소가 0x7ffff7fb88c7 입니다 (asm 및 trace 기준)
    # 이 명령어가 연속해서(혹은 한 덩어리로) 몇 번 호출되는지를 셉니다.
    
    trace_ip = "0x7ffff7fb88c7"
    
    ops_counts = []
    current_count = 0
    in_block = False
    
    # 두 파일을 순서대로 읽습니다.
    full_lines = []
    for fname in filenames:
        try:
            with open(fname, 'r') as f:
                full_lines.extend(f.readlines())
        except FileNotFoundError:
            print(f"[!] File not found: {fname}")
            return

    # 라인을 순회하며 연산 덩어리(Burst) 크기를 잽니다.
    # 각 비트 처리 구간마다 movsb 호출 횟수가 다를 것입니다.
    
    # 휴리스틱: movsb가 나오면 카운트 증가, 
    # movsb가 아닌 다른 'Write Detected'나 명령어가 오랫동안 나오면 블록 종료로 간주
    
    # 하지만 로그 포맷상 => IP 가 나오고 그 뒤에 메모리 덤프가 나옵니다.
    # => IP 라인만 카운트하면 됩니다.
    
    ips = []
    for line in full_lines:
        if line.startswith("=>"):
            ip = line.split(":")[0].split(" ")[1]
            ips.append(ip)

    # IP 스트림을 분석하여 패턴 분리
    # 보통 Double 연산 구간과 Add 연산 구간은 특정 명령어로 구분됩니다.
    # 여기서는 단순하게 'rep movsb'의 밀집도로 0/1을 판별해 봅니다.
    
    cluster_sizes = []
    current_cluster = 0
    
    # 갭(Gap)이 크면 다음 비트 연산으로 넘어간 것으로 간주
    gap_threshold = 5 # movsb가 아닌 다른 명령어가 5개 이상 나오면 끊음
    gap_count = 0
    
    for ip in ips:
        if ip == trace_ip:
            current_cluster += 1
            gap_count = 0
        else:
            gap_count += 1
            if gap_count > gap_threshold and current_cluster > 0:
                cluster_sizes.append(current_cluster)
                current_cluster = 0
    
    if current_cluster > 0:
        cluster_sizes.append(current_cluster)

    # 2. 클러스터 크기 분석 (0 vs 1 판별)
    if not cluster_sizes:
        print("[-] No movsb operations found.")
        return

    avg = sum(cluster_sizes) / len(cluster_sizes)
    print(f"[*] Found {len(cluster_sizes)} operation bursts.")
    print(f"[*] Average burst size: {avg:.2f}")
    print(f"[*] Max: {max(cluster_sizes)}, Min: {min(cluster_sizes)}")
    
    # 평균보다 현저히 크면 1 (Square + Multiply), 작으면 0 (Square)
    # 보통 Square와 Multiply의 연산량이 비슷하다면:
    # 0 (Square) ~= N
    # 1 (Square + Mult) ~= 2N
    
    # 임계값 설정 (Min과 Max의 중간)
    threshold = (min(cluster_sizes) + max(cluster_sizes)) / 2
    print(f"[*] Threshold: {threshold:.2f}")
    
    bits = ""
    for size in cluster_sizes:
        if size > threshold:
            bits += "1"
        else:
            bits += "0"
            
    print(f"[*] Recovered {len(bits)} bits.")
    print(f"[*] Bits: {bits}")
    
    # 3. 비트 -> 문자열 변환
    # 플래그 길이는 64바이트(512비트)라고 했습니다.
    # 복구된 비트가 512비트 근처인지 확인해야 합니다.
    # 보통 최상위 비트(항상 1)가 생략되거나 패딩이 있을 수 있습니다.
    
    try:
        # 비트스트림을 정수로 변환
        val = int(bits, 2)
        # 바이트로 변환
        from Crypto.Util.number import long_to_bytes
        flag = long_to_bytes(val)
        print("\n[+] Decoded Flag Candidate:")
        print(flag)
        
        # ASCII 디코딩 시도
        try:
            print(f"[+] ASCII: {flag.decode()}")
        except:
            pass
            
    except Exception as e:
        print(f"[-] Decoding failed: {e}")

# 실행
print("--- Side-Channel Analysis ---")
# 파일 이름은 업로드된 실제 파일명에 맞게 수정하세요
analyze_trace_sca(['mem_trace.log', 'mem_trace2.log'])