from sage.all import *
from Crypto.Util.number import long_to_bytes

# 1. 메모리 덤프에서 추출한 값들 (Little-Endian to Big-Integer)
def parse_le(words):
    # words = [low, ..., high]
    res = 0
    for w in reversed(words):
        res = (res << 64) | w
    return res

# 0x7ffff7faf300
raw_P = [0x8c8fca1105779ca1, 0xaf9538f9cb8f4b2e, 0xa4a2dd55819c8639, 0x23c763205bd782ec]
P = parse_le(raw_P)

# 0x7ffff7faf320
raw_A = [0xf0df91a6ca83b805, 0x075ff072b9f5e06f, 0xa6cc984dd0152ddb, 0x63c1797800379a2c]
A = parse_le(raw_A)

# 0x7ffff7faf340
raw_B = [0x964c12787d5581c4, 0x5cdf286001c3afe9, 0x934bd170d0b650cc, 0x2dc20d0d511a08f1]
B = parse_le(raw_B)

# 0x7ffff7faf378 (Target Value)
# "3TF_" 뒤에 있는 32바이트 데이터
raw_Target_X = [0x1c60f4043be69da0, 0x89d5dbdca98b41a9, 0x79670de8cce014a1, 0x422e2374d0e0a26e]
target_x = parse_le(raw_Target_X)

print(f"[+] Modulus P: {hex(P)}")
print(f"[+] Curve A: {hex(A)}")
print(f"[+] Curve B: {hex(B)}")
print(f"[+] Target X: {hex(target_x)}")

# 2. 타원곡선 정의 (Montgomery Curve일 가능성이 높음: B*y^2 = x^3 + A*x^2 + x)
#    하지만 메모리 구조상 Short Weierstrass (y^2 = x^3 + Ax + B) 일 수도 있음.
#    일단 일반적인 Weierstrass로 시도해보고, 안되면 Montgomery로 변환.

try:
    # GF(P) 위에서의 타원곡선 정의
    F = GF(P)
    E = EllipticCurve(F, [A, B])
    print("[+] Curve defined (Short Weierstrass):", E)
    
    # 3. Target Point Q 찾기 (X좌표로부터 Y좌표 복원)
    try:
        Q = E.lift_x(target_x)
        print("[+] Target Point Q found:", Q)
    except ValueError:
        print("[-] Failed to lift X. Trying Montgomery form or Twist...")
        # Montgomery Form일 경우: B*y^2 = x^3 + A*x^2 + x
        # 이를 Weierstrass로 변환하는 공식 적용 필요
        # (만약 실패하면 아래 Montgomery 로직 추가 필요)
        exit()

    # 4. Base Point G 찾기
    #    보통 Generator는 곡선 위수를 계산하여 가장 작은 subgroup의 generator를 쓰거나
    #    코드 어딘가에 숨겨져 있음. 
    #    하지만 여기선 'G' 값이 명시적으로 안 보임.
    #    -> CSWAP 로그에서 계속 보였던 '0xf108...'과 '0x620c...'가 G의 좌표일 수 있음!
    
    # CSWAP 로그에서 추출한 값 (Little Endian 가정)
    # [CSWAP] A: 0xf1081a510d0dc22d ... 
    # 이 값들이 하나의 좌표를 구성할 수 있음. 
    # 여기서는 일단 Order를 구해서 G를 유추하거나, 작은 소인수분해 시도.
    
    order = E.order()
    print(f"[+] Curve Order: {order}")
    print(f"[+] Factored Order: {factor(order)}")

    # Pohlig-Hellman 공격
    # (Order가 Smooth하다면 금방 풀림)
    
    # Generator를 모르므로, 직접 찾아야 함.
    # 보통 플래그는 ASCII 범위이므로, 작은 숫자임. 
    # 하지만 여기선 64바이트 플래그이므로 매우 큰 수.
    
    # ★ 중요: Base Point G를 모르더라도, 
    # 만약 우리가 찾은 Q가 Generator에 의해 생성된 점이라면
    # Discrete Log를 풀 때 G를 임의의 점으로 잡고 풀면 k * (Something) 꼴이 나옴.
    
    # 하지만 CSWAP 로그에서 반복된 그 값을 G_x로 가정해보자.
    # (로그에 나왔던 0xf108... 값은 64비트라 너무 작음. 4개를 합쳐야 함)
    # 0x7ffff7faf360 (Set 3 바로 뒤)에 있는 값이 G일 수도 있음.
    
    raw_G = [0xdeccdccd34860c62, 0xa4f96e8c33b9d828, 0x0, 0x0] # 뒤에 0은 가정
    # 일단 Order가 Smooth한지 먼저 확인하는 것이 급선무.

    # 5. Discrete Log 풀기 (Q = k * G)
    # G를 모르니, P-1 (Modulus-1) 공격이나 Smart Attack 등을 고려해야 함.
    # 하지만 Order가 소인수분해 잘 되면 그냥 G 상관없이 풀림.
    
except Exception as e:
    print("[-] Error:", e)