Homemade Cipher (WaRP) 복호화 - 파일 안내
=========================================

[플래그]  WaRP{3ntr0py_att@ck}

[필요 파일]
  cipher.py        문제에서 제공된 암호 (필수, 같은 폴더)
  flag_bmp.enc     암호문

[빠른 복호화 — nonce를 이미 아는 경우]
  python3 solve.py flag_bmp.enc --nonce 1521696479
    -> flag_decrypted.bmp 생성. 이미지를 열면 플래그가 보임.

[처음부터 — nonce 전수조사 포함]
  (1) 순수 파이썬 (느림, 검증/이식용):
        python3 solve.py flag_bmp.enc
  (2) C 전수조사 (권장, 수 분 내):
        # boxes.h, brute8.c, make_pairs.py 사용
        python3 make_pairs.py flag_bmp.enc pairs.txt
        gcc -O3 -march=native -o brute8 brute8.c
        # H = (nonce>>8) 를 [0, 2^24) 범위로 스캔. 인자: pairs파일 H시작 H끝
        ./brute8 pairs.txt 0 16777216
        # 출력된 'CANDIDATE nonce=...' 의 nonce 중 아무 값이나 사용:
        python3 solve.py flag_bmp.enc --nonce <찾은_nonce>

[원리 요약]
  암호 분해:  key[c] = base_{b,c,d}[(key[x]+a)] - a   (mod 256)
    - (a,b,c,d): (nonce+위치)의 하위->상위 바이트
    - base 는 공개 s-box(s1~s4,r)만으로 계산 가능
    - 비밀은 key(256 순열)와 nonce(32bit) 뿐
  취약점("엔트로피 공격"):
    단색 배경 BMP라 같은 채널 배경 픽셀은 key[배경]이 상수.
    -> 배경 픽셀들의 암호문 충돌 패턴이 key와 무관하게 nonce에만 의존.
    -> 이 k-free 검사로 nonce 전수조사 -> 배경 앵커로 key 전체 복원 -> 복호화.
