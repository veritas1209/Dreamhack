# 암호문 복호화를 위한 코드 실행

# 암호화 알고리즘 클래스
class STREAM:
    def __init__(self, seed, size):
        self.state = self.num2bits(seed, size)

    def num2bits(self, num, size):
        assert num < (1 << size)
        return bin(num)[2:].zfill(size)
    
    def bits2num(self, bits):
        return int('0b' + bits, 2)
    
    def shift(self):
        new_bit = self.state[-1]
        self.state = new_bit + self.state[:-1]
        return new_bit
    
    def getNbits(self, num):
        sequence = ""
        for _ in range(num):
            sequence += self.shift()
        return sequence

    def decrypt(self, ciphertext):
        plaintext = b""
        for c in ciphertext:
            stream = self.bits2num(self.getNbits(8))
            p = c ^ stream
            plaintext += bytes([p])
        return plaintext


# 복호화 시도
ciphertext_hex = "3cef03c64ac240c349971d9e4c951cc14ec4199f409249c21e964ac540c540944f901c934cc240934d96419f4b9e4d9f1cc41dc61dc34e9219c31bc11a914f9141c61ada"
ciphertext = bytes.fromhex(ciphertext_hex)

# 가능한 모든 시드를 시도하면서 복호화
decrypted_results = {}
for seed in range(0x100):  # 0x00부터 0xFF까지 모든 시드 테스트
    stream = STREAM(seed, 16)
    decrypted_text = stream.decrypt(ciphertext)
    try:
        # 복호화된 결과가 UTF-8 문자열로 해석될 수 있는지 확인
        decrypted_results[seed] = decrypted_text.decode('utf-8')
    except UnicodeDecodeError:
        continue  # 해석할 수 없는 문자열은 무시

# 성공적으로 복호화된 결과 반환
print(decrypted_results)
# 새로운 정보를 바탕으로 복호화 재시도
# 복호화할 때 플래그 형식 'DH{' 및 '}' 패턴을 확인

# 가능한 모든 시드와 'DH{'로 시작하는 복호화 결과 찾기
possible_flag = None

for seed in range(0x10000):  # 16비트 시드: 0x0000부터 0xFFFF까지 시도
    stream = STREAM(seed, 16)
    decrypted_text = stream.decrypt(ciphertext)
    if decrypted_text.startswith(b'DH{') and decrypted_text.endswith(b'}'):
        possible_flag = (seed, decrypted_text.decode('utf-8'))
        break  # 플래그가 발견되면 반복 중단

print(possible_flag)
