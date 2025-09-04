from collections import Counter

# 1. 영어에서 자주 등장하는 알파벳 순서
english_freq_order = "ATEOINSHRDLCUMWFGYPBVKJXQZ"

# 2. 암호문 파일 읽기 (UTF-8로 명시)
with open("MyNewBook.txt", 'r', encoding='utf-8') as f:
    ciphertext = f.read()

# 3. 알파벳 빈도 분석
letters_only = [c.upper() for c in ciphertext if c.isalpha()]
letter_counts = Counter(letters_only)

# 4. 암호문에 실제 등장한 문자 순서
cipher_freq_order = [pair[0] for pair in letter_counts.most_common()]

# 5. 매핑 생성 (빈도 기반 추정)
guess_mapping = {}
for i, c in enumerate(cipher_freq_order):
    if i < len(english_freq_order):
        guess_mapping[c] = english_freq_order[i]
    else:
        guess_mapping[c] = c

# 6. 복호화 시도
guessed_plaintext = ""
for c in ciphertext:
    if c.isupper():
        guessed_plaintext += guess_mapping.get(c, c)
    elif c.islower():
        upper_c = c.upper()
        mapped = guess_mapping.get(upper_c, upper_c)
        guessed_plaintext += mapped.lower()
    else:
        guessed_plaintext += c

# 7. 결과 저장 (UTF-8로 명시)
with open("GuessedDecoded.txt", 'w', encoding='utf-8') as out:
    out.write(guessed_plaintext)

print("복호화 추정이 완료되었습니다. 결과는 'GuessedDecoded.txt'에 저장되었습니다.")
