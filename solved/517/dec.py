def caesar_decrypt(ciphertext, shift):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():  # 알파벳인지 확인
            if char.islower():  # 소문자
                decrypted_text += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            elif char.isupper():  # 대문자
                decrypted_text += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            decrypted_text += char  # 알파벳이 아니면 그대로 유지
    return decrypted_text

def try_all_shifts(ciphertext):
    print("암호문:", ciphertext)
    print("모든 경우의 수:")
    for shift in range(1, 27):  # 1부터 26까지 시도
        print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")

# 테스트할 암호문
ciphertext = "EDVLF FUBSWR GUHDPKDFN"

try_all_shifts(ciphertext)
