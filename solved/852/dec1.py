def caesar_decrypt(ciphertext, shift):
    decrypted_text = []
    for char in ciphertext:
        if char.isalpha():
            # 대소문자 구분하여 복호화
            start = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - start - shift) % 26 + start)
            decrypted_text.append(decrypted_char)
        else:
            # 공백은 그대로 둡니다.
            decrypted_text.append(char)
    return ''.join(decrypted_text)

ciphertext = "EDVLF FUBSWR GUHDPKDFN"
for shift in range(1, 26):
    print(f"Shift {shift}: {caesar_decrypt(ciphertext, shift)}")
