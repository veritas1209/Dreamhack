from random import shuffle

letter_upper = [chr(i + 65) for i in range(26)]
shuffle(letter_upper)
letter_lower = [chr(ord(alp) + 32) for alp in letter_upper]

f = open("mybook.txt", 'r')
new_f = open("MyNewBook.txt", 'w')

while(1):
    line = f.readline()
    new_line = ""
    
    if not line :
        break
    for char in line:
        if char.isupper() :
            new_line += letter_upper[ord(char) - 0x41]
        elif char.islower() :
            new_line += letter_lower[ord(char) - 0x61]
        else :
            new_line += char 
        
    new_f.write(new_line)    
