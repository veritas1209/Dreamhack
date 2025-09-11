from Crypto.Util.number import bytes_to_long
import random

unit1 = ["","십","백","천"]
unit2 = ["","만","억","조","경","해","자","양","구","간","정","재","극","항하사","아승기","나유타","불가사의","무량대수"]

flag = bytes_to_long(b'DH{fake_flag}')

def HACKcrypt(pt,base=10):
    ct = ''
    if base == 10:
        pt = str(pt)[::-1]
        for i in range(0,len(pt),4):
            ct += unit2[i//4][::-1]
            for j in range(4):
                if pt[i+j] != '0':
                    ct += unit1[j]
                    if random.randrange(1,6) == 1:
                        ct += "핵" # HACK!!
                    else:
                        ct += pt[i+j]
        return ct[::-1]
    
    if base == 2:
        pt = bin(pt)[2:]
        for i in range(len(pt)):
            if random.randrange(1,6) == 1:
                ct += "핵" # HACK!!
            else:
                ct += pt[i]
        return ct

print(HACKcrypt(flag,10))
print(HACKcrypt(flag,2))

# OUTPUT
# 핵천7백1십2무량대수7천2백8십5불가사의8백5십나유타4천3백핵십핵아승기1천7백8십2항하사6천핵백핵십3극3천핵백9십핵재1천핵백핵십6정5천핵백4십핵간핵백1십구6천7백8십양8천2백5십6자3천핵백7십핵해3천핵경핵천5백9십1조9천4백6십3억8천5백5십만6천1백7십3
# 100핵1핵0010핵10핵00111101핵01핵01000001핵핵000핵10핵0111010핵1111010핵0핵0000핵10001핵10001000핵0111110핵11100100110000011핵0핵01010111110111001핵핵01100핵001101100핵111011000핵1001101011핵핵1011101핵001001핵0핵001핵핵00핵0011010100111핵110011111100핵핵1111001111핵1핵핵111핵01