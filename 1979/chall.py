def checker(user_input):
    banned_alphabet="aefghmprvwxyAEFGHMPRVWXY"
    banned_character="'\"\\`:;/<>~!@#$%^&*|"
    for i in range(0,len(banned_alphabet),1):
        x=banned_alphabet[i]
        if x in user_input:
            return False
    for i in range(0,len(banned_character),1):
        x=banned_character[i]
        if x in user_input:
            return False
    return True
        
print("Welcome to Python Lipogram challenge!")
print("Show me your lipogram!")
x=input('> ')

result=checker(x)

if result==True:
    print("What a masterpiece! I gave you flag.",flush=True)
    flag = 'DH{**flag**}' # I gave! Take this.
    try:
        exec(x)
    except:
        pass
else:
    print("Not a valid lipogram!")