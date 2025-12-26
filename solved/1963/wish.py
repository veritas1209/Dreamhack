banned='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()~`{}[]+-_=<>.,/?:;|'

print("Enter your wish!")
x=input('> ')

filtered=False
for i in range(0,len(banned),1):
    letter=banned[i]
    if letter in x:
        filtered=True
        break

if filtered==False:
    print("Wish granted!",flush=True)
    try:
        exec(eval(x))
    except:
        pass
else:
    print("Sorry, I didn't understand your wish.")