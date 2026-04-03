from flask import Flask, render_template, request
import regex

app = Flask(__name__)

BUFFER_SIZE = 1210

@app.route('/', methods=['GET', 'POST'])
def index():
    msg = "입력을 기다리는 중..."
    current_len = 0
    flag = None
    
    if request.method == 'POST':
        user_input = request.form.get('data', '')

        if len(regex.findall(r'\X', user_input)) != 1:
            msg = "3rr0r: 한글자만 입력 가능합니다!"
        else:
            current_len = len(user_input.encode('utf-8'))
            
            if current_len >= BUFFER_SIZE:
                msg = "SUCCESS: BUFFER OVERFLOW!"
                with open("flag.txt", "r") as f:
                        flag = f.read()
            else:
                msg = f"입력: {user_input} | utf-8 길이: {current_len} bytes"

    percent = min(100, (current_len / BUFFER_SIZE) * 100)
    
    return render_template('index.html', 
                           current_len=current_len, 
                           max_size=BUFFER_SIZE, 
                           percent=percent, 
                           msg=msg, 
                           flag=flag)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
