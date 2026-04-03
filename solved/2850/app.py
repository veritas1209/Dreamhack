from flask import Flask, request, render_template
import requests
import time

app = Flask(__name__)

server_res = {
    "current": 0,
    "max": 220913,
    "status": "Healthy",
    "flag": "SP{this_is_test_flag}"
}

@app.before_request
def handle_all_requests():
    client_ip = request.remote_addr

    if client_ip not in ['127.0.0.1', '::1']:
        time.sleep(2)

    if request.method == 'GET':
        server_res["current"] += 1
        if server_res["current"] >= server_res["max"]:
            server_res["status"] = "CRITICAL - OVERHEAT"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send')
def send():
    res_text = ""

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    run = request.args.get('run')

    if run == 'true':
        try:
            full_url = f"http://{ip}"
            r = requests.get(full_url, timeout=1, headers=request.headers)
            res_text = f"Relayed via {ip}: {r.status_code}"
        except Exception as e:
            res_text = f"Error: {str(e)}"

    return render_template('send.html', ip=ip, res_text=res_text)
@app.route('/check')
def check():
    is_done = server_res["current"] >= server_res["max"]
    return render_template('check.html', res=server_res, is_done=is_done)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
