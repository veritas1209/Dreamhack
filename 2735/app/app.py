import requests
from flask import Flask, request, render_template_string
import urllib.parse

app = Flask(__name__)

def is_safe_url(url):
    blacklist = [
        'localhost', '127.', '192.168.', '10.', '172.', 'docker'
    ]
    
    parsed = urllib.parse.urlparse(url)
    target = parsed.hostname if parsed.hostname else url

    for blocked in blacklist:
        if blocked in target.lower():
            return False
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        url = request.form.get('url', '')
        method = request.form.get('method', 'GET').upper()
        data = request.form.get('data', '')

        if not url.startswith('http://') and not url.startswith('https://'):
            return "Invalid URL scheme. Only HTTP/HTTPS allowed."

        if not is_safe_url(url):
            return "Access to internal network is prohibited."

        try:
            if method == 'GET':
                response = requests.get(url, timeout=3, allow_redirects=False)
            elif method == 'POST':
                headers = {'Content-Type': 'application/json'}
                response = requests.post(url, data=data, headers=headers, timeout=3, allow_redirects=False)
            else:
                return "Unsupported HTTP method."
            
            result = response.text
        except requests.exceptions.RequestException:
            result = "Failed to connect to the target URL."

    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>API Previewer</title>
        <style>body { font-family: sans-serif; margin: 40px; }</style>
    </head>
    <body>
        <h2>Internal API Testing Tool</h2>
        <form method="POST">
            <div>
                <label>Method:</label>
                <select name="method">
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                </select>
            </div><br>
            <div>
                <label>URL:</label>
                <input type="text" name="url" style="width: 300px;" placeholder="http://example.com/api" required>
            </div><br>
            <div>
                <label>POST Data (JSON):</label><br>
                <textarea name="data" rows="4" cols="40" placeholder='{"key": "value"}'></textarea>
            </div><br>
            <button type="submit">Send Request</button>
        </form>
        <hr>
        <h3>Response:</h3>
        <pre>{{ result }}</pre>
    </body>
    </html>
    """
    return render_template_string(template, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
