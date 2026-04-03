from flask import Flask, request, render_template, send_from_directory
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' in request.files:
        file = request.files['file']
        file.save(os.path.join(UPLOAD_FOLDER, 'wargame'))
        return render_template('index.html', msg="File uploaded.", status="success"), 200
    return render_template('index.html', msg="ERROR: No file selected.", status="error"), 400

@app.route('/downloads/<filename>')
def download_file(filename):
    if (".." in filename) or ("/" in filename):
        return "No Hack~ ^_^"
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0',port=5000)