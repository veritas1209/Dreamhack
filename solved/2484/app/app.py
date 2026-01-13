from flask import Flask, render_template, request, jsonify, redirect
import subprocess
import os
from werkzeug.utils import secure_filename
import umjunsik
import re

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/tmp/umm_uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return redirect('/umm')


@app.route('/umm', methods=['GET', 'POST'])
def umm():
    if request.method == 'GET':
        return render_template('umm.html')

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'umm.....'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'ummm..'}), 400

        if not file.filename.endswith('.umm'):
            return jsonify({'error': 'Only umm....'}), 400

        # Save the uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            result = subprocess.run(['umjunsik', filepath], capture_output=True, text=True)

            banned = [
                ' ', ';', '&', '|', '`', '\n', '<', '>', '{', '}', '[', ']', '(', ')', "'", '*', '#', '@', '!', '.', '%', '\\', '+', '-', '$', '_',
                'flag', 'cat', 'python', 'tee', 'find', 'locate', 'strings', 'xxd', 'od', 'nl', 'hexdump', 'tac', 'rev', 'cut',
                'tail', 'less', 'more', 'exec', 'import', 'open', 'subprocess', 'os', 'sed', 'awk', 'paste', 'bin', 'bash', 'sh', 'touch', 'mv',
                'cp', 'ln', 'dd', 'ls', 'base64', 'print', 'system', 'file', 'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'xz',
            ]

            if any(item in result.stdout.lower() for item in banned):
                return jsonify({'error': 'Umm!!'}), 400

            cmd = result.stdout.strip()

            final_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            return jsonify({
                'umjunsik_output': cmd,
                'execution_result': final_result.stdout,
                'execution_error': final_result.stderr
            })

        except subprocess.TimeoutExpired:
            return jsonify({'error': 'ummm....'}), 500
        except Exception as e:
            return jsonify({'error': 'umm...'}), 500
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
