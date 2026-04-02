from flask import Flask, render_template, request, redirect, url_for, abort, flash
from urllib.parse import unquote
import subprocess
import os
import sys

app = Flask(__name__)
app.secret_key = os.urandom(16)

reports = []

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
BOT_PATH = os.path.join(PROJECT_ROOT, "private", "bot.py")
PYTHON_BIN = sys.executable


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", reports=reports)


@app.route("/submit", methods=["POST"])
def submit():
    css = request.form.get("css", "")

    if not css:
        flash("CSS is required.")
        return redirect(url_for("index"))

    if len(css) > 5000:
        flash("CSS is too long.")
        return redirect(url_for("index"))

    reports.append(css)
    idx = len(reports) - 1
    return redirect(url_for("view_report", idx=idx))


@app.route("/view/<int:idx>", methods=["GET"])
def view_report(idx: int):
    if idx < 0 or idx >= len(reports):
        abort(404)

    css = reports[idx]
    flag_value = request.cookies.get("flag", "guest")
    flag_value = unquote(flag_value)

    return render_template(
        "report_view.html",
        css=css,
        flag_value=flag_value,
        idx=idx,
    )


@app.route("/report/<int:idx>", methods=["POST"])
def report_to_admin(idx: int):
    if idx < 0 or idx >= len(reports):
        abort(404)

    target_url = f"{BASE_URL}/view/{idx}"

    try:
        subprocess.Popen(
            [PYTHON_BIN, BOT_PATH, target_url],
            cwd=PROJECT_ROOT,
        )
        flash("Reported to admin.")
    except Exception:
        flash("Failed to report to admin.")

    return redirect(url_for("view_report", idx=idx))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)