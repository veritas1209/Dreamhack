import os
import re
from flask import Flask, request, session, redirect, url_for, render_template
import mysql.connector

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "**REDACTED**")

COMMENT_RE = re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE)

def reject_sql_comments(s: str) -> bool:
    return bool(COMMENT_RE.search(s or ""))

def get_conn():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "user"),
        password=os.getenv("DB_PASS", "pass"),
        database=os.getenv("DB_NAME", "db"),
        autocommit=True,
    )

@app.get("/")
def index():
    return render_template("index.html", user=session.get("user"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("user"):
            return redirect(url_for("index"))
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    sql = "SELECT id, username FROM users WHERE username = %s AND password = %s LIMIT 1;"
    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, (username, password))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        session["user"] = row["username"]
        return redirect(url_for("index"))

    return render_template("login.html", error="Invalid username/password"), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.get("/search")
def search():
    q = request.args.get("q", "")

    if q == "":
        return render_template("search.html", q=q, q2=None, rows=[], error=None)

    q2 = q + q

    if reject_sql_comments(q):
        return render_template("search.html", q=q, q2=q2, rows=[], error="Comment tokens are not allowed."), 200

    sql = f"SELECT id, username FROM users WHERE username='{q2}' ORDER BY id ASC;"

    conn = get_conn()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql)
        rows = cur.fetchall()
        return render_template("search.html", q=q, q2=q2, rows=rows, error=None)
    except mysql.connector.Error:
        return render_template("search.html", q=q, q2=q2, rows=[], error="DB error occurred."), 200
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
