import os
import time
import secrets
import random
import threading
from flask import Flask, request, jsonify, make_response, render_template

FLAG_PRICE = 1_000_000_000

app = Flask(__name__)

_sessions = {}
_lock = threading.Lock()

FLAG = 'DH{This_is_fake_flag}'

def _new_session():
    sid = secrets.token_urlsafe(16)
    r = random.Random() 
    _sessions[sid] = {
        "points": 0,
        "rng": r,
        "bets": 0,
    }
    return sid

def _get_session():
    sid = request.cookies.get("sid", "")
    with _lock:
        if not sid or sid not in _sessions:
            sid = _new_session()
        return sid, _sessions[sid]

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/", methods=["GET"])
def index():
    sid, s = _get_session()
    resp = make_response(render_template("index.html"))
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp

@app.route("/api/me", methods=["GET"])
def me():
    sid, s = _get_session()
    resp = jsonify(
        ok=True,
        points=s["points"],
        bets=s["bets"],
        flag_price=FLAG_PRICE,
    )
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp

@app.route("/api/bet", methods=["POST"])
def bet():
    sid, s = _get_session()

    data = request.get_json(silent=True) or {}
    guess = data.get("guess", None)

    if not isinstance(guess, int):
        return jsonify(ok=False, error="guess must be an integer (0..2^32-1)"), 400
    if guess < 0 or guess > 0xFFFFFFFF:
        return jsonify(ok=False, error="guess out of range (0..2^32-1)"), 400

    with _lock:
        bet_no = s["bets"] + 1

        raw = s["rng"].getrandbits(32)
        roll = (raw ^ bet_no) & 0xFFFFFFFF

        s["bets"] = bet_no

        win = (guess == roll)
        if win:
            s["points"] += 10_000_000

        points_now = s["points"]
        bets_now = s["bets"]

    return jsonify(
        ok=True,
        bet_no=bet_no,
        roll=roll,
        win=win,
        jackpot=FLAG_PRICE,
        points=points_now,
        bets=bets_now,
    )

@app.route("/api/buy_flag", methods=["POST"])
def buy_flag():
    sid, s = _get_session()
    with _lock:
        if s["points"] < FLAG_PRICE:
            return jsonify(ok=False, error="Not enough points."), 403
        s["points"] -= FLAG_PRICE
    return jsonify(ok=True, flag=FLAG)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)