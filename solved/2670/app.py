from flask import Flask, request, jsonify, make_response
from urllib.parse import urlsplit
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import secrets
import threading
import hashlib

app = Flask(__name__)
app.secret_key = "kimboan"

COOKIE_NAME = "SESSION"
FLAG_VALUE = "FAKE_FLAG"

_store = {}
_lock = threading.RLock()

def newSid():
	return secrets.token_urlsafe(24)

def sha256_hex(s):
	return hashlib.sha256(s.encode("utf-8")).hexdigest()

@app.get("/login")
def login():
	sid = request.cookies.get(COOKIE_NAME)
	userId = request.args.get("id", "")
	password = request.args.get("password", "")

	resp = make_response(jsonify(ok=True))

	with _lock:
		if userId == "admin" and sha256_hex(password) == "80c0a354393511c1201de46b51ef4a2f009aab55e7a151fa413d5c260196f79f":
			if (not sid) or (sid not in _store):
				sid = newSid()
			_store[sid] = {"role": "admin"}
		else:
			sid = newSid()
			_store[sid] = {"role": "guest"}

	resp.set_cookie(COOKIE_NAME, sid, httponly=True, path="/")
	return resp    
    
@app.get("/flag")
def flag():
    sid = request.cookies.get(COOKIE_NAME)
    with _lock:
        if not sid or sid not in _store:
            return jsonify({"error": "no session"}), 401
            
        if _store[sid].get("role") == "admin" :        
        
            return jsonify({"flag": FLAG_VALUE}), 200
            
        return jsonify(_store[sid]), 200    

@app.get("/")
def root():
	return "hello~"

@app.get("/xss")
def xss():
	payload = request.args.get("payload", "")
    
	blacklist = [
		"<img", "</img",
		"<svg", "</svg",
		"<iframe", "</iframe",
		"<object", "</object",
		"<embed", "</embed",
		"<link", "</link",
		"<meta", "</meta",
		"<style", "</style",
		"<base", "</base",
		"<form", "</form",
		"<input", "</input",
		"<textarea", "</textarea",
		"<button", "</button",
		"<video", "</video",
		"<audio", "</audio",
		"<source", "</source",
		"<track", "</track",
		"<math", "</math",
		"<applet", "</applet",
		"<frame", "</frame",
		"<frameset", "</frameset",
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
		"onfocus=",
		"onblur=",
		"onsubmit=",
        "window",
		"oninput=",
		"onchange=",
		"onkeydown=",
		"onkeypress=",
		"onkeyup=",
		"srcdoc=",
		"javascript:",
		"vbscript:",
		"data:",
		"document.cookie",
		"eval(",
		"settimeout(",
		"setinterval(",
        "[",
        "/*",
        "*/"
	]


	t = payload.lower()

	for bad in blacklist:
		if bad in t:
			return "melong"
            
	return payload

@app.get("/admin")
def testPage():
    raw_path = request.args.get("path", "")

    if not raw_path:
        return "missing path", 400

    s = urlsplit(raw_path)
    if s.scheme or s.netloc or raw_path.startswith("//") or ("\r" in raw_path or "\n" in raw_path):
        return "only path is allowed", 400

    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path

    BASE = "http://localhost:5000"
    target = BASE + raw_path
    login_url = BASE + "/login?id=admin&password=[FAKE_PASSWORD]"

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")

    driver = None

    try:
        driver = webdriver.Chrome(options=opts)

        driver.get(BASE + "/")
        driver.get(target)
        time.sleep(5)

        driver.get(login_url)
        time.sleep(1)

        return jsonify({"success": True})
    except Exception:
        return jsonify({"success": False}), 500
    finally:
        if driver:
            driver.quit()

if __name__ == "__main__":
	app.run("0.0.0.0", 5000, threaded=True, use_reloader=False)
