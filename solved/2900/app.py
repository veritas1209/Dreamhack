from flask import Flask, request, render_template, session, redirect
import os
import secrets
import string

bang = Flask(__name__)
bang.secret_key = os.environ.get("SECRET_KEY", "replace_this_with_secret")


def generate_secure_password(length=64):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))


somw = generate_secure_password(128)

ACCOUNTS = {
    "guest": {"pw": "guest", "bal": 5000, "history": []},
    "me": {"pw": "me", "bal": 0, "history": []},
    "richman": {"pw": somw, "bal": 1000000, "history": []}
}

FLAG = "DH{**fakeflag**}"


@bang.route('/')
def none():
    return render_template('none.html')


@bang.route('/login', methods=['GET', 'POST'])
def login():
    msg = None

    if request.method == 'GET':
        return render_template('login.html', msg=msg)

    name = request.form.get("username", "").strip()
    pw = request.form.get("userpw", "")

    if name not in ACCOUNTS:
        msg = "User does not exist"
        return render_template('login.html', msg=msg)

    if ACCOUNTS[name]["pw"] != pw:
        msg = "Incorrect password"
        return render_template('login.html', msg=msg)

    session["username"] = name
    balance = ACCOUNTS[name]["bal"]

    return render_template('deposit.html', balance=balance)


@bang.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')


@bang.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'username' not in session:
        return redirect('/login')

    user = session['username']

    if request.method == 'GET':
        bal = ACCOUNTS[user]["bal"]
        return render_template('deposit.html', balance=bal)

    who = request.form.get("username", "").strip()
    mon = request.form.get("how_much", "0").strip()

    try:
        mon = int(mon)
        if mon <= 0:
            return "Enter 1 or more numbers"
    except ValueError:
        return "Only numbers"

    if who not in ACCOUNTS:
        return "User does not exist"

    if who == user:
        bal = ACCOUNTS[user]["bal"]
        return render_template('deposit.html', balance=bal)

    if ACCOUNTS[user]["bal"] < mon:
        bal = ACCOUNTS[user]["bal"]
        return render_template('deposit.html', balance=bal, msg="no money 💸")

    ACCOUNTS[user]["bal"] -= mon
    ACCOUNTS[who]["bal"] += mon

    ACCOUNTS[user]["history"].append(f"Sent {mon}won -> {who}")
    ACCOUNTS[who]["history"].append(f"Deposit: +{mon}won <- {user}")

    if ACCOUNTS["me"]["bal"] >= 1_000_000:
        return render_template(
            'deposit.html',
            balance=ACCOUNTS[user]["bal"],
            msg=f"🤨 FLAG: {FLAG}"
        )

    bal = ACCOUNTS[user]["bal"]

    return render_template(
        'deposit.html',
        balance=bal,
        msg=f"{who}님에게 {mon}원을 보냈습니다 💰"
    )


@bang.route('/history', methods=['GET'])
def history():
    if 'username' not in session:
        return redirect('/login')

    target = request.args.get('user', session['username']).strip()

    if target not in ACCOUNTS:
        return "User does not exist"

    requested_by = session['username']
    balance = ACCOUNTS[target]['bal']
    history_list = ACCOUNTS[target]['history']

    credential = {
        "username": target,
        "password": ACCOUNTS[target]['pw']
    }

    return render_template(
        'history.html',
        requested_by=requested_by,
        target=target,
        balance=balance,
        history=history_list,
        credential=credential
    )


if __name__ == "__main__":
    bang.run(host="0.0.0.0", port=5000, debug=True)