#!/usr/bin/env python3
"""
Flask Login Server - Lab Environment
For educational security testing only
"""

from flask import Flask, request, redirect, render_template_string, session, make_response
import secrets
import time
import os

app = Flask(__name__)
# Use environment variable for secret key (best practice)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Load credentials from environment variables
VALID_USER = os.environ.get('LAB_USERNAME', 'admin')
VALID_PASS = os.environ.get('LAB_PASSWORD', '123456')

LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Lab Login</title></head>
<body>
  <h2>Login - Lab Environment</h2>
  <form method="post" action="/login">
    <input type="hidden" name="csrf_token" value="{{ csrf }}">
    <input type="text" name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <input type="submit" value="Login">
  </form>
  {% if error %}
    <p style="color:red;">{{ error }}</p>
  {% endif %}
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<h1>Dashboard</h1>
<p>Welcome, authenticated user</p>
<a href="/logout">Logout</a>
"""

@app.route("/", methods=["GET"])
def index():
    csrf = secrets.token_hex(16)
    session["csrf"] = csrf
    return render_template_string(LOGIN_TEMPLATE, csrf=csrf)

@app.route("/login", methods=["POST"])
def login():
    time.sleep(0.3)  # Anti-bruteforce delay

    csrf = request.form.get("csrf_token")
    if not csrf or csrf != session.get("csrf"):
        return "Invalid request", 403

    user = request.form.get("username", "")
    pwd = request.form.get("password", "")

    if user == VALID_USER and pwd == VALID_PASS:
        session["auth"] = True
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("SESSIONID", secrets.token_hex(16), httponly=True)
        return resp

    # Ambiguous error message
    csrf = secrets.token_hex(16)
    session["csrf"] = csrf
    return render_template_string(
        LOGIN_TEMPLATE,
        csrf=csrf,
        error="Authentication failed"
    ), 200

@app.route("/dashboard")
def dashboard():
    if not session.get("auth"):
        return redirect("/")
    return DASHBOARD_TEMPLATE

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    print("=" * 70)
    print(" LAB LOGIN SERVER")
    print(" For educational security testing only")
    print("=" * 70)
    print(f" Default credentials: {VALID_USER}:{VALID_PASS}")
    print(" Set LAB_USERNAME and LAB_PASSWORD env vars to customize")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)
