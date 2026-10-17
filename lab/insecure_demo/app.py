"""INTENTIONALLY VULNERABLE demo application.

    !!  This app is deliberately insecure.  It exists only so that the
    !!  scanner in ``soclab/vapt.py`` has something real to find, and so
    !!  that you can practise writing a finding and a fix.
    !!  It binds to 127.0.0.1 and must never be deployed anywhere.

The flaws on purpose:

  1. No security headers (CSP, HSTS, X-Frame-Options, ...)
  2. Session cookie without Secure / HttpOnly / SameSite
  3. Debug mode on, so tracebacks are rendered to the browser
  4. Directory-style file listing under /files
  5. A .env file left inside the web root
  6. A version banner in the Server header
  7. An IDOR: /profile?id=N returns any user's profile
  8. A hard-coded default credential (admin / admin123)

Run it with:

    python lab/insecure_demo/app.py            # http://127.0.0.1:5001
    python -m soclab vapt http://127.0.0.1:5001
"""

from __future__ import annotations

import os

from flask import Flask, Response, jsonify, request, session

app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "hardcoded-demo-secret-key"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")

# A deliberately insecure cookie policy.
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None

USERS = {
    "1": {"id": "1", "name": "Apoorva Ramesh", "email": "apoorva.r@example.in", "pan": "ABCDE1234F"},
    "2": {"id": "2", "name": "Sneha Iyer", "email": "sneha.i@example.in", "pan": "ZZZZZ9999K"},
    "3": {"id": "3", "name": "Manoj Kulkarni", "email": "manoj.k@example.in", "pan": "MMMMM5555N"},
}

SECRET_FILE = os.path.join(BASE_DIR, ".env")
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w", encoding="utf-8") as fh:
        fh.write("DB_PASSWORD=SuperSecret!123\nAPI_KEY=demo-only-not-real\n")


@app.route("/")
def index() -> Response:
    session["visits"] = session.get("visits", 0) + 1
    body = f"""<!doctype html>
<html><head><title>Acme Employee Portal</title></head>
<body>
  <h1>Acme Employee Portal</h1>
  <p>Demo application for security assessment practice.</p>
  <ul>
    <li><a href="/profile?id=1">Profile (IDOR demo)</a></li>
    <li><a href="/files/">File listing (misconfiguration demo)</a></li>
    <li><a href="/login">Login (default credential demo)</a></li>
  </ul>
  <p>Session visits: {session['visits']}</p>
</body></html>"""
    return Response(body, mimetype="text/html")


@app.route("/profile")
def profile() -> Response:
    # Flaw 7: no authorisation check - any id returns any profile.
    user_id = request.args.get("id", "1")
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@app.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if request.method == "GET":
        return Response(
            """<!doctype html><html><body>
            <h2>Login</h2>
            <form method="post">
              <input name="username" placeholder="username">
              <input name="password" type="password" placeholder="password">
              <button>Sign in</button>
            </form>
            <p>Hint for the lab: admin / admin123</p>
            </body></html>""",
            mimetype="text/html",
        )
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Flaw 8: hard-coded default credential and no lockout/rate limiting.
    if username == "admin" and password == "admin123":
        return jsonify({"status": "ok", "token": "demo-token-not-real"})
    return jsonify({"status": "failed"}), 401


@app.route("/files/")
def files() -> Response:
    # Flaw 4: directory listing.
    try:
        entries = sorted(os.listdir(FILES_DIR))
    except FileNotFoundError:
        entries = []
    rows = "".join(f"<li><a href='/files/{e}'>{e}</a></li>" for e in entries)
    return Response(
        f"<!doctype html><html><head><title>Index of /files/</title></head>"
        f"<body><h1>Index of /files/</h1><ul>{rows}</ul></body></html>",
        mimetype="text/html",
    )


@app.route("/<path:name>")
def root_files(name: str) -> Response:
    # Flaw 5: the .env file lives inside the web root and is served to anyone.
    safe = os.path.basename(name)
    path = os.path.join(BASE_DIR, safe)
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            return Response(fh.read(), mimetype="text/plain")
    return jsonify({"error": "not found"}), 404


@app.route("/files/<path:name>")
def file_download(name: str) -> Response:
    safe = os.path.basename(name)
    path = os.path.join(FILES_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    with open(path, "rb") as fh:
        return Response(fh.read(), mimetype="text/plain")


@app.errorhandler(500)
def handle_error(err):  # type: ignore[no-untyped-def]
    # Flaw 3: the debug traceback is rendered to the client.
    return Response(f"<pre>{err}</pre>", status=500, mimetype="text/html")


if __name__ == "__main__":
    print("=" * 64)
    print(" INTENTIONALLY VULNERABLE demo app - 127.0.0.1 only")
    print("=" * 64)
    app.run(host="127.0.0.1", port=5001, debug=True, use_reloader=False)
