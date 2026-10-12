import os
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, flash, redirect, render_template,
    request, session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash

app = Flask(__name__)

secret = os.environ.get("FLASK_SECRET_KEY")
if not secret or len(secret) < 32:
    raise RuntimeError("Configure FLASK_SECRET_KEY com pelo menos 32 caracteres.")

app.config.update(
    SECRET_KEY=secret,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)

CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected_username = os.environ.get("APP_USERNAME", "")
        password_hash = os.environ.get("APP_PASSWORD_HASH", "")

        if (
            expected_username
            and username == expected_username
            and password_hash
            and check_password_hash(password_hash, password)
        ):
            session.clear()
            session["authenticated"] = True
            session["username"] = username
            session.permanent = True

            destination = request.args.get("next", "")
            if destination.startswith("/") and not destination.startswith("//"):
                return redirect(destination)
            return redirect(url_for("dashboard"))

        flash("Usuário ou senha inválidos.", "error")

    return render_template("login.html")


@app.get("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        username=session.get("username", "usuário"),
    )


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("Você saiu do sistema com segurança.", "success")
    return redirect(url_for("login"))


@app.errorhandler(429)
def too_many_requests(error):
    return (
        render_template(
            "error.html",
            code=429,
            message="Muitas tentativas. Aguarde antes de tentar novamente.",
        ),
        429,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

    