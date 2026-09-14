"""The basic HTML interface. Every page is server-rendered with Jinja2
(autoescape on), every form carries a CSRF token, and authentication is an
HttpOnly cookie holding the same short-lived access token the API uses."""
from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..services import documents as docs
from ..services import password_reset as recovery
from ..services.auth import AuthError, authenticate, page_auth_required, register_user
from ..services.cerebras import ChatUpstreamError
from ..services.chat import (
    CHAT_RATE_LIMIT,
    CHAT_RATE_SCOPE,
    CHAT_RATE_WINDOW,
    ChatValidationError,
    validate_chat_input,
)
from ..services.csrf import validate_csrf
from ..services.ratelimit import rate_limited
from ..services.security import PasswordPolicyError, create_access_token
from ..utils import clean_text, normalise_email
from .chat import UNAVAILABLE, ask_assistant
from .documents import attachment_response
from .messages import create_message, recent_messages

bp = Blueprint("pages", __name__)


def _set_auth_cookie(resp, user):
    resp.set_cookie(
        current_app.config["AUTH_COOKIE_NAME"],
        create_access_token(user),
        max_age=current_app.config["ACCESS_TOKEN_TTL"],
        httponly=True,
        secure=current_app.config["AUTH_COOKIE_SECURE"],
        samesite="Lax",
        path="/",
    )
    return resp


@bp.get("/")
def index():
    return render_template("index.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    validate_csrf()
    email = normalise_email(request.form.get("email"))
    full_name = clean_text(request.form.get("full_name"), 120)
    if email is None or full_name is None:
        flash("Please enter a valid email address and your name.", "error")
        return render_template("register.html"), 400
    try:
        register_user(email, full_name, request.form.get("password", ""))
    except PasswordPolicyError as exc:
        flash(str(exc), "error")
        return render_template("register.html"), 400
    except AuthError as exc:
        flash(exc.message, "error")
        return render_template("register.html"), exc.status
    db.session.commit()
    flash("Account created. You can log in now.", "ok")
    return redirect(url_for("pages.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    validate_csrf()
    email = normalise_email(request.form.get("email"))
    password = request.form.get("password", "")
    try:
        if email is None:
            raise AuthError("Invalid email or password", 401)
        user = authenticate(email, password)
    except AuthError as exc:
        db.session.commit()
        flash(exc.message, "error")
        return render_template("login.html"), exc.status
    db.session.commit()
    resp = make_response(redirect(url_for("pages.dashboard")))
    return _set_auth_cookie(resp, user)


@bp.post("/logout")
def logout():
    validate_csrf()
    resp = make_response(redirect(url_for("pages.login")))
    resp.delete_cookie(current_app.config["AUTH_COOKIE_NAME"], path="/")
    return resp


# --- account recovery (A.3.3): the pages behind the emailed link ---------
# GET and POST are separate view functions so the per-IP limit only counts
# submissions, and the reset pages are never cached (the token is in the URL).

@bp.get("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


@bp.post("/forgot-password")
@rate_limited(5, 300)
def forgot_password_submit():
    validate_csrf()
    email = normalise_email(request.form.get("email"))
    if email is not None:
        recovery.request_reset(email)
    flash(recovery.GENERIC_MESSAGE, "ok")            # same answer whether or not the address exists
    return redirect(url_for("pages.login"))


def _reset_page(token, status=200):
    resp = make_response(render_template("reset_password.html", token=token), status)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.get("/reset-password")
def reset_password():
    token = request.args.get("token", "")
    if recovery.find_valid_token(token) is None:
        return _reset_page(None, 400)
    return _reset_page(token)


@bp.post("/reset-password")
@rate_limited(10, 300)
def reset_password_submit():
    validate_csrf()
    token = request.form.get("token", "")
    new_password = request.form.get("new_password", "")
    if new_password != request.form.get("confirm_password", ""):
        flash("The two passwords do not match.", "error")
        return _reset_page(token, 400)
    try:
        recovery.reset_password(token, new_password)
    except recovery.ResetTokenError:
        return _reset_page(None, 400)
    except PasswordPolicyError as exc:
        flash(str(exc), "error")
        return _reset_page(token, 400)
    flash("Password updated. Please log in with your new password.", "ok")
    resp = make_response(redirect(url_for("pages.login")))
    resp.delete_cookie(current_app.config["AUTH_COOKIE_NAME"], path="/")   # this browser too
    return resp


@bp.get("/dashboard")
@page_auth_required()
def dashboard():
    user = g.current_user
    documents = [] if user.role == "admin" else docs.list_documents(user)
    return render_template("dashboard.html", documents=documents)


@bp.post("/dashboard/upload")
@page_auth_required(roles=("patient", "clinician"))
def upload():
    validate_csrf()
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("pages.dashboard"))
    try:
        docs.create_document(g.current_user, upload_file.filename, upload_file.read())
    except docs.FileValidationError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("pages.dashboard"))
    db.session.commit()
    flash("File uploaded.", "ok")
    return redirect(url_for("pages.dashboard"))


@bp.get("/download/<int:doc_id>")
@page_auth_required(roles=("patient", "clinician"))
def download(doc_id: int):
    doc, data = docs.read_document(g.current_user, doc_id)
    db.session.commit()
    return attachment_response(doc, data)


@bp.route("/board", methods=["GET", "POST"])
@page_auth_required()
def board():
    if request.method == "POST":
        validate_csrf()
        if create_message(g.current_user, request.form.get("body")) is None:
            flash("Message must be between 1 and 2000 characters.", "error")
        else:
            db.session.commit()
        return redirect(url_for("pages.board"))
    return render_template("board.html", messages=recent_messages())


@bp.route("/chat", methods=["GET", "POST"])
@page_auth_required(roles=("patient", "clinician"))
@rate_limited(
    CHAT_RATE_LIMIT,
    CHAT_RATE_WINDOW,
    key_func=lambda: f"user:{g.current_user.id}",
    scope=CHAT_RATE_SCOPE,
    methods=("POST",),
)
def chat():
    reply = error = None
    question = ""
    if request.method == "POST":
        validate_csrf()
        question = request.form.get("message", "")
        try:
            message, history = validate_chat_input({"message": question})
            reply = ask_assistant(g.current_user, message, history)
        except ChatValidationError as exc:
            error = str(exc)
        except ChatUpstreamError as exc:
            current_app.logger.warning("assistant unavailable: %s", exc)
            error = UNAVAILABLE
    return render_template("chat.html", reply=reply, error=error, question=question)
