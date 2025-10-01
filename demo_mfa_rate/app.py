from flask import Flask, render_template, request, redirect, url_for, session, flash
import os, pyotp, qrcode, io, base64
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

# เปิดให้เห็น headers ของ rate-limit เวลา debug
app.config["RATELIMIT_HEADERS_ENABLED"] = True

# syntax สำหรับ Flask-Limiter 3.x
limiter = Limiter(
    get_remote_address,
    default_limits=["10 per minute", "100 per hour"]
)
limiter.init_app(app)

#user
USERS = {
    "user": {
        "password_hash": generate_password_hash("123456789"),
        "display": "user",
        "mfa_secret": None,
        "mfa_enabled": False
    }
}

def generate_qr_data_uri(secret, username):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Demo")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    data = base64.b64encode(buf.getvalue()).decode('ascii')
    return f"data:image/png;base64,{data}"

# ---------------- Routes ----------------

@app.route("/", methods=["GET","POST"])
@limiter.limit("3 per minute")   # จำกัด login ผิดได้ไม่เกิน x ครั้งต่อนาที
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["pre_mfa_user"] = username
            if user["mfa_enabled"]:
                return redirect(url_for("mfa_verify"))
            else:
                return redirect(url_for("mfa_setup"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html", demo_type="MFA + Rate Limit")

@app.route("/mfa_setup", methods=["GET","POST"])
def mfa_setup():
    username = session.get("pre_mfa_user")
    if not username:
        return redirect(url_for("login"))
    user = USERS[username]

    if request.method == "POST":
        # ใช้ secret จาก session ไม่สุ่มใหม่
        secret = session.get("temp_secret")
        if not secret:
            flash("Session lost. Please try again.", "danger")
            return redirect(url_for("login"))

        user["mfa_secret"] = secret
        user["mfa_enabled"] = True
        session["username"] = username
        session.pop("pre_mfa_user", None)
        session.pop("temp_secret", None)
        flash("2FA enabled. You are logged in.", "success")
        return redirect(url_for("home"))

    # GET: สร้าง secret แล้วเก็บใน session
    temp_secret = pyotp.random_base32()
    session["temp_secret"] = temp_secret
    qr = generate_qr_data_uri(temp_secret, username)
    return render_template("mfa_setup.html", qr_data=qr, secret=temp_secret)

@app.route("/mfa_verify", methods=["GET","POST"])
@limiter.limit("5 per 10 minutes")   # จำกัด OTP ผิด 5 ครั้ง/10 นาที
def mfa_verify():
    username = session.get("pre_mfa_user")
    if not username:
        return redirect(url_for("login"))
    user = USERS[username]
    if request.method == "POST":
        otp = request.form.get("otp","").strip()
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(otp):
            session["username"] = username
            session.pop("pre_mfa_user", None)
            return redirect(url_for("home"))
        else:
            flash("Invalid or expired OTP", "danger")
    return render_template("mfa_verify.html")

@app.route("/home")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("home.html", username=USERS[session["username"]]["display"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template(
        "429.html",
        error="Too Many Requests",
        description="กรุณารอซักครู่ก่อนลองใหม่อีกครั้ง",
        limit=e.description  # จะได้ข้อความจาก limiter ด้วย
    ), 429

if __name__ == "__main__":
    app.run(debug=True, port=5002)
