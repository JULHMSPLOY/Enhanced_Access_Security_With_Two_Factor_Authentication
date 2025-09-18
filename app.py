from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
import os

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.urandom(24)

# ตัวอย่าง user แบบง่าย (demo)
USER = {
    "username": "student",
    "password": "123456"
}

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == USER["username"] and password == USER["password"]:
            # สร้าง secret เฉพาะ session นี้ (จริงควรเก็บต่อ user ใน DB)
            secret = pyotp.random_base32()
            session["username"] = username
            session["secret"] = secret

            # สร้าง TOTP object และรหัสปัจจุบัน
            totp = pyotp.TOTP(secret)
            otp_now = totp.now()
            # สำหรับ demo: พิมพ์ OTP ใน terminal (หรือส่งจริงทาง email/sms)
            print("=== Demo OTP (TOTP) ===", otp_now)
            # เก็บ timestamp/otp ใน session ถ้าต้องการตรวจสอบเพิ่มเติม
            return redirect(url_for("verify"))
        else:
            error = "Username หรือ Password ไม่ถูกต้อง"
    return render_template("login.html", error=error)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "username" not in session or "secret" not in session:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        secret = session.get("secret")
        totp = pyotp.TOTP(secret)
        if totp.verify(otp):  # ตรวจ TOTP
            # Login สำเร็จจริง -> ทำสิ่งที่ต้องการ
            # (ในระบบจริงจะรีเซ็ต session ข้อมูลที่จำเป็น)
            return render_template("success.html", username=session.get("username"))
        else:
            error = "รหัส OTP ไม่ถูกต้อง หรือหมดเวลา"
            return render_template("fail.html", error=error)
    return render_template("verify.html", username=session.get("username"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
