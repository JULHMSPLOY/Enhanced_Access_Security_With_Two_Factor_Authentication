from flask import Flask, render_template, request, redirect, url_for, session, flash
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

# user
USERS = {
    "user": {
        "password": "123456789",   #  (plaintext)
        "display": "User"
    }
}

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = USERS.get(username)
        if user and password == user["password"]:
            session["username"] = username
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html", demo_type="No MFA / No Rate Limit")

@app.route("/home")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("home.html", username=USERS[session["username"]]["display"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, port=5001)
