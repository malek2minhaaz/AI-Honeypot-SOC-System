from flask import Flask, render_template, request, jsonify, redirect, session
from datetime import datetime
from ai_analysis import analyze_attack
from ai_chat import ask_ai
from scanner import scan_website
import requests
import sqlite3

app = Flask(__name__)

# SECRET KEY
app.secret_key = "cybersecurity_secret_key"

# LOG FILES
HONEYPOT_LOG_FILE = "honeypot_logs.txt"
SCAN_LOG_FILE = "scan_logs.txt"


# HOME PAGE
@app.route("/")
def home():

    return render_template("index.html")


# USER SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username")

        email = request.form.get("email")

        password = request.form.get("password")

        confirm_password = request.form.get(
            "confirm_password"
        )

        # PASSWORD CHECK
        if password != confirm_password:

            return render_template(

                "signup.html",

                message="Passwords do not match"

            )

        try:

            conn = sqlite3.connect("users.db")

            cursor = conn.cursor()

            # CHECK EXISTING USER
            cursor.execute(

                """
                SELECT * FROM users
                WHERE username=? OR email=?
                """,

                (username, email)

            )

            existing_user = cursor.fetchone()

            if existing_user:

                conn.close()

                return render_template(

                    "signup.html",

                    message="Username or Email already exists"

                )

            # INSERT USER
            cursor.execute(

                """
                INSERT INTO users(
                    username,
                    email,
                    password,
                    joined_date
                )

                VALUES(?,?,?,?)
                """,

                (

                    username,

                    email,

                    password,

                    str(datetime.now())

                )

            )

            conn.commit()

            conn.close()

            return redirect("/user-login")

        except Exception as e:

            return render_template(

                "signup.html",

                message=str(e)

            )

    return render_template("signup.html")


# USER LOGIN
@app.route("/user-login", methods=["GET", "POST"])
def user_login():

    if request.method == "POST":

        username = request.form.get("username")

        password = request.form.get("password")

        conn = sqlite3.connect("users.db")

        cursor = conn.cursor()

        cursor.execute(

            """
            SELECT * FROM users
            WHERE username=? AND password=?
            """,

            (username, password)

        )

        user = cursor.fetchone()

        conn.close()

        # LOGIN SUCCESS
        if user:

            session["username"] = username

            return redirect("/user-dashboard")

        else:

            return render_template(

                "user_login.html",

                message="Invalid Username or Password"

            )

    return render_template("user_login.html")


# USER LOGOUT
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/user-login")


# USER DASHBOARD
@app.route("/user-dashboard")
def user_dashboard():

    if "username" not in session:

        return redirect("/user-login")

    return render_template(

        "user_dashboard.html",

        username=session["username"]

    )


# USER PROFILE
@app.route("/profile")
def profile():

    if "username" not in session:

        return redirect("/user-login")

    username = session["username"]

    conn = sqlite3.connect("users.db")

    cursor = conn.cursor()

    # USER INFO
    cursor.execute(

        """
        SELECT username, email, joined_date
        FROM users
        WHERE username=?
        """,

        (username,)

    )

    user = cursor.fetchone()

    # USER SCAN HISTORY
    cursor.execute(

        """
        SELECT website_url,
               threat_level,
               security_score,
               scan_date

        FROM scan_history

        WHERE username=?

        ORDER BY id DESC
        """,

        (username,)

    )

    scans = cursor.fetchall()

    conn.close()

    return render_template(

        "profile.html",

        username=user[0],

        email=user[1],

        joined_date=user[2],

        scans=scans

    )


# HONEYPOT ADMIN LOGIN
@app.route("/secure-admin")
def secure_admin():

    return render_template("login.html")


# WEBSITE SECURITY SCANNER
@app.route("/scan", methods=["GET", "POST"])
def scan():

    if "username" not in session:

        return redirect("/user-login")

    results = None

    if request.method == "POST":

        url = request.form.get("url")

        results = scan_website(url)

        # SAVE SCAN HISTORY
        if results and "error" not in results:

            try:

                conn = sqlite3.connect("users.db")

                cursor = conn.cursor()

                cursor.execute(

                    """
                    INSERT INTO scan_history(

                        username,

                        website_url,

                        threat_level,

                        security_score,

                        scan_date

                    )

                    VALUES(?,?,?,?,?)
                    """,

                    (

                        session["username"],

                        url,

                        results.get("threat_level", "Unknown"),

                        str(results.get("security_score", "0")),

                        str(datetime.now())

                    )

                )

                conn.commit()

                conn.close()

            except Exception as e:

                print("SCAN HISTORY ERROR:", e)

    return render_template(

        "scan.html",

        results=results

    )


# ADMIN LOGIN HANDLER
@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username")

    password = request.form.get("password")

    # REAL ADMIN LOGIN
    if username == "admin" and password == "secure123":

        session["admin"] = True

        return jsonify({

            "status": "SUCCESS",

            "redirect": "/soc-dashboard"

        })

    # REAL / FORWARDED IP
    ip_address = request.headers.get(

        "X-Forwarded-For",

        request.remote_addr

    )

    # LOCAL TESTING FIX
    if ip_address == "127.0.0.1":

        ip_address = "8.8.8.8"

    timestamp = datetime.now()

    # GEO IP LOOKUP
    try:

        geo_response = requests.get(

            f"http://ip-api.com/json/{ip_address}"

        )

        geo_data = geo_response.json()

        country = geo_data.get("country", "Unknown")

        city = geo_data.get("city", "Unknown")

        isp = geo_data.get("isp", "Unknown")

    except:

        country = "Unknown"

        city = "Unknown"

        isp = "Unknown"

    # DEFAULT THREAT
    threat_level = "LOW"

    attack_type = "Normal Activity"

    # SQL INJECTION DETECTION
    sql_payloads = [

        "' OR 1=1",

        "--",

        "UNION SELECT",

        "' OR '1'='1"

    ]

    for payload in sql_payloads:

        if payload.lower() in username.lower() or payload.lower() in password.lower():

            threat_level = "CRITICAL"

            attack_type = "SQL Injection Attempt"

    # BRUTE FORCE DETECTION
    suspicious_usernames = [

        "admin",

        "root",

        "administrator",

        "test",

        "guest"

    ]

    if username.lower() in suspicious_usernames:

        threat_level = "HIGH"

        attack_type = "Brute Force Attempt"

    # WEAK PASSWORD DETECTION
    weak_passwords = [

        "123456",

        "password",

        "admin123",

        "root",

        "1234",

        "qwerty",

        "letmein",

        "admin"

    ]

    if password.lower() in weak_passwords:

        threat_level = "HIGH"

        if attack_type == "Normal Activity":

            attack_type = "Weak Password Attack"

    # STORE HONEYPOT LOGS
    log_entry = f"""
Time: {timestamp}
IP: {ip_address}
Country: {country}
City: {city}
ISP: {isp}
Username: {username}
Password: {password}
Threat Level: {threat_level}
Attack Type: {attack_type}
-------------------------
"""

    with open(HONEYPOT_LOG_FILE, "a") as file:

        file.write(log_entry)

    return jsonify({

        "status": "CAPTURED",

        "redirect": "/captured"

    })


# SOC DASHBOARD
@app.route("/soc-dashboard")
def dashboard():

    if "admin" not in session:

        return redirect("/secure-admin")

    # HONEYPOT LOGS
    try:

        with open(HONEYPOT_LOG_FILE, "r") as file:

            honeypot_logs = file.read()

    except:

        honeypot_logs = ""

    # SCAN LOGS
    try:

        with open(SCAN_LOG_FILE, "r") as file:

            scan_logs = file.read()

    except:

        scan_logs = ""

    # AI ANALYSIS
    analysis = analyze_attack(

        honeypot_logs + "\n" + scan_logs

    )

    # TOTAL ATTACKS
    total_attacks = honeypot_logs.count("Username:")

    usernames = []

    for line in honeypot_logs.splitlines():

        if "Username:" in line:

            username = line.split("Username:")[1].strip()

            usernames.append(username)

    # UNIQUE USERS
    unique_user_count = len(set(usernames))

    # THREAT COUNTS
    high_threats = honeypot_logs.count(

        "Threat Level: HIGH"

    )

    critical_threats = honeypot_logs.count(

        "Threat Level: CRITICAL"

    )

    normal_threats = (

        total_attacks -

        high_threats -

        critical_threats

    )

    # USERNAME FREQUENCY
    username_counts = {}

    for user in usernames:

        if user in username_counts:

            username_counts[user] += 1

        else:

            username_counts[user] = 1

    # REGISTERED USERS
    conn = sqlite3.connect("users.db")

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT username, email, joined_date
        FROM users
        """

    )

    users = cursor.fetchall()

    conn.close()

    total_registered_users = len(users)

    return render_template(

        "dashboard.html",

        honeypot_logs=honeypot_logs,

        scan_logs=scan_logs,

        analysis=analysis,

        total_attacks=total_attacks,

        unique_user_count=unique_user_count,

        high_threats=high_threats,

        critical_threats=critical_threats,

        normal_threats=normal_threats,

        username_counts=username_counts,

        users=users,

        total_registered_users=total_registered_users

    )


# AI SECURITY ASSISTANT PAGE
@app.route("/ai-assistant")
def ai_page():

    if "username" not in session:

        return redirect("/user-login")

    return render_template("ai_assistant.html")


# AI ASSISTANT
@app.route("/ask_ai", methods=["POST"])
def ai_assistant():

    question = request.form.get("question")

    try:

        with open(HONEYPOT_LOG_FILE, "r") as file:

            honeypot_logs = file.read()

    except:

        honeypot_logs = ""

    try:

        with open(SCAN_LOG_FILE, "r") as file:

            scan_logs = file.read()

    except:

        scan_logs = ""

    combined_logs = honeypot_logs + "\n" + scan_logs

    answer = ask_ai(question, combined_logs)

    return jsonify({

        "response": answer

    })


# CAPTURED PAGE
@app.route("/captured")
def captured():

    return render_template("captured.html")


if __name__ == "__main__":

    app.run(debug=True)