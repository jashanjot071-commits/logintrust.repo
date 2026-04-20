from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
import subprocess
import os
import re
import logging
import bcrypt
from supabase import create_client

# ================= APP SETUP ================= #

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

app.secret_key = "my_super_secret_key_123"

SUPABASE_URL = "https://ogqrzdxdxbaeuoqvhbnr.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9ncXJ6ZHhkeGJhZXVvcXZoYm5yIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ2MTkxNjYsImV4cCI6MjA5MDE5NTE2Nn0.Bz97vHYFnXqo0iixYSLUcaIzEgOMTqBO9Atq1R_FvwQ"

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase credentials missing.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ================= LOGGING ================= #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ================= AUTH DECORATOR ================= #

def login_required(f):
    """Decorator to protect routes that require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ================= AUTH ROUTES ================= #

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # --- Input validation ---
        if not username or not password:
            return render_template("register.html", error="Username and password are required.")

        if len(password) < 8:
            return render_template("register.html", error="Password must be at least 8 characters.")

        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            return render_template(
                "register.html",
                error="Username must be 3–30 characters and contain only letters, numbers, or underscores."
            )

        # --- Check for duplicate username ---
        try:
            existing = supabase.table("users").select("username").eq("username", username).execute()
            if existing.data:
                return render_template("register.html", error="Username already taken.")

            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            supabase.table("users").insert({
                "username": username,
                "password": hashed.decode("utf-8")
            }).execute()

            logger.info(f"New user registered: {username}")
            return redirect(url_for("login"))

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return render_template("register.html", error="Registration failed. Please try again.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("scanner"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return render_template("login.html", error="Username and password are required.")

        try:
            result = supabase.table("users").select("*").eq("username", username).execute()

            if result.data:
                stored_hash = result.data[0]["password"]

                if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                    session.clear()
                    session["user"] = username
                    session.permanent = True

                    # 🔥 REDIRECT TO SCANNER
                    return redirect(url_for("scanner"))

            return render_template("login.html", error="Invalid credentials.")

        except Exception as e:
            return render_template("login.html", error="Login failed.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    user = session.get("user", "unknown")
    session.clear()
    logger.info(f"User logged out: {user}")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])


# ================= MAIN PAGES ================= #

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scanner")
@login_required
def scanner():
    return render_template("scanner.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ================= SCANNER API ================= #
SAFE_URL_PATTERN = re.compile(
    r'(?!(?:10|127|169\.254|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)'
    r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
    r'$'
)

@app.route("/scan-api", methods=["POST"])
@login_required
def scan():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body. Expected JSON."}), 400

    scan_url = data.get("url", "").strip()

    if not scan_url:
        return jsonify({"error": "No URL provided."}), 400

    # Auto add https
    if not scan_url.startswith(("http://", "https://")):
        scan_url = "https://" + scan_url

    # Validate
    if not SAFE_URL_PATTERN.match(scan_url):
        return jsonify({"error": "Invalid or disallowed URL format."}), 400

    if len(scan_url) > 2048:
        return jsonify({"error": "URL too long."}), 400

    try:
        # ✅ FIXED PATH
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(BASE_DIR, "scan.sh")

        if not os.path.exists(script_path):
            return jsonify({"error": "scan.sh not found"}), 500

        # ✅ RUN SCRIPT
        result = subprocess.run(
            ["bash", script_path, scan_url],
            capture_output=True,
            text=True,
            timeout=180
        )

        output = result.stdout.strip()
        error_output = result.stderr.strip()

        print("==== SCAN OUTPUT ====")
        print(output)
        print("==== ERROR OUTPUT ====")
        print(error_output)
        print("=====================")

        # 🔥 DEBUG LOG
        logger.info(f"STDOUT:\n{output}")
        logger.warning(f"STDERR:\n{error_output}")

        # ❗ DO NOT FAIL HERE
        if not output:
            output = "No output from script."

        # ✅ SCORE PARSE (SAFE)
        score = 0
        score_match = re.search(r'risk\s*score\s*[:=]?\s*(\d+)', output, re.IGNORECASE)
        if score_match:
            score = int(score_match.group(1))
        else:
            # fallback (count warnings)
            score = output.lower().count("risk") + output.lower().count("warning")

        # ✅ REASONS
        reasons = [
            line.strip()[2:]
            for line in output.splitlines()
            if line.strip().startswith("- ")
        ]

        # ✅ VERDICT
        if score >= 8:
            verdict = "Critical"
        elif score >= 6:
            verdict = "Dangerous"
        elif score >= 4:
            verdict = "High risk"
        elif score >= 2:
            verdict = "Suspicious" 
        else:
            verdict = "safe"

        return jsonify({
            "score": score,
            "verdict": verdict,
            "reasons": reasons if reasons else ["Scan completed."],
            "report": output
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out (180s)."}), 500

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "Server error"}), 500

# ================= RUN ================= #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))