from flask import Flask, render_template, request
import re
import math

app = Flask(__name__)

# small common password blacklist (expand if you like)
COMMON_PASSWORDS = {
    "123456","password","12345678","qwerty","123456789","12345","1234",
    "111111","1234567","dragon","123123","baseball","abc123","football",
    "monkey","letmein","shadow","master","666666","qwertyuiop"
}

def analyze_password(password: str):
    """Analyze password and return a dictionary with score, rating, issues, entropy, suggestions."""
    if password is None:
        password = ""
    length = len(password)
    has_lower = re.search(r'[a-z]', password) is not None
    has_upper = re.search(r'[A-Z]', password) is not None
    has_digit = re.search(r'\d', password) is not None
    has_symbol = re.search(r'[^A-Za-z0-9]', password) is not None

    issues = []
    
    if length < 8:
        issues.append("Password is shorter than 8 characters.")
    if not has_lower:
        issues.append("Password has no lowercase letters.")
    if not has_upper:
        issues.append("Password has no uppercase letters.")
    if not has_digit:
        issues.append("Password does not contain any digits.")
    if not has_symbol:
        issues.append("Password does not contain any symbols like !@#$%&*.")


    pw_lower = password.lower()
    if pw_lower in COMMON_PASSWORDS or pw_lower.isnumeric():
        issues.append("Password is too common or numeric-only.")

    # Score calculation (0 - 100)
    score = 0
    # length contribution: each char after 7 gives up to 40 points
    if length > 7:
        score += min((length - 7) * 4, 40)
    # variety
    score += 10 if has_lower else 0
    score += 10 if has_upper else 0
    score += 10 if has_digit else 0
    score += 10 if has_symbol else 0

    # estimate entropy (bits)
    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_symbol: pool += 32
    entropy = length * (math.log2(pool) if pool > 0 else 0)
    entropy_points = min(int(entropy // 6), 10)  # ~6 bits per point, cap at 10
    score += entropy_points

    # penalize extremely common passwords
    if pw_lower in COMMON_PASSWORDS or pw_lower.isnumeric():
        score = min(score, 10)

    score = max(0, min(100, int(score)))

    if pw_lower in COMMON_PASSWORDS or pw_lower.isnumeric():
        rating = "Very Weak"
    elif score < 40:
        rating = "Weak"
    elif score < 70:
        rating = "Medium"
    else:
        rating = "Strong"

    suggestions = []
    if length < 12:
        suggestions.append("Consider using 12+ characters for better security.")
    if not has_symbol:
        suggestions.append("Add symbols to increase unpredictability.")
    if not (has_lower and has_upper):
        suggestions.append("Mix uppercase and lowercase letters.")
    if not has_digit:
        suggestions.append("Add numbers to the password.")
    if pw_lower in COMMON_PASSWORDS:
        suggestions.append("Avoid common passwords (e.g., 'password', '123456').")

    return {
        "password": password,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": score,
        "rating": rating,
        "issues": issues,
        "entropy": round(entropy, 2),
        "suggestions": suggestions
    }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    pw = request.form.get("password", "")
    result = analyze_password(pw)
    # Do NOT log or send real passwords anywhere in production.
    # Here we return results only for local demo/testing.
    return render_template("result.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
