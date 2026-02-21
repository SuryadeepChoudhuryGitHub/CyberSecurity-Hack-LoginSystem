from flask import Flask, render_template, request, jsonify
import sqlite3
import re
import math
import hashlib
import os

app = Flask(__name__)
DB_PATH = 'passwords.db'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def check_username_exists(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result is not None


def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("At least 8 characters required")
    if not re.search(r'[a-z]', password):
        errors.append("At least one lowercase letter required")
    if not re.search(r'[A-Z]', password):
        errors.append("At least one uppercase letter required")
    if not re.search(r'\d', password):
        errors.append("At least one digit required")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password):
        errors.append("At least one special character required")
    # Check for 2 consecutive same characters
    for i in range(len(password) - 1):
        if password[i] == password[i + 1]:
            errors.append("No two consecutive identical characters allowed")
            break
    return errors


def analyze_password(password):
    """Analyze password strength and return score, suggestions, crack time."""
    score = 0
    suggestions = []
    checks = {}

    # Length check
    length = len(password)
    checks['length'] = length >= 8
    if length >= 8:
        score += 20
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length < 8:
        suggestions.append("Use at least 8 characters")

    # Lowercase
    has_lower = bool(re.search(r'[a-z]', password))
    checks['lowercase'] = has_lower
    if has_lower:
        score += 10
    else:
        suggestions.append("Add lowercase letters")

    # Uppercase
    has_upper = bool(re.search(r'[A-Z]', password))
    checks['uppercase'] = has_upper
    if has_upper:
        score += 10
    else:
        suggestions.append("Add uppercase letters")

    # Digit
    has_digit = bool(re.search(r'\d', password))
    checks['digit'] = has_digit
    if has_digit:
        score += 10
    else:
        suggestions.append("Add at least one number")

    # Special character
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password))
    checks['special'] = has_special
    if has_special:
        score += 15
    else:
        suggestions.append("Add special characters (!@#$%^&*...)")

    # No consecutive same chars
    no_consec = True
    for i in range(len(password) - 1):
        if password[i] == password[i + 1]:
            no_consec = False
            break
    checks['no_consecutive'] = no_consec
    if no_consec:
        score += 15
    else:
        suggestions.append("Remove consecutive identical characters (e.g., 'aa', '11')")

    # Variety bonus
    char_set_size = 0
    if has_lower:
        char_set_size += 26
    if has_upper:
        char_set_size += 26
    if has_digit:
        char_set_size += 10
    if has_special:
        char_set_size += 32

    # Crack time estimate (brute force at 10 billion guesses/sec)
    if char_set_size > 0 and length > 0:
        combinations = char_set_size ** length
        guesses_per_second = 10_000_000_000  # modern GPU cluster
        seconds = combinations / guesses_per_second

        if seconds < 1:
            crack_time = "Instantly"
        elif seconds < 60:
            crack_time = f"{int(seconds)} seconds"
        elif seconds < 3600:
            crack_time = f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            crack_time = f"{int(seconds/3600)} hours"
        elif seconds < 2592000:
            crack_time = f"{int(seconds/86400)} days"
        elif seconds < 31536000:
            crack_time = f"{int(seconds/2592000)} months"
        elif seconds < 3153600000:
            crack_time = f"{int(seconds/31536000)} years"
        elif seconds < 3.154e12:
            crack_time = f"{int(seconds/3153600000)} thousand years"
        else:
            crack_time = "Millions of years"
    else:
        crack_time = "Instantly"

    # Clamp score
    score = min(score, 100)

    # Strength label
    if score < 30:
        strength = "Very Weak"
        color = "#ff2d55"
    elif score < 50:
        strength = "Weak"
        color = "#ff9500"
    elif score < 70:
        strength = "Moderate"
        color = "#ffcc00"
    elif score < 90:
        strength = "Strong"
        color = "#34c759"
    else:
        strength = "Very Strong"
        color = "#00c7be"

    # Additional suggestions
    if length < 12 and len(suggestions) == 0:
        suggestions.append("Increase to 12+ characters for extra security")
    if score >= 80 and not suggestions:
        suggestions.append("Excellent! Your password is very secure.")

    return {
        'score': score,
        'strength': strength,
        'color': color,
        'suggestions': suggestions,
        'crack_time': crack_time,
        'checks': checks
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    result = analyze_password(password)
    return jsonify(result)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400

    if check_username_exists(username):
        return jsonify({'success': False, 'message': 'Username already taken. Please choose another.'}), 409

    errors = validate_password(password)
    if errors:
        return jsonify({'success': False, 'message': 'Password does not meet requirements: ' + '; '.join(errors)}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  (username, hash_password(password)))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'Account created successfully for {username}!'})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Username already taken'}), 409


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
