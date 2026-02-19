from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import re
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey_change_in_production'

DB_PATH = 'passwords.db'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*()\[\],.?":{}|<>_\-\\\/`~+=;\'@]', password):
        errors.append("Password must contain at least one special character.")
    for i in range(len(password) - 1):
        if password[i] == password[i + 1]:
            errors.append("Password must not contain two consecutive identical characters.")
            break
    return errors


def username_exists(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result is not None


def register_user(username, password):
    password_hash = generate_password_hash(password)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
              (username, password_hash, now))
    conn.commit()
    conn.close()


def verify_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row[0], password):
        return True
    return False


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('login.html', error="Please enter both username and password.", username=username)
        if not username_exists(username):
            return render_template('login.html', error="No account found with that username.", username=username)
        if not verify_user(username, password):
            return render_template('login.html', error="Incorrect password. Please try again.", username=username)
        session['username'] = username
        flash(f"Welcome back, {username}!", 'success')
        return redirect(url_for('home'))
    return render_template('login.html', error=None, username='')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        errors = []
        if not username:
            errors.append("Username is required.")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        elif username_exists(username):
            errors.append(f"Username '{username}' is already taken.")
        if not password:
            errors.append("Password is required.")
        else:
            errors.extend(validate_password(password))
        if password and confirm_password != password:
            errors.append("Passwords do not match.")
        if errors:
            return render_template('register.html', errors=errors, username=username)
        register_user(username, password)
        session['username'] = username
        flash(f"Welcome, {username}! Your account has been created.", 'success')
        return redirect(url_for('home'))
    return render_template('register.html', errors=[], username='')


@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html', username=session['username'])


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)