from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from otp_generator import generate_otp
import os
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask import render_template
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(days=7)

# Configure Flask-Mail for Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'avaneesh.lakkamraju@gmail.com'  # <-- CHANGE THIS
app.config['MAIL_PASSWORD'] = 'mbfc nzsa ahio oqsv'             # <-- CHANGE THIS
app.config['MAIL_DEFAULT_SENDER'] = 'avaneesh.lakkamraju@gmail.com'  # <-- CHANGE THIS

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

mail = Mail(app)

# In-memory store for OTPs (email: otp)
otp_store = {}

# HTML templates (simple inline for demo)




SECRET_KEY = app.secret_key
serializer = URLSafeTimedSerializer(SECRET_KEY)

register_html = '''
<!doctype html>
<title>Register</title>
<h2>Register</h2>
<form method="post">
  Email: <input type="email" name="email" required><br>
  Password: <input type="password" name="password" required><br>
  <input type="submit" value="Register">
</form>
{{ message }}
'''

login_html = '''
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post">
  Email: <input type="email" name="email" required><br>
  Password: <input type="password" name="password" required><br>
  <input type="submit" value="Login">
</form>
{{ message }}
'''

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Float, default=0.0)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'deposit' or 'withdraw'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    message = ''
    email = session.get('email')
    if not email:
        return redirect(url_for('request_otp'))
    if request.method == 'POST':
        otp_input = request.form['otp']
        if otp_store.get(email) == otp_input:
            # OTP verified, create user if not exists
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, balance=1000.0)  # Start with fake money
                db.session.add(user)
                db.session.commit()
            session['user_id'] = user.id
            otp_store.pop(email, None)
            return redirect(url_for('dashboard'))
        else:
            message = 'Invalid OTP. Please try again.'
    return render_template('verify_otp.html', message=message)

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user or not user.is_verified:
        return redirect(url_for('login'))
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.timestamp.desc()).all()
    # Dashboard
    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/deposit', methods=['POST'])
def deposit():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user or not user.is_verified:
        return redirect(url_for('login'))
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            raise ValueError
    except Exception:
        return redirect(url_for('dashboard'))
    user.balance += amount
    txn = Transaction(user_id=user.id, amount=amount, type='deposit')
    db.session.add(txn)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/withdraw', methods=['POST'])
def withdraw():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user or not user.is_verified:
        return redirect(url_for('login'))
    try:
        amount = float(request.form['amount'])
        if amount <= 0 or amount > user.balance:
            raise ValueError
    except Exception:
        return redirect(url_for('dashboard'))
    user.balance -= amount
    txn = Transaction(user_id=user.id, amount=amount, type='withdraw')
    db.session.add(txn)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

ADMIN_EMAIL = 'avaneesh.lakkamraju@gmail.com'

def is_admin():
    user_id = session.get('user_id')
    if not user_id:
        return False
    user = User.query.get(user_id)
    return user and user.email == ADMIN_EMAIL

@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        return redirect(url_for('dashboard'))
    users = User.query.all()
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    # Admin Panel
    return render_template('admin.html', users=users, transactions=transactions)

@app.route('/admin/adjust_balance', methods=['POST'])
def admin_adjust_balance():
    if not is_admin():
        return redirect(url_for('dashboard'))
    user_id = request.form.get('user_id')
    new_balance = request.form.get('new_balance')
    user = User.query.get(user_id)
    try:
        new_balance = float(new_balance)
        user.balance = new_balance
        db.session.commit()
    except Exception:
        pass
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not is_admin():
        return redirect(url_for('dashboard'))
    user_id = request.form.get('user_id')
    user = User.query.get(user_id)
    if user:
        Transaction.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    import re
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')
        recaptcha_secret = '6LeZWI0rAAAAAB2CxckkRZjLjmmKiXi8lClzTcP6'
        recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_payload = {'secret': recaptcha_secret, 'response': recaptcha_response}
        recaptcha_result = requests.post(recaptcha_verify_url, data=recaptcha_payload).json()
        print('reCAPTCHA result (register):', recaptcha_result)
        if not recaptcha_result.get('success'):
            message = 'reCAPTCHA verification failed. Please try again.'
        # Password policy: 8+ chars, at least one letter, one number, one symbol
        elif len(password) < 8 or \
           not re.search(r'[A-Za-z]', password) or \
           not re.search(r'\d', password) or \
           not re.search(r'[^A-Za-z0-9]', password):
            message = 'Password must be at least 8 characters long and include letters, numbers, and symbols.'
        elif User.query.filter_by(email=email).first():
            message = 'Email already registered.'
        else:
            password_hash = generate_password_hash(password)
            user = User(email=email, password_hash=password_hash, is_verified=False, balance=1000.0)
            db.session.add(user)
            db.session.commit()
            # Send verification email
            token = serializer.dumps(email, salt='email-verify')
            verify_url = url_for('verify_email', token=token, _external=True)
            try:
                msg = Message('Verify your email', recipients=[email])
                msg.body = f'Click to verify your email: {verify_url}'
                mail.send(msg)
                message = 'Verification email sent. Please check your inbox.'
            except Exception as e:
                message = f'Error sending email: {e}'
    return render_template('register.html', message=message)

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600)
    except Exception:
        return 'Invalid or expired token.'
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        return 'Email verified! You can now log in.'
    return 'User not found.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')
        recaptcha_secret = '6LeZWI0rAAAAAB2CxckkRZjLjmmKiXi8lClzTcP6'
        recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_payload = {'secret': recaptcha_secret, 'response': recaptcha_response}
        recaptcha_result = requests.post(recaptcha_verify_url, data=recaptcha_payload).json()
        print('reCAPTCHA result (login):', recaptcha_result)
        if not recaptcha_result.get('success'):
            message = 'reCAPTCHA verification failed. Please try again.'
        else:
            user = User.query.filter_by(email=email).first()
            if not user:
                message = 'No such user.'
            elif not user.is_verified:
                message = 'Email not verified. Please check your inbox.'
            elif not user.password_hash or not check_password_hash(user.password_hash, password):
                message = 'Incorrect password.'
            else:
                session['email'] = email
                session['user_id'] = user.id
                # Send OTP as before
                otp = generate_otp()
                otp_store[email] = otp
                try:
                    msg = Message('Your OTP Code', recipients=[email])
                    msg.body = f'Your OTP is: {otp}'
                    mail.send(msg)
                    return redirect(url_for('verify_otp'))
                except Exception as e:
                    message = f'Error sending OTP: {e}'
    return render_template('login.html', message=message)

if __name__ == '__main__':
    app.run(debug=True) 
