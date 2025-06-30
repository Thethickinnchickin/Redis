import random
import string
import uuid
from flask import Flask, session, request, redirect, url_for, render_template, flash
from flask_session import Session
import redis
from pymongo.mongo_client import MongoClient
from app.models import User  # Updated import path
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from functools import wraps
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_pymongo import PyMongo
import logging
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from app.forms import (  # Updated import path
    DeleteUserForm, LoginForm, TwoFactorForm,
    RegisterForm, RequestPasswordResetForm, ResetPasswordForm
)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder="app/static", template_folder="app/templates")

csrf = CSRFProtect(app)

# Logging setup
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiter with Redis
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}"
)
limiter.init_app(app)

# MongoDB setup
uri = os.getenv('MONGO_URI')
if not uri:
    raise ValueError("Mongo URI not found in environment variables!")

app.config['MONGO_URI'] = uri
client = MongoClient(uri)
mongo = PyMongo(app)

try:
    client.admin.command('ping')
    logger.info("Connected to MongoDB successfully.")
except Exception as e:
    logger.error(f"MongoDB connection error: {e}")

User.set_mongo(client)

# Redis session store
try:
    session_redis = redis.StrictRedis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None)
    )
    session_redis.ping()
    logger.info("Connected to Redis successfully.")
except redis.ConnectionError as e:
    logger.error(f"Redis connection error: {e}")
    raise e

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_REDIS'] = session_redis
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Gmail setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['PREFERRED_URL_SCHEME'] = 'https'
mail = Mail(app)

Session(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logger.warning("Unauthorized access attempt.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_verification_email(user_email, verification_link):
    try:
        msg = Message('Verify Your Email Address',
                      sender='redisemailer@gmail.com',
                      recipients=[user_email])
        msg.body = f'Please verify your email: {verification_link}'
        mail.send(msg)
        logger.info(f"Verification email sent to {user_email}")
    except Exception as e:
        logger.error(f"Email sending error: {e}")

def generate_verification_token():
    return str(uuid.uuid4())

def generate_2fa_code():
    code = random.randint(100000, 999999)
    expiration = datetime.utcnow() + timedelta(minutes=5)
    return code, expiration

def send_2fa_email(user_email, code):
    try:
        msg = Message("Your 2FA Code",
                      sender='redisemailer@gmail.com',
                      recipients=[user_email])
        msg.body = f"Your 2FA code is {code}."
        mail.send(msg)
        logger.info(f"2FA code sent to {user_email}")
    except Exception as e:
        logger.error(f"2FA email error: {e}")

def send_reset_email(email, reset_link):
    try:
        msg = Message('Password Reset Request',
                      sender='redisemailer@gmail.com',
                      recipients=[email])
        msg.body = f'Reset your password: {reset_link}'
        mail.send(msg)
        logger.info(f"Password reset sent to {email}")
    except Exception as e:
        logger.error(f"Reset email error: {e}")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username, password, email = form.username.data, form.password.data, form.email.data

        if User.find_by_username(username):
            flash("Username already exists.", "error")
            return redirect(url_for('register'))
        if User.find_by_email(email):
            flash("Email already exists.", "error")
            return redirect(url_for('register'))

        user = User(username, password)
        user.email = email
        user.is_verified = False
        user.role = 'user'
        user.verification_token = generate_verification_token()
        user.save_to_db()

        verification_link = url_for('verify_email', token=user.verification_token, _external=True, _scheme='https')
        send_verification_email(email, verification_link)

        flash("Check your email to verify your account.", "success")
        return render_template('registration_success.html')

    return render_template('register.html', form=form)

@app.route('/verify/<token>')
def verify_email(token):
    user = User.find_by_verification_token(token)
    if user:
        user.is_verified = True
        user.verification_token = None
        user.save_to_db()
        flash("Email verified!", "success")
        return render_template('login.html', form=RegisterForm())
    flash("Invalid verification link.", "error")
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.find_by_username(username)

        if user and user.is_verified and user.check_password(password):
            session['temp_username'] = username
            session['temp_email'] = user.email
            code, expiration = generate_2fa_code()
            session['2fa_code'] = code
            session['2fa_code_expiration'] = expiration.isoformat()
            session['2fa_expiration'] = expiration.isoformat()

            send_2fa_email(user.email, code)
            flash("2FA code sent to your email.", "info")
            return redirect(url_for('two_factor'))

        flash("Invalid credentials.", "error")
    return render_template('login.html', form=form)

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'temp_username' not in session:
        return redirect(url_for('login'))

    form = TwoFactorForm()
    expiration_str = session.get('2fa_code_expiration')
    if expiration_str and datetime.now(timezone.utc) > datetime.fromisoformat(expiration_str).astimezone(timezone.utc):
        flash("2FA code expired.", "error")
        return redirect(url_for('resend_2fa_code'))

    if form.validate_on_submit():
        if form.code.data == str(session.get('2fa_code')):
            session['username'] = session.pop('temp_username')
            session.pop('temp_email', None)
            session.pop('2fa_code', None)
            session.pop('2fa_code_expiration', None)
            flash(f"Welcome, {session['username']}!", "success")
            return redirect(url_for('home'))
        flash("Invalid 2FA code.", "error")

    return render_template('two_factor.html', form=form)

@app.route('/resend_2fa_code')
def resend_2fa_code():
    if 'temp_username' not in session:
        return redirect(url_for('login'))

    user = User.find_by_username(session['temp_username'])
    if user:
        code, expiration = generate_2fa_code()
        session['2fa_code'] = code
        session['2fa_code_expiration'] = expiration.isoformat()
        send_2fa_email(user.email, code)
        flash("2FA code resent.", "info")
    return redirect(url_for('two_factor'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=session['username'])

@app.route('/reset-password', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if not user:
            flash("No account with that email.", "error")
            return redirect(url_for('request_password_reset'))

        user.generate_reset_token()
        user.save_to_db()
        reset_link = url_for('reset_password', token=user.reset_token, _external=True, _scheme='https')
        send_reset_email(user.email, reset_link)
        flash("Check your email for the reset link.", "info")
        return redirect(url_for('login'))

    return render_template('reset_password_request.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.find_by_reset_token(token)
    if not user:
        flash("Invalid token.", "error")
        return redirect(url_for('request_password_reset'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data
        user.salt = os.urandom(16)
        user.password_hash = user.generate_scrypt_hash(new_password)
        user.reset_token = None
        user.token_expiry = None
        existing_data = user.mongo.db.users.find_one({"username": user.username})
        user.role = existing_data.get("role", "user")

        user_data = {
            "username": user.username,
            "password_hash": user.password_hash,
            "salt": user.salt.hex(),
            "email": user.email,
            "verification_token": user.verification_token,
            "is_verified": user.is_verified,
            "reset_token": user.reset_token,
            "token_expiry": user.token_expiry,
            "role": user.role
        }
        user.mongo.db.users.update_one({"username": user.username}, {"$set": user_data})
        flash("Password updated. Log in now.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form, token=token)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    user = User.find_by_username(session.get('username'))
    if user.role != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('home'))
    form = DeleteUserForm()
    users = User.find_by_role('user')
    return render_template('admin_dashboard.html', users=users, form=form)

@app.route('/delete_user/<username>', methods=['POST'])
@limiter.limit("7 per minute")
def delete_user(username):
    form = DeleteUserForm()
    if not form.validate_on_submit():
        flash("Invalid request.", "error")
        return redirect(url_for('admin_dashboard'))

    requester = User.find_by_username(session.get('username'))
    if not requester or (requester.role != 'admin' and requester.username != username):
        flash("Permission denied.", "error")
        return redirect(url_for('home'))

    user_to_delete = User.find_by_username(username)
    if user_to_delete:
        try:
            user_to_delete.delete_from_db()
            flash(f"User '{username}' deleted.", "success")
        except ValueError as e:
            flash(str(e), "error")
    else:
        flash("User not found.", "error")

    if requester.username == username:
        return redirect(url_for('logout'))
    return redirect(url_for('admin_dashboard'))

# Error logging
if not app.debug:
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.ERROR)
    app.logger.addHandler(handler)

    @app.errorhandler(500)
    def internal_error(error):
        return f"Internal server error: {error}", 500

if __name__ == '__main__':
    print("Mongo instance in User model:", User.mongo)
    app.run(ssl_context='adhoc', debug=True)
