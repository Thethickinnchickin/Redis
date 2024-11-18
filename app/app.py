import random
import string
import uuid
from flask import Flask, session, request, redirect, url_for, render_template_string, render_template, flash
from flask_session import Session
import redis
from pymongo.mongo_client import MongoClient
from models import User  # Import the User model
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
# app.py
from forms import DeleteUserForm, LoginForm, TwoFactorForm, RegisterForm, RequestPasswordResetForm, ResetPasswordForm


# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

csrf = CSRFProtect(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Limiter with Redis storage for rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}"
)
limiter.init_app(app)

# MongoDB Configuration
uri = os.getenv('MONGO_URI')  # Ensure MongoDB URI is in .env
if not uri:
    raise ValueError("Mongo URI not found in environment variables!")

app.config['MONGO_URI'] = uri
client = MongoClient(uri)
mongo = PyMongo(app)

# Test the MongoDB connection
try:
    client.admin.command('ping')
    logger.info("Pinged your deployment. Successfully connected to MongoDB!")
except Exception as e:
    logger.error(f"Error connecting to MongoDB: {e}")

# Pass the client to User model
User.set_mongo(client)  # Pass the MongoClient instance to User

# Redis Configuration for Sessions
try:
    session_redis = redis.StrictRedis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        password=os.getenv('REDIS_PASSWORD', None)
    )
    session_redis.ping()  # Test connection
    logger.info("Successfully connected to Redis!")
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

# Secure the session cookie:
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Protect from JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection

# Gmail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Gmail address from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # App password from .env
app.config['PREFERRED_URL_SCHEME'] = 'https'
mail = Mail(app)

# Flask Session
Session(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logger.warning("Attempt to access a protected page without being logged in.")
            return redirect(url_for('login'))  # Redirect to login if not logged in
        return f(*args, **kwargs)
    return decorated_function

def send_verification_email(user_email, verification_link):
    try:
        msg = Message(
            'Verify Your Email Address',
            sender='redisemailer@gmail.com',  # replace with your Gmail address
            recipients=[user_email]
        )
        msg.body = f'Please verify your email by clicking the following link: {verification_link}'
        mail.send(msg)
        logger.info(f"Verification email sent to {user_email}")
    except Exception as e:
        logger.error(f"Error sending verification email: {e}")

def generate_verification_token():
    return str(uuid.uuid4())

def generate_2fa_code():
    code = random.randint(100000, 999999)
    expiration_time = datetime.utcnow() + timedelta(minutes=5)  # Set code to expire in 5 minutes
    return code, expiration_time

def send_2fa_email(user_email, code):
    try:
        msg = Message("Your 2FA Code",
                      sender='redisemailer@gmail.com',
                      recipients=[user_email])
        msg.body = f"Your 2FA code is {code}."
        mail.send(msg)
        logger.info(f"2FA code sent to {user_email}")
    except Exception as e:
        logger.error(f"Error sending 2FA email: {e}")

def send_reset_email(email, reset_link):
    try:
        msg = Message(
            'Password Reset Request',
            sender='redisemailer@gmail.com',
            recipients=[email]
        )
        msg.body = f'Please use the following link to reset your password: {reset_link}'
        mail.send(msg)
        logger.info(f"Password reset email sent to {email}")
    except Exception as e:
        logger.error(f"Error sending reset email: {e}")

def is_2fa_code_expired():
    expiration_time = session.get('2fa_expiration')
    if expiration_time and datetime.now(timezone.utc) > expiration_time:
        return True
    return False

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        # Check if the username already exists
        if User.find_by_username(username):
            flash("Username already exists. Please choose a different one.", "error")
            logger.warning(f"Registration failed: username '{username}' already exists.")
            return redirect(url_for('register'))

        # Check if the email already exists
        if User.find_by_email(email):
            flash("Email already exists. Please login", "error")
            logger.warning(f"Registration failed: email '{email}' already exists.")
            return redirect(url_for('register'))

        # Create user instance and generate a password hash
        user = User(username, password)
        user.email = email  # Set the email
        user.is_verified = False  # Initially the user is not verified
        user.role = 'user'  # Default role set to 'user'

        # Generate verification token and save it to the user
        verification_token = generate_verification_token()  # Generate token
        user.verification_token = verification_token  # Store the token in the user
        
        # Save the user to the database
        user.save_to_db()
        logger.info(f"User '{username}' registered successfully.")
        
        # Send verification email
        verification_link = url_for('verify_email', token=verification_token, _external=True, _scheme='https')
        send_verification_email(email, verification_link)
        
        flash("Registration successful! Please check your email to verify your account.", "success")
        return render_template('registration_success.html')

    return render_template('register.html', form=form)

@app.route('/verify/<token>')
def verify_email(token):
    user = User.find_by_verification_token(token)
    if user:
        user.is_verified = True
        user.verification_token = None  # clear the token once verified
        user.save_to_db()
        logger.info(f"User '{user.username}' email verified successfully.")
        flash("Your email has been verified! You can now log in.", "success")
        return render_template('login.html', form=RegisterForm())
    else:
        logger.warning(f"Verification failed: Invalid or expired token '{token}'.")
        flash("Invalid or expired verification link.", "error")
        return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'username' in session:
        return redirect(url_for('home'))  # Redirect to homepage if already logged in
    
    form = LoginForm()  # Use the form object
    
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.find_by_username(username)

        if user and user.is_verified and user.check_password(password):
            session['temp_username'] = username
            session['temp_email'] = user.email
            code, expiration = generate_2fa_code()
            session['2fa_code'] = code
            session['2fa_code_expiration'] = expiration.isoformat()

            # Setting expiration time for the 2FA code
            current_utc_time = datetime.now(timezone.utc)
            expiration_time = current_utc_time + timedelta(minutes=5)
            session['2fa_expiration'] = expiration_time.isoformat()

            send_2fa_email(user.email, code)
            logger.info(f"2FA code sent to {user.email} for user '{username}'")
            flash("A 2FA code has been sent to your email.", "info")
            return redirect(url_for('two_factor'))

        flash("Invalid credentials. Please try again.", "error")
        logger.warning(f"Login attempt failed for user '{username}'.")
    return render_template('login.html', form=form)  # Pass form to the template

@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'temp_username' not in session:
        return redirect(url_for('login'))

    form = TwoFactorForm()  # Use the 2FA form

    expiration_str = session.get('2fa_code_expiration')
    if expiration_str:
        # Convert expiration time from the session to a timezone-aware datetime
        expiration_time = datetime.fromisoformat(expiration_str).astimezone(timezone.utc)

        # Compare timezone-aware datetimes
        if datetime.now(timezone.utc) > expiration_time:
            flash("The 2FA code has expired. Please request a new one.", "error")
            logger.warning("2FA code expired.")
            return redirect(url_for('resend_2fa_code'))
    if request.method == 'POST' and form.validate_on_submit():
        code = form.code.data
        if code == str(session.get('2fa_code')):
            session['username'] = session['temp_username']
            session.pop('temp_username')
            session.pop('temp_email')
            session.pop('2fa_code')
            session.pop('2fa_code_expiration')

            flash(f"Welcome back, {session['username']}!", "success")
            logger.info(f"User '{session['username']}' logged in successfully.")
            return redirect(url_for('home'))
        else:
            flash("Invalid 2FA code. Please try again.", "error")
            logger.warning(f"Invalid 2FA code entered for user '{session.get('temp_username')}'.")
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
        logger.info(f"2FA code resent to {user.email}")
        flash("A new 2FA code has been sent to your email.", "info")
    return redirect(url_for('two_factor'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    logger.info("User logged out successfully.")
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    username = session.get('username')
    if not username:
        flash("Your session has expired. Please log in again.", "error")
        return redirect(url_for('login'))
    return render_template('profile.html', username=username)


@app.route('/reset-password', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.find_by_email(email)

        if not user:
            flash("No account found with that email.", "error")
            return redirect(url_for('request_password_reset'))
        
        # Generate and save the reset token
        user.generate_reset_token()
        user.save_to_db()

        # Send the reset email with HTTPS link
        reset_link = url_for('reset_password', token=user.reset_token, _external=True, _scheme='https')
        send_reset_email(user.email, reset_link)
        flash("Check your email for the password reset link.", "info")
        return redirect(url_for('login'))

    return render_template('reset_password_request.html', form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.find_by_reset_token(token)
    if not user:
        flash("Invalid or expired token.", "error")
        return redirect(url_for('request_password_reset'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data
        user.salt = os.urandom(16)  # Generate a new salt
        user.password_hash = user.generate_scrypt_hash(new_password)
        user.reset_token = None  # Clear the token after reset
        user.token_expiry = None

        # Preserve the existing role during updates
        existing_user_data = user.mongo.db.users.find_one({"username": user.username})
        user.role = existing_user_data.get("role", "user")  # Ensure role is preserved

        # Update user in database
        user_data = {
            "username": user.username,
            "password_hash": user.password_hash,
            "salt": user.salt.hex(),
            "email": user.email,
            "verification_token": user.verification_token,
            "is_verified": user.is_verified,
            "reset_token": user.reset_token,
            "token_expiry": user.token_expiry,
            "role": user.role,  # Explicitly set the role
        }
        user.mongo.db.users.update_one({"username": user.username}, {"$set": user_data})

        flash("Your password has been updated. You can now log in.", "success")
        return redirect(url_for('login'))


    return render_template('reset_password.html', form=form, token=token)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Check if the logged-in user is an admin
    username = session.get('username')
    user = User.find_by_username(username)
    if user.role != 'admin':
        flash("You do not have permission to access this page", "error")
        return redirect(url_for('home'))  # Redirect to a non-admin page
    form = DeleteUserForm()
    # Retrieve all users (or filtered users if you need)
    users = User.find_by_role('user')  # You can add more roles or get all users
    return render_template('admin_dashboard.html', users=users, form=form)

@app.route('/delete_user/<username>', methods=['POST'])
@limiter.limit("7 per minute")
def delete_user(username):
    """Delete a user by username."""
    form = DeleteUserForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for('admin_dashboard'))

    logged_in_username = session.get('username')
    logged_in_user = User.find_by_username(logged_in_username)
    
    if not logged_in_user:
        flash("You must be logged in to delete an account", "error")
        return redirect(url_for('login'))
    
    # Check if the user has permission
    if logged_in_user.role != 'admin' and logged_in_user.username != username:
        flash("You do not have permission to delete this account", "error")
        return redirect(url_for('home'))
    
    user_to_delete = User.find_by_username(username)
    
    if user_to_delete:
        try:
            user_to_delete.delete_from_db()
            flash(f"User '{username}' deleted successfully", "success")
        except ValueError as e:
            flash(str(e), "error")
    else:
        flash(f"User with username '{username}' not found.", "error")
    
    if logged_in_user.username == username:
        return redirect(url_for('logout'))
    
    return redirect(url_for('admin_dashboard'))

# Error handling and logging
if not app.debug:
    import logging
    from logging.handlers import RotatingFileHandler

    handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.ERROR)
    app.logger.addHandler(handler)

    @app.errorhandler(500)
    def internal_server_error(error):
        return f"An internal server error occurred.\n{error}", 500

if __name__ == '__main__':
    print("Mongo instance in User model:", User.mongo)
    app.run(ssl_context='adhoc',debug=True)

