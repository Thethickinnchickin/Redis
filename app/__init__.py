import os
import random
import string
import uuid
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, session, redirect, url_for, flash
from flask_session import Session
import redis
from pymongo.mongo_client import MongoClient
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_pymongo import PyMongo
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Create the limiter object globally (but don't init yet)
from app.extensions import limiter


# Import models and forms using relative imports
from app.models import User
from app.forms import (
    DeleteUserForm, LoginForm, TwoFactorForm,
    RegisterForm, RequestPasswordResetForm, ResetPasswordForm
)

load_dotenv()

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")


    # CSRF protection
    csrf = CSRFProtect(app)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Configure and init the limiter
    limiter.storage_uri = f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}"
    limiter.init_app(app)
    app.limiter = limiter  # Optional convenience

    # Register routes
    from app.routes import bp
    app.register_blueprint(bp)

    # Logging setup
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    app.logger = logger

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

    app.config.update({
        'SESSION_TYPE': 'redis',
        'SESSION_PERMANENT': False,
        'SESSION_USE_SIGNER': True,
        'SESSION_KEY_PREFIX': 'flask_session:',
        'SESSION_REDIS': session_redis,
        'PERMANENT_SESSION_LIFETIME': timedelta(minutes=5),
        'SECRET_KEY': os.getenv('SECRET_KEY', os.urandom(24)),
        'SESSION_COOKIE_SECURE': True,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Strict'
    })

    # Gmail setup
    app.config.update({
        'MAIL_SERVER': 'smtp.gmail.com',
        'MAIL_PORT': 587,
        'MAIL_USE_TLS': True,
        'MAIL_USERNAME': os.getenv('MAIL_USERNAME'),
        'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD'),
        'PREFERRED_URL_SCHEME': 'https'
    })
    mail = Mail(app)
    app.mail = mail

    # Flask-Session setup
    Session(app)

    # Error logging setup (only if not debug)
    if not app.debug:
        from logging.handlers import RotatingFileHandler
        handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1)
        handler.setLevel(logging.ERROR)
        app.logger.addHandler(handler)

        @app.errorhandler(500)
        def internal_error(error):
            return f"Internal server error: {error}", 500

    return app

# Helper decorators and functions moved here if needed by routes

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            app.logger.warning("Unauthorized access attempt.")
            return redirect(url_for('routes.login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_verification_token():
    return str(uuid.uuid4())

def generate_2fa_code():
    code = random.randint(100000, 999999)
    expiration = datetime.utcnow() + timedelta(minutes=5)
    return code, expiration

# If you want to share helpers like email sending, put them here and import them into routes.py

def send_verification_email(app, user_email, verification_link):
    try:
        msg = Message('Verify Your Email Address',
                      sender='redisemailer@gmail.com',
                      recipients=[user_email])
        msg.body = f'Please verify your email: {verification_link}'
        app.mail.send(msg)
        app.logger.info(f"Verification email sent to {user_email}")
    except Exception as e:
        app.logger.error(f"Email sending error: {e}")

def send_2fa_email(app, user_email, code):
    try:
        msg = Message("Your 2FA Code",
                      sender='redisemailer@gmail.com',
                      recipients=[user_email])
        msg.body = f"Your 2FA code is {code}."
        app.mail.send(msg)
        app.logger.info(f"2FA code sent to {user_email}")
    except Exception as e:
        app.logger.error(f"2FA email error: {e}")

def send_reset_email(app, email, reset_link):
    try:
        msg = Message('Password Reset Request',
                      sender='redisemailer@gmail.com',
                      recipients=[email])
        msg.body = f'Reset your password: {reset_link}'
        app.mail.send(msg)
        app.logger.info(f"Password reset sent to {email}")
    except Exception as e:
        app.logger.error(f"Reset email error: {e}")
