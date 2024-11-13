import uuid
from flask import Flask, session, request, redirect, url_for, render_template_string, render_template, flash
from flask_session import Session
import redis
from pymongo.mongo_client import MongoClient
from models import User  # Import the User model
import os
from datetime import timedelta
from dotenv import load_dotenv
from functools import wraps
from flask_mail import Mail, Message

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# MongoDB Configuration
uri = "mongodb+srv://mattreileydeveloper:NewPassword@cluster0.ueh7b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"  # Make sure this matches the MongoDB URI in .env
client = MongoClient(uri)

# Test the MongoDB connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# Pass the client to User model
User.set_mongo(client)  # Pass the MongoClient instance to User

# Redis Configuration for Sessions
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_REDIS'] = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)  # Session expiration

# Assuming this is in your Flask app (e.g., app.py)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'redisemailer@gmail.com'  # replace with your Gmail address
app.config['MAIL_PASSWORD'] = 'crok iqis rimk hsdh'  # replace with your app password

mail = Mail(app)

# Set the secret key for signing the session
app.secret_key = os.urandom(24)

# Initialize the Session extension
Session(app)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))  # Redirect to login if not logged in
        return f(*args, **kwargs)
    return decorated_function

def send_verification_email(user_email, verification_link):
    msg = Message(
        'Verify Your Email Address',
        sender='redisemailer@gmail.com',  # replace with your Gmail address
        recipients=[user_email]
    )
    msg.body = f'Please verify your email by clicking the following link: {verification_link}'
    mail.send(msg)

# Generate a verification token for a new user
def generate_verification_token():
    return str(uuid.uuid4())

def send_reset_email(email, reset_link):
    msg = Message(
        'Password Reset Request',
        sender='redisemailer@gmail.com',
        recipients=[email]
    )
    msg.body = f'Please use the following link to reset your password: {reset_link}'
    mail.send(msg)
 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']  # assuming you added an email field in the registration form
    
    # Check if the username already exists
    if User.find_by_username(username):
        flash("Username already exists. Please choose a different one.", "error")
        return redirect(url_for('register'))
    
    # Check if the username already exists
    if User.find_by_email(email):
        flash("Email already exists. Please login", "error")
        return redirect(url_for('register'))
    
    
    # Create user instance and generate a password hash
    user = User(username, password)
    user.email = email  # Set the email
    user.is_verified = False  # Initially the user is not verified
    user.role = 'admin'
    
    # Generate verification token and save it to the user
    verification_token = generate_verification_token()  # Generate token
    user.verification_token = verification_token  # Store the token in the user
    
    # Save the user to the database
    user.save_to_db()

    # Send verification email
    verification_link = url_for('verify_email', token=verification_token, _external=True)
    send_verification_email(email, verification_link)
    
    return render_template('registration_success.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = User.find_by_verification_token(token)
    if user:
        user.is_verified = True
        user.verification_token = None  # clear the token once verified
        user.save_to_db()
        print("User is verifged")
        flash("Your email has been verified! You can now log in.", "success")
        return redirect(url_for('login'))
    else:
        flash("Invalid or expired verification link.", "error")
        return redirect(url_for('home'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))  # Redirect to homepage if already logged in
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.find_by_username(username)

        if user and user.is_verified and user.check_password(password):
            session['username'] = username
            flash("Login successful!", "success")
            return redirect(url_for('profile'))
        
        flash("Invalid credentials. Please try again.", "error")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=session['username'])

@app.route('/logout')
def logout():
    # Clear the session and log the user out
    session.clear()
    flash("You have logged out successfully.", "info")
    return redirect(url_for('home'))

@app.route('/reset-password', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'GET':
        return render_template('reset_password_request.html')

    email = request.form['email']
    user = User.find_by_email(email)

    if not user:
        flash("No account found with that email.", "error")
        return redirect(url_for('request_password_reset'))
    
    # Generate and save the reset token
    user.generate_reset_token()
    user.save_to_db()

    # Send the reset email
    reset_link = url_for('reset_password', token=user.reset_token, _external=True)
    send_reset_email(user.email, reset_link)
    flash("Check your email for the password reset link.", "info")
    return redirect(url_for('login'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.find_by_reset_token(token)
    if not user:
        flash("Invalid or expired token.", "error")
        return redirect(url_for('request_password_reset'))

    if request.method == 'POST':
        new_password = request.form['password']
        user.salt = os.urandom(16)  # Generate a new salt
        user.password_hash = user.generate_scrypt_hash(new_password)
        user.reset_token = None  # Clear the token after reset
        user.token_expiry = None
        user.save_to_db()
        
        flash("Your password has been updated. You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Check if the logged-in user is an admin
    username = session.get('username')
    user = User.find_by_username(username)
    if user.role != 'admin':
        flash("You do not have permission to access this page", "error")
        return redirect(url_for('home'))  # Redirect to a non-admin page

    # Retrieve all users (or filtered users if you need)
    users = User.find_by_role('user')  # You can add more roles or get all users
    return render_template('admin_dashboard.html', users=users)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    """Delete a user by username."""
    logged_in_username = session.get('username')  # Get logged-in user's username
    
    # Fetch the logged-in user from the database
    logged_in_user = User.find_by_username(logged_in_username)
    
    if not logged_in_user:
        flash("You must be logged in to delete an account", "error")
        return redirect(url_for('login'))  # Redirect to the login page if user is not logged in
    
    # Check if the logged-in user is trying to delete their own account or is an admin
    if logged_in_user.role != 'admin' and logged_in_user.username != username:
        # If the user is not an admin and is not deleting their own account
        flash("You do not have permission to delete another user's account", "error")
        return redirect(url_for('home'))  # Redirect to a non-admin page
    
    # Fetch the user to delete using the username passed in the URL
    user_to_delete = User.find_by_username(username)
    
    if user_to_delete:
        try:
            # Allow the user to delete their own account or admin to delete any user
            user_to_delete.delete_from_db()
            if logged_in_user.username == username:
                flash("Your account has been deleted successfully", "success")
            else:
                flash(f"User {username} deleted successfully", "success")
        except ValueError as e:
            flash(str(e), "danger")
    else:
        flash(f"User with username {username} not found.", "danger")
    
    # Redirect to the appropriate page
    if logged_in_user.username == username:
        return redirect(url_for('logout'))  # Redirect to logout if the user deleted their own account
    return redirect(url_for('admin_dashboard'))  # Redirect to the admin dashboard after admin deletion



if __name__ == '__main__':
    print("Mongo instance in User model:", User.mongo)
    app.run(debug=True)
