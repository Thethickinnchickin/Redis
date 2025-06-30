from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, current_app
)
from datetime import datetime, timezone
from app import (
    login_required, generate_verification_token, generate_2fa_code,
    send_verification_email, send_2fa_email, send_reset_email
)
from app.models import User
from app.forms import (
    DeleteUserForm, LoginForm, TwoFactorForm,
    RegisterForm, RequestPasswordResetForm, ResetPasswordForm
)
from app.extensions import limiter

bp = Blueprint('routes', __name__)

@bp.route('/')
def home():
    return render_template('templates/home.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username, password, email = form.username.data, form.password.data, form.email.data

        if User.find_by_username(username):
            flash("Username already exists.", "error")
            return redirect(url_for('routes.register'))
        if User.find_by_email(email):
            flash("Email already exists.", "error")
            return redirect(url_for('routes.register'))

        user = User(username, password)
        user.email = email
        user.is_verified = False
        user.role = 'user'
        user.verification_token = generate_verification_token()
        user.save_to_db()

        verification_link = url_for('routes.verify_email', token=user.verification_token, _external=True, _scheme='https')
        send_verification_email(bp.app, email, verification_link)

        flash("Check your email to verify your account.", "success")
        return render_template('registration_success.html')

    return render_template('register.html', form=form)

@bp.route('/verify/<token>')
def verify_email(token):
    user = User.find_by_verification_token(token)
    if user:
        user.is_verified = True
        user.verification_token = None
        user.save_to_db()
        flash("Email verified!", "success")
        return render_template('login.html', form=RegisterForm())
    flash("Invalid verification link.", "error")
    return redirect(url_for('routes.home'))

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if 'username' in session:
        return redirect(url_for('routes.home'))

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

            send_2fa_email(bp.app, user.email, code)
            flash("2FA code sent to your email.", "info")
            return redirect(url_for('routes.two_factor'))

        flash("Invalid credentials.", "error")
    return render_template('login.html', form=form)

@bp.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'temp_username' not in session:
        return redirect(url_for('routes.login'))

    form = TwoFactorForm()
    expiration_str = session.get('2fa_code_expiration')
    if expiration_str and datetime.now(timezone.utc) > datetime.fromisoformat(expiration_str).astimezone(timezone.utc):
        flash("2FA code expired.", "error")
        return redirect(url_for('routes.resend_2fa_code'))

    if form.validate_on_submit():
        if form.code.data == str(session.get('2fa_code')):
            session['username'] = session.pop('temp_username')
            session.pop('temp_email', None)
            session.pop('2fa_code', None)
            session.pop('2fa_code_expiration', None)
            flash(f"Welcome, {session['username']}!", "success")
            return redirect(url_for('routes.home'))
        flash("Invalid 2FA code.", "error")

    return render_template('two_factor.html', form=form)

@bp.route('/resend_2fa_code')
def resend_2fa_code():
    if 'temp_username' not in session:
        return redirect(url_for('routes.login'))

    user = User.find_by_username(session['temp_username'])
    if user:
        code, expiration = generate_2fa_code()
        session['2fa_code'] = code
        session['2fa_code_expiration'] = expiration.isoformat()
        send_2fa_email(bp.app, user.email, code)
        flash("2FA code resent.", "info")
    return redirect(url_for('routes.two_factor'))

@bp.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('routes.login'))

@bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=session['username'])

@bp.route('/reset-password', methods=['GET', 'POST'])
def request_password_reset():
    form = RequestPasswordResetForm()
    if form.validate_on_submit():
        user = User.find_by_email(form.email.data)
        if not user:
            flash("No account with that email.", "error")
            return redirect(url_for('routes.request_password_reset'))

        user.generate_reset_token()
        user.save_to_db()
        reset_link = url_for('routes.reset_password', token=user.reset_token, _external=True, _scheme='https')
        send_reset_email(bp.app, user.email, reset_link)
        flash("Check your email for the reset link.", "info")
        return redirect(url_for('routes.login'))

    return render_template('reset_password_request.html', form=form)

@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.find_by_reset_token(token)
    if not user:
        flash("Invalid token.", "error")
        return redirect(url_for('routes.request_password_reset'))

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
        return redirect(url_for('routes.login'))

    return render_template('reset_password.html', form=form, token=token)

@bp.route('/admin_dashboard')
@login_required
def admin_dashboard():
    user = User.find_by_username(session.get('username'))
    if user.role != 'admin':
        flash("Access denied.", "error")
        return redirect(url_for('routes.home'))
    form = DeleteUserForm()
    users = User.find_by_role('user')
    return render_template('admin_dashboard.html', users=users, form=form)

@bp.route('/delete_user/<username>', methods=['POST'])
@limiter.limit("7 per minute")
def delete_user(username):
    form = DeleteUserForm()
    if not form.validate_on_submit():
        flash("Invalid request.", "error")
        return redirect(url_for('routes.admin_dashboard'))

    requester = User.find_by_username(session.get('username'))
    if not requester or (requester.role != 'admin' and requester.username != username):
        flash("Permission denied.", "error")
        return redirect(url_for('routes.home'))

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
        return redirect(url_for('routes.logout'))
    return redirect(url_for('routes.admin_dashboard'))
