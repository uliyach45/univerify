from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, AuditLog
from datetime import datetime

auth = Blueprint('auth', __name__)

def log_action(action, details=None, success=True, user_id=None):
    try:
        uid = user_id or (current_user.id if current_user.is_authenticated else None)
        log = AuditLog(user_id=uid, action=action, details=details,
                      ip_address=request.remote_addr, success=success)
        db.session.add(log)
        db.session.commit()
    except:
        pass

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    full_name = data.get('full_name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'student')
    reg_number = data.get('reg_number', '').strip()
    department = data.get('department', '').strip()

    if not all([full_name, email, password]):
        return jsonify({'error': 'Name, email and password are required'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'This email is already registered'}), 400

    user = User(
        full_name=full_name, email=email, role=role,
        reg_number=reg_number or None,
        department=department or None
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    log_action('USER_REGISTERED', f'New {role}: {email}', user_id=user.id)
    return jsonify({'success': True, 'message': 'Account created successfully!', 'role': role})

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        log_action('LOGIN_FAILED', f'Failed: {email}', success=False)
        return jsonify({'error': 'Invalid email or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is deactivated. Contact admin.'}), 403

    login_user(user, remember=True)
    log_action('LOGIN_SUCCESS', f'{user.role} logged in', user_id=user.id)

    if user.role == 'admin':
        redirect_url = '/dashboard'
    elif user.role == 'student':
        redirect_url = '/student'
    else:
        redirect_url = '/verify'

    return jsonify({'success': True, 'role': user.role,
                   'name': user.full_name, 'redirect': redirect_url})

@auth.route('/logout')
@login_required
def logout():
    log_action('LOGOUT', f'{current_user.email} logged out')
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])

@auth.route('/api/users/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Admin only'}), 403
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    log_action('USER_TOGGLED', f'{user.email} active={user.is_active}')
    return jsonify({'success': True, 'is_active': user.is_active})
