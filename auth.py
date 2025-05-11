from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import logging
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from client_db import CLIENT_DB_PATH, get_client_by_user_id

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def verify_credentials(username, password):
    """Verify user credentials and return user info if valid"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user by username
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            logger.warning(f"Login attempt failed: User {username} not found")
            return {
                'status': 'error',
                'message': 'Invalid credentials'
            }
        
        # Check password
        if not check_password_hash(user['password_hash'], password + user['salt']):
            logger.warning(f"Login attempt failed: Invalid password for user {username}")
            return {
                'status': 'error',
                'message': 'Invalid credentials'
            }
        
        # Generate session token
        session_token = generate_session_token()
        
        # Store session
        cursor.execute('''
            INSERT INTO sessions (user_id, session_token, created_at, expires_at)
            VALUES (?, ?, ?, datetime('now', '+1 day'))
        ''', (user['id'], session_token, datetime.now().isoformat()))
        
        conn.commit()
        
        return {
            'status': 'success',
            'session_token': session_token,
            'user': dict(user)
        }
        
    except Exception as e:
        logger.error(f"Error verifying credentials: {e}")
        return {
            'status': 'error',
            'message': 'An error occurred while verifying credentials'
        }
    finally:
        if conn:
            conn.close()

def generate_session_token():
    """Generate a unique session token"""
    import secrets
    return secrets.token_urlsafe(32)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Verify credentials
        result = verify_credentials(username, password)
        
        if result['status'] == 'success':
            # Set session
            session['session_token'] = result['session_token']
            
            # Log success
            logger.info(f"User {username} (role: {result['user']['role']}) logged in successfully")
            
            # Redirect based on role
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif result['user']['role'] == 'client':
                return redirect(url_for('client.dashboard'))
            else:
                flash('Invalid user role', 'danger')
                return render_template('auth/login.html')
        else:
            flash(result.get('message', 'Invalid credentials'), 'danger')
            return render_template('auth/login.html')
            
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'danger')
            return render_template('auth/register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')
        
        try:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            
            # Check if username exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash('Username already exists', 'danger')
                return render_template('auth/register.html')
            
            # Check if email exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                flash('Email already registered', 'danger')
                return render_template('auth/register.html')
            
            # Generate salt and hash password
            import secrets
            salt = secrets.token_hex(16)
            password_hash = generate_password_hash(password + salt)
            
            # Insert new user
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, 'client', ?)
            ''', (username, email, password_hash, salt, datetime.now().isoformat()))
            
            conn.commit()
            logger.info(f"Created user: {username} with role: client")
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            flash('An error occurred during registration', 'danger')
            return render_template('auth/register.html')
        finally:
            if conn:
                conn.close()
                
    return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    try:
        # Clear session token from database
        session_token = session.get('session_token')
        if session_token:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
            conn.commit()
            conn.close()
        
        # Clear session
        session.clear()
        flash('You have been logged out', 'info')
        
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        flash('An error occurred during logout', 'danger')
        
    return redirect(url_for('auth.login'))
