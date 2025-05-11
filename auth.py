from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import logging
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from client_db import CLIENT_DB_PATH, get_client_by_user_id

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create the auth blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    """Complete client profile after registration"""
    # Check if user is logged in
    session_token = session.get('session_token')
    if not session_token:
        return redirect(url_for('auth.login'))
    
    result = verify_session(session_token)
    if result['status'] != 'success':
        return redirect(url_for('auth.login'))
    
    user = result['user']
    
    if request.method == 'POST':
        try:
            # Get form data
            business_name = request.form.get('business_name')
            contact_email = request.form.get('contact_email')
            contact_phone = request.form.get('contact_phone')
            business_domain = request.form.get('business_domain', '')
            
            # Basic validation
            if not business_name or not contact_email:
                flash('Business name and contact email are required', 'danger')
                return render_template('auth/complete-profile.html', user=user)
            
            # Connect to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            
            # Create client profile
            cursor.execute('''
                INSERT INTO clients (
                    created_by,
                    business_name,
                    business_domain,
                    contact_email,
                    contact_phone,
                    created_at,
                    active,
                    subscription_status
                ) VALUES (?, ?, ?, ?, ?, ?, 1, 'trial')
            ''', (
                user['user_id'],
                business_name,
                business_domain,
                contact_email,
                contact_phone,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            flash('Profile completed successfully!', 'success')
            return redirect(url_for('client.dashboard'))
            
        except Exception as e:
            logger.error(f"Error completing profile: {e}")
            flash('An error occurred while completing your profile', 'danger')
            return render_template('auth/complete-profile.html', user=user)
    
    return render_template('auth/complete-profile.html', user=user)

def verify_session(session_token):
    """Verify a session token"""
    if not session_token:
        return {"status": "error", "message": "No session token provided"}
    
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find the session and join with user data
        cursor.execute('''
            SELECT s.*, u.username, u.email, u.role, u.id as user_id
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? 
            AND u.active = 1 
            AND s.expires_at > datetime('now')
        ''', (session_token,))
        
        session = cursor.fetchone()
        
        if not session:
            return {"status": "error", "message": "Invalid or expired session"}
        
        return {
            "status": "success",
            "user": {
                "user_id": session['user_id'],
                "username": session['username'],
                "email": session['email'],
                "role": session['role']
            }
        }
    except Exception as e:
        logger.error(f"Session verification error: {e}")
        return {"status": "error", "message": "Session verification failed"}
    finally:
        if conn:
            conn.close()

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

@auth_bp.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    """Complete client profile after registration"""
    # Check if user is logged in
    session_token = session.get('session_token')
    if not session_token:
        return redirect(url_for('auth.login'))
    
    result = verify_session(session_token)
    if result['status'] != 'success':
        return redirect(url_for('auth.login'))
    
    user = result['user']
    
    if request.method == 'POST':
        try:
            # Get form data
            business_name = request.form.get('business_name')
            contact_email = request.form.get('contact_email')
            contact_phone = request.form.get('contact_phone')
            address = request.form.get('address')
            industry = request.form.get('industry')
            
            # Basic validation
            if not business_name or not contact_email:
                flash('Business name and contact email are required', 'danger')
                return render_template('auth/complete_profile.html', user=user)
            
            # Connect to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            
            # Create client profile
            cursor.execute('''
                INSERT INTO clients (
                    user_id,
                    business_name,
                    contact_email,
                    contact_phone,
                    address,
                    industry,
                    created_at,
                    active,
                    subscription_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'trial')
            ''', (
                user['user_id'],
                business_name,
                contact_email,
                contact_phone,
                address,
                industry,
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            flash('Profile completed successfully!', 'success')
            return redirect(url_for('client.dashboard'))
            
        except Exception as e:
            logger.error(f"Error completing profile: {e}")
            flash('An error occurred while completing your profile', 'danger')
            return render_template('auth/complete_profile.html', user=user)
    
    return render_template('auth/complete_profile.html', user=user)

def generate_session_token():
    """Generate a unique session token"""
    token = secrets.token_urlsafe(32)
    
    # Verify token doesn't exist in database
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    while True:
        cursor.execute('SELECT id FROM sessions WHERE session_token = ?', (token,))
        if not cursor.fetchone():
            break
        token = secrets.token_urlsafe(32)
    
    conn.close()
    return token

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Verify credentials
        result = verify_credentials(username, password)
        
        if result['status'] == 'success':
            # Set session
            session['session_token'] = result['session_token']
            session['username'] = result['user']['username']
            session['role'] = result['user']['role']
            
            # Log success
            logger.info(f"User {username} (role: {result['user']['role']}) logged in successfully")
            
            # Redirect based on role
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            flash(result.get('message', 'Invalid credentials'), 'danger')
            return render_template('auth/login.html')
            
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    # ... your existing register route code ...
    pass


@auth_bp.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
