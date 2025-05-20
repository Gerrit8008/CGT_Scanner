# auth_decorators.py - Authentication decorators for Flask
from functools import wraps
from flask import session, redirect, url_for, flash, request
import os
import sqlite3
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def login_required(f):
    """
    Decorator to require login for Flask routes
    
    Args:
        f: Flask route function
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token
        session_token = session.get('session_token')
        
        if not session_token:
            # No session token, redirect to login
            return redirect(url_for('auth.login', next=request.url))
        
        # Verify session token
        try:
            # Connect to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find session and join with user
            cursor.execute('''
            SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND u.active = 1
            ''', (session_token,))
            
            session_record = cursor.fetchone()
            
            if not session_record:
                # Invalid session, redirect to login
                conn.close()
                flash('Your session has expired. Please log in again.', 'danger')
                return redirect(url_for('auth.login', next=request.url))
            
            # Add user to kwargs
            user = {
                'user_id': session_record['user_id'],
                'username': session_record['username'],
                'email': session_record['email'],
                'role': session_record['role'],
                'full_name': session_record.get('full_name', '')
            }
            
            kwargs['user'] = user
            
            conn.close()
            
            # Call the original function
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in login_required: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('auth.login'))
    
    return decorated_function

def admin_required(f):
    """
    Decorator to require admin login for Flask routes
    
    Args:
        f: Flask route function
        
    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token
        session_token = session.get('session_token')
        
        if not session_token:
            # No session token, redirect to login
            return redirect(url_for('auth.login', next=request.url))
        
        # Verify session token
        try:
            # Connect to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find session and join with user
            cursor.execute('''
            SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND u.active = 1
            ''', (session_token,))
            
            session_record = cursor.fetchone()
            
            if not session_record:
                # Invalid session, redirect to login
                conn.close()
                flash('Your session has expired. Please log in again.', 'danger')
                return redirect(url_for('auth.login', next=request.url))
            
            # Check if user is admin
            if session_record['role'] != 'admin':
                # Not admin, redirect to login
                conn.close()
                flash('You need administrator privileges to access this page.', 'danger')
                return redirect(url_for('auth.login'))
            
            # Add user to kwargs
            user = {
                'user_id': session_record['user_id'],
                'username': session_record['username'],
                'email': session_record['email'],
                'role': session_record['role'],
                'full_name': session_record.get('full_name', '')
            }
            
            kwargs['user'] = user
            
            conn.close()
            
            # Call the original function
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in admin_required: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('auth.login'))
    
    return decorated_function

def get_current_user():
    """
    Get the current authenticated user
    
    Returns:
        dict: User information or None if not authenticated
    """
    session_token = session.get('session_token')
    
    if not session_token:
        return None
    
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find session and join with user
        cursor.execute('''
        SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND u.active = 1
        ''', (session_token,))
        
        session_record = cursor.fetchone()
        
        if not session_record:
            conn.close()
            return None
        
        # Create user dictionary
        user = {
            'user_id': session_record['user_id'],
            'username': session_record['username'],
            'email': session_record['email'],
            'role': session_record['role'],
            'full_name': session_record.get('full_name', '')
        }
        
        conn.close()
        return user
    except Exception as e:
        logger.error(f"Error in get_current_user: {e}")
        return None
