import traceback
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime
from auth_utils import create_user, authenticate_user, verify_session
from client_db import register_client, get_client_by_user_id
from database_manager import DatabaseManager
from database_utils import get_db_connection

# Import the fixed authenticate_user function
from fix_auth import authenticate_user_wrapper as authenticate_user
from fix_auth import verify_session, logout_user, create_user

# Initialize the database manager
db_manager = DatabaseManager()

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with proper role-based redirection and enhanced debugging"""
    # Check if already logged in
    session_token = session.get('session_token')
    if session_token:
        logging.debug(f"Found existing session token: {session_token[:10]}...")
        result = verify_session(session_token)
        if result['status'] == 'success':
            # User is already logged in - redirect based on role
            logging.debug(f"Session valid for user: {result['user']['username']}")
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
    
    # Get 'next' parameter for redirection after login
    next_url = request.args.get('next', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        logging.debug(f"Login attempt for user: {username}")
        
        if not username or not password:
            flash('Please provide username and password', 'danger')
            return render_template('auth/login.html', next=next_url)
        
        # Get client IP and user agent for security logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Use the fixed authenticate_user function with all parameters
        try:
            logging.debug(f"Authenticating user: {username}")
            result = authenticate_user(username, password, ip_address, user_agent)
            logging.debug(f"Authentication result: {result['status']}")
            
            if result['status'] == 'success':
                # Store session token and user info in session
                session['session_token'] = result['session_token']
                session['username'] = result['username']
                session['role'] = result['role']
                session['user_id'] = result['user_id']
                
                # Log successful login
                logging.info(f"User {username} (role: {result['role']}) logged in successfully")
                
                # Redirect based on role or next parameter
                if next_url:
                    logging.debug(f"Redirecting to next URL: {next_url}")
                    return redirect(next_url)
                elif result['role'] == 'admin':
                    logging.debug("Redirecting to admin dashboard")
                    return redirect(url_for('admin.dashboard'))
                else:
                    # All non-admin users go to client dashboard
                    logging.debug("Redirecting to client dashboard")
                    return redirect(url_for('client.dashboard'))
            else:
                logging.warning(f"Login failed for user {username}: {result.get('message', 'Unknown error')}")
                flash(result['message'], 'danger')
                return render_template('auth/login.html', next=next_url)
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            logging.error(traceback.format_exc())
            flash(f"An error occurred during login: {str(e)}", 'danger')
            return render_template('auth/login.html', next=next_url)
    
    # GET request - show login form
    return render_template('auth/login.html', next=next_url)

# Logout route
# Update the logout route in auth.py to accept both GET and POST

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """User logout - accepts both GET and POST methods"""
    try:
        # Get session token
        session_token = session.get('session_token')
        
        if session_token:
            # Use the logout_user function to properly clear session from database
            result = logout_user(session_token)
            logging.debug(f"Session logout result: {result}")
        
        # Clear the Flask session
        session.clear()
        
        # Flash success message
        flash('You have been logged out successfully', 'success')
        
        # Always redirect to login page after logout, regardless of role
        return redirect(url_for('auth.login'))
        
    except Exception as e:
        logging.error(f"Error during logout: {e}")
        # Clear session anyway to ensure logout even if there's an error
        session.clear()
        flash('Logout completed', 'info')
        return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Client registration page with proper role-based redirection"""
    if request.method == 'POST':
        # ... [existing user registration code] ...

        if user_result['status'] == 'success':
            # Get business registration data
            business_data = {
                'business_name': request.form.get('business_name', ''),
                'business_domain': request.form.get('business_domain', ''),
                'contact_email': email,
                'contact_phone': request.form.get('contact_phone', ''),
                'scanner_name': request.form.get('scanner_name', '')
            }
            
            # Register client using the new database manager
            if business_data['business_name'] and business_data['business_domain']:
                client_id = register_client(user_result['user_id'], business_data)
                
                # Create client's specific database
                db_name = db_manager.create_client_database(
                    client_id, 
                    business_data['business_name']
                )
                
                if db_name:
                    flash('Registration successful! You can now log in', 'success')
                else:
                    flash('User created but client database creation failed', 'warning')
            else:
                flash('User created successfully. Please log in and complete your client profile', 'success')
            
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {user_result["message"]}', 'danger')

def register_client(user_id: int, business_data: dict) -> dict:
    """Register a new client and create their database"""
    try:
        with get_db_connection(db_manager.admin_db_path) as conn:
            cursor = conn.cursor()
            
            # Insert client record
            cursor.execute('''
                INSERT INTO clients (
                    user_id, business_name, business_domain, 
                    contact_email, contact_phone, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                business_data['business_name'],
                business_data['business_domain'],
                business_data['contact_email'],
                business_data.get('contact_phone', ''),
                datetime.now().isoformat()
            ))
            
            client_id = cursor.lastrowid
            
            # Create client's specific database
            db_name = db_manager.create_client_database(
                client_id, 
                business_data['business_name']
            )
            
            return {
                "status": "success",
                "client_id": client_id,
                "database": db_name
            }
            
    except Exception as e:
        logging.error(f"Error registering client: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

@auth_bp.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    """Complete user profile after registration"""
    # Check if user is logged in
    session_token = session.get('session_token')
    if not session_token:
        return redirect(url_for('auth.login'))
    
    # Verify session token
    result = verify_session(session_token)
    if result['status'] != 'success':
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('auth.login'))
    
    user = result['user']
    
    # Check if user already has a client profile
    client = get_client_by_user_id(user['user_id'])
    if client:
        # Redirect to appropriate dashboard based on role
        if user['role'] == 'admin':
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        # Process the form submission
        business_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email'),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', request.form.get('business_name', '') + ' Scanner'),
            'subscription_level': 'basic',  # Default to basic
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro', 'Thank you for using our security scanner.'),
            'default_scans': request.form.getlist('default_scans') or ['network', 'web', 'email', 'system']
        }
        
        # Register the client
        result = register_client(user['user_id'], business_data)
        
        if result['status'] == 'success':
            flash('Profile created successfully!', 'success')
            # Redirect to client dashboard
            return redirect(url_for('client.dashboard'))
        else:
            flash(f'Error creating profile: {result.get("message", "Unknown error")}', 'danger')
            # Stay on the form page
            return render_template('auth/complete-profile.html', user=user, error=result.get('message'))
    
    # Show the profile completion form
    return render_template('auth/complete-profile.html', user=user)
