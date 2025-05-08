@function_calls
@invoke name="artifacts"
@parameter name="command" create
@parameter name="id" auth_fix
@parameter name="type" application/vnd.ant.code
@parameter name="language" python
@parameter name="title" Fixed auth.py
@parameter name="content"
# auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime

# Import the fixed authenticate_user function
from fix_auth import authenticate_user_wrapper as authenticate_user
from fix_auth import verify_session, logout_user, create_user

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Login route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with proper parameter handling"""
    # Check if already logged in
    session_token = session.get('session_token')
    if session_token:
        result = verify_session(session_token)
        if result['status'] == 'success':
            # User is already logged in - redirect based on role
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
    
    # Get 'next' parameter for redirection after login
    next_url = request.args.get('next', '')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide username and password', 'danger')
            return render_template('auth/login.html', next=next_url)
        
        # Get client IP and user agent for security logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Use the fixed authenticate_user function with all parameters
        result = authenticate_user(username, password, ip_address, user_agent)
        
        if result['status'] == 'success':
            # Store session token and user info in session
            session['session_token'] = result['session_token']
            session['username'] = result['username']
            session['role'] = result['role']
            session['user_id'] = result['user_id']
            
            # Redirect based on role or next parameter
            if next_url:
                return redirect(next_url)
            elif result['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            flash(result['message'], 'danger')
            return render_template('auth/login.html', next=next_url)
    
    # GET request - show login form
    return render_template('auth/login.html', next=next_url)

# Logout route
@auth_bp.route('/logout')
def logout():
    """User logout"""
    session_token = session.get('session_token')
    if session_token:
        logout_user(session_token)
    
    # Clear session
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('auth.login'))

# Registration route for clients
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Client registration page"""
    if request.method == 'POST':
        # Get user registration data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '')
        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html')
        
        # Create user
        user_result = create_user(username, email, password, 'client', full_name)
        
        if user_result['status'] == 'success':
            # Get business registration data
            business_data = {
                'business_name': request.form.get('business_name', ''),
                'business_domain': request.form.get('business_domain', ''),
                'contact_email': email,  # Use the same email as user by default
                'contact_phone': request.form.get('contact_phone', ''),
                'scanner_name': request.form.get('scanner_name', '')
            }
            
            # Register client
            if business_data['business_name'] and business_data['business_domain']:
                from client_db import register_client
                client_result = register_client(user_result['user_id'], business_data)
                
                if client_result['status'] == 'success':
                    flash('Registration successful! You can now log in', 'success')
                else:
                    flash(f'User created but client registration failed: {client_result["message"]}', 'warning')
            else:
                flash('User created successfully. Please log in and complete your client profile', 'success')
            
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {user_result["message"]}', 'danger')
    
    # GET request - show registration form
    return render_template('auth/register.html')

# Client profile completion route
@auth_bp.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    """Complete client profile"""
    # Check if logged in
    session_token = session.get('session_token')
    if not session_token:
        return redirect(url_for('auth.login'))
    
    # Verify session
    session_result = verify_session(session_token)
    if session_result['status'] != 'success':
        # Session invalid - clear and redirect to login
        session.clear()
        return redirect(url_for('auth.login'))
    
    user = session_result['user']
    
    if request.method == 'POST':
        # Get business data
        business_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email', user['email']),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', '')
        }
        
        # Register client
        from client_db import register_client
        client_result = register_client(user['user_id'], business_data)
        
        if client_result['status'] == 'success':
            flash('Client profile completed successfully', 'success')
            return redirect(url_for('client.dashboard'))
        else:
            flash(f'Failed to complete profile: {client_result["message"]}', 'danger')
    
    # GET request - show profile completion form
    return render_template('auth/complete_profile.html', user=user)
@invoke
@function_calls
