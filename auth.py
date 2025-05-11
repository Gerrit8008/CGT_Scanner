# This updated auth.py version fixes the user routing based on roles
import traceback
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime
from auth_utils import create_user, authenticate_user, verify_session
from client_db import register_client, get_client_by_user_id

# Import the fixed authenticate_user function
from fix_auth import authenticate_user_wrapper as authenticate_user
from fix_auth import verify_session, logout_user, create_user

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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Verify credentials and get user info
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

# Registration route for clients
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Client registration page with proper role-based redirection"""
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
        
        # IMPORTANT: Create user with client role (never admin)
        user_role = 'client'  # Force client role for registration
        user_result = create_user(username, email, password, user_role, full_name)
        
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
            
            # Redirect to login after successful registration
            # The login function will then direct them to the client dashboard
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {user_result["message"]}', 'danger')
    
    # GET request - show registration form
    return render_template('auth/register.html')

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
