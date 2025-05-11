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
    """User registration page"""
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '')
        
        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('auth/register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name)
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('auth/register.html', 
                                 username=username, 
                                 email=email,
                                 full_name=full_name)
        
        # Create user
        result = create_user(username, email, password, 'client', full_name)
        
        if result['status'] == 'success':
            flash('Registration successful! Please log in', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {result["message"]}', 'danger')
            return render_template('auth/register.html', 
                                username=username, 
                                email=email,
                                full_name=full_name)
    
    # GET request - show registration form
    return render_template('auth/register.html')

def register_client(user_id, business_data):
    """
    Register a client for a user with improved error handling
    
    Args:
        user_id (int): User ID
        business_data (dict): Business information
        
    Returns:
        dict: Client registration result
    """
    from fix_database import get_db_connection
    
    try:
        # Check for required fields
        if not business_data.get('business_name') or not business_data.get('business_domain') or not business_data.get('contact_email'):
            return {"status": "error", "message": "Business name, domain, and contact email are required"}
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute('SELECT id, role FROM users WHERE id = ? AND active = 1', (user_id,))
            user = cursor.fetchone()
            
            if not user:
                return {"status": "error", "message": "User not found or inactive"}
            
            # Check if client already exists for this user
            cursor.execute('SELECT id FROM clients WHERE user_id = ?', (user_id,))
            existing_client = cursor.fetchone()
            
            if existing_client:
                return {"status": "error", "message": "Client already registered for this user"}
            
            # Generate API key
            import secrets
            api_key = secrets.token_hex(16)
            
            # Get current timestamp
            from datetime import datetime
            now = datetime.now().isoformat()
            
            # Insert client record
            cursor.execute('''
            INSERT INTO clients (
                user_id, business_name, business_domain, contact_email, contact_phone,
                scanner_name, subscription_level, subscription_status, subscription_start,
                api_key, created_at, created_by, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            ''', (
                user_id,
                business_data.get('business_name'),
                business_data.get('business_domain'),
                business_data.get('contact_email'),
                business_data.get('contact_phone', ''),
                business_data.get('scanner_name', business_data.get('business_name') + ' Scanner'),
                business_data.get('subscription_level', 'basic'),
                'active',
                now,
                api_key,
                now,
                user_id
            ))
            
            client_id = cursor.lastrowid
            
            # Insert customization record with default values
            try:
                import json
                cursor.execute('''
                INSERT INTO customizations (
                    client_id, primary_color, secondary_color, email_subject, email_intro, 
                    default_scans, last_updated, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    client_id,
                    business_data.get('primary_color', '#FF6900'),
                    business_data.get('secondary_color', '#808588'),
                    business_data.get('email_subject', 'Your Security Scan Report'),
                    business_data.get('email_intro', 'Thank you for using our security scanner.'),
                    json.dumps(business_data.get('default_scans', ['network', 'web', 'email', 'system'])),
                    now,
                    user_id
                ))
            except Exception as custom_error:
                logging.warning(f"Error creating customization record: {custom_error}")
            
            # Create scanner deployment record
            try:
                subdomain = business_data.get('business_name', '').lower()
                # Clean up subdomain to be URL-friendly
                subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
                # Remove consecutive dashes
                subdomain = '-'.join(filter(None, subdomain.split('-')))
                
                # Check for duplicate subdomain
                cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
                if cursor.fetchone():
                    subdomain = f"{subdomain}-{client_id}"
                
                cursor.execute('''
                INSERT INTO deployed_scanners 
                (client_id, subdomain, deploy_status, deploy_date, last_updated, template_version)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    client_id,
                    subdomain,
                    'pending',
                    now,
                    now,
                    '1.0'
                ))
            except Exception as deploy_error:
                logging.warning(f"Error creating scanner deployment: {deploy_error}")
            
            conn.commit()
            
            return {
                "status": "success", 
                "client_id": client_id, 
                "message": "Client registered successfully",
                "api_key": api_key
            }
            
    except Exception as e:
        logging.error(f"Error in register_client: {e}")
        return {"status": "error", "message": str(e)}
        
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
        
        # Validate required fields
        if not business_data['business_name'] or not business_data['business_domain']:
            flash('Business name and domain are required', 'danger')
            return render_template('auth/complete-profile.html', user=user)
        
        # Use the improved register_client function
        try:
            from fix_database import get_db_connection
            
            # Use the improved client registration function
            result = register_client(user['user_id'], business_data)
            
            if result['status'] == 'success':
                flash('Profile created successfully!', 'success')
                # Redirect to client dashboard
                return redirect(url_for('client.dashboard'))
            else:
                flash(f'Error creating profile: {result.get("message", "Unknown error")}', 'danger')
                # Stay on the form page
                return render_template('auth/complete-profile.html', user=user)
        except Exception as e:
            import traceback
            logging.error(f"Complete profile error: {str(e)}")
            logging.error(traceback.format_exc())
            flash(f'An error occurred during profile creation: {str(e)}', 'danger')
            return render_template('auth/complete-profile.html', user=user, error=str(e))
    
    # Show the profile completion form
    return render_template('auth/complete-profile.html', user=user)
