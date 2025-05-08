from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime
from functools import wraps

# Import authentication utilities
from auth_utils import verify_session

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Middleware to require client login with role check
def client_required(f):
    @wraps(f)  # Preserve function metadata
    def decorated_function(*args, **kwargs):
        # Check for session token
        session_token = session.get('session_token')
        
        if not session_token:
            logger.debug("No session token found, redirecting to login")
            return redirect(url_for('auth.login', next=request.url))
        
        # Verify session token
        result = verify_session(session_token)
        
        if result['status'] != 'success':
            logger.debug(f"Invalid session: {result.get('message')}")
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('auth.login', next=request.url))
        
        # Add role check - ensure user is a client
        if result['user']['role'] != 'client':
            logger.warning(f"Access denied: User {result['user']['username']} with role {result['user']['role']} attempted to access client area")
            flash('Access denied. This area is for clients only.', 'danger')
            
            # Redirect admins to their dashboard
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        logger.debug(f"Client access granted for user: {result['user']['username']}")
        return f(*args, **kwargs)
    
    return decorated_function

# Client dashboard
@client_bp.route('/dashboard')
@client_required
def dashboard(user):
    """Client dashboard"""
    try:
        # Get client info for this user
        from client_db import get_client_by_user_id
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            # Client record doesn't exist yet - redirect to complete profile
            logger.info(f"User {user['username']} has no client profile, redirecting to complete_profile")
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get client's scanners
        from client_db import get_deployed_scanners_by_client_id
        scanners = get_deployed_scanners_by_client_id(client['id'])
        
        # Get scan history
        from client_db import get_scan_history_by_client_id
        scan_history = get_scan_history_by_client_id(client['id'], limit=5)
        
        # Count total scans
        total_scans = len(get_scan_history_by_client_id(client['id']))
        
        return render_template(
            'client/client-dashboard.html',
            user=user,
            client=client,
            scanners=scanners.get('scanners', []),
            scan_history=scan_history,
            total_scans=total_scans
        )
    except Exception as e:
        logger.error(f"Error displaying client dashboard: {str(e)}")
        flash('An error occurred while loading your dashboard', 'danger')
        return render_template('client/client-dashboard.html', user=user, error=str(e))

# Client profile route
@client_bp.route('/profile')
@client_required
def profile(user):
    """Client profile page"""
    try:
        # Get client info
        from client_db import get_client_by_user_id
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        return render_template(
            'client/profile.html',
            user=user,
            client=client
        )
    except Exception as e:
        logger.error(f"Error displaying client profile: {str(e)}")
        flash('An error occurred while loading your profile', 'danger')
        return redirect(url_for('client.dashboard'))

# Update client profile route
@client_bp.route('/profile/update', methods=['POST'])
@client_required
def update_profile(user):
    """Update client profile"""
    try:
        # Get client info
        from client_db import get_client_by_user_id, update_client
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile first', 'warning')
            return redirect(url_for('auth.complete_profile'))
        
        # Get form data
        client_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email'),
            'contact_phone': request.form.get('contact_phone'),
            'scanner_name': request.form.get('scanner_name')
        }
        
        # Update client
        result = update_client(client['id'], client_data, user['user_id'])
        
        if result['status'] == 'success':
            flash('Profile updated successfully', 'success')
        else:
            flash(f'Failed to update profile: {result.get("message", "Unknown error")}', 'danger')
        
        return redirect(url_for('client.profile'))
    except Exception as e:
        logger.error(f"Error updating client profile: {str(e)}")
        flash('An error occurred while updating your profile', 'danger')
        return redirect(url_for('client.profile'))
