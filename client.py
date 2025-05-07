# client.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import os
import logging
from datetime import datetime

# Import authentication utilities
from auth_utils import verify_session

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Middleware to require client login
def client_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success':
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('auth.login', next=request.url))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

# Client dashboard
@client_bp.route('/dashboard')
@client_required
def dashboard(user):
    """Client dashboard"""
    # Get client info for this user
    from client_db import get_client_by_user_id
    client = get_client_by_user_id(user['user_id'])
    
    if not client:
        # Client record doesn't exist yet - redirect to complete profile
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
