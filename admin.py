# admin.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime

# Import authentication utilities
from auth_utils import verify_session

# Define admin blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Middleware to require admin login
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            flash('You need administrative privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

# Admin dashboard
@admin_bp.route('/dashboard')
@admin_required
def dashboard(user):
    """Admin dashboard"""
    # Get summary stats
    from client_db import get_dashboard_summary
    summary = get_dashboard_summary()
    
    # Get recent clients
    from client_db import list_clients
    recent_clients = list_clients(page=1, per_page=5).get('clients', [])
    
    return render_template(
        'admin/admin-dashboard.html',
        user=user,
        summary=summary,
        recent_clients=recent_clients
    )

# User management
@admin_bp.route('/users')
@admin_required
def user_list(user):
    """User management"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get users
    from client_db import list_users
    users = list_users(page, per_page)
    
    return render_template(
        'admin/user-management.html',
        user=user,
        users=users.get('users', []),
        pagination=users.get('pagination', {})
    )

# Client management
@admin_bp.route('/clients')
@admin_required
def client_list(user):
    """Client management"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    filters = {}
    if 'subscription' in request.args:
        filters['subscription'] = request.args.get('subscription')
    if 'status' in request.args:
        filters['status'] = request.args.get('status')
    if 'search' in request.args:
        filters['search'] = request.args.get('search')
    
    # Get clients
    from client_db import list_clients
    clients = list_clients(page, per_page, filters)
    
    return render_template(
        'admin/client-management.html',
        user=user,
        clients=clients.get('clients', []),
        pagination=clients.get('pagination', {}),
        filters=filters
    )
