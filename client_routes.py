from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import logging
from functools import wraps
from datetime import datetime
from client_db import (
    get_client_by_user_id,
    get_deployed_scanners_by_client_id,
    get_scan_history_by_client_id,
    get_client_statistics,
    get_recent_activities
)
from auth_utils import verify_session

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def client_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            logger.debug("No session token found, redirecting to login")
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success':
            logger.debug(f"Invalid session: {result.get('message')}")
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('auth.login', next=request.url))
        
        if result['user']['role'] != 'client':
            logger.warning(f"Access denied: User {result['user']['username']} with role {result['user']['role']} attempted to access client area")
            flash('Access denied. This area is for clients only.', 'danger')
            return redirect(url_for('auth.login'))
        
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    return decorated_function

@client_bp.route('/')
@client_bp.route('/dashboard')
@client_required
def dashboard(user):
    """Client dashboard"""
    try:
        # Get client info for this user
        client = get_client_by_user_id(user['id'])
        
        if not client:
            logger.info(f"User {user['username']} has no client profile, redirecting to complete_profile")
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get client dashboard data
        deployed_scanners = get_deployed_scanners_by_client_id(client['id'])
        recent_scans = get_scan_history_by_client_id(client['id'], limit=5)
        recent_activities = get_recent_activities(client['id'], limit=5)
        statistics = get_client_statistics(client['id'])
        
        return render_template('client/dashboard.html',
            user=user,
            client=client,
            scanners=deployed_scanners,
            recent_scans=recent_scans,
            recent_activities=recent_activities,
            statistics=statistics
        )
    except Exception as e:
        logger.error(f"Error in client dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard', 'danger')
        return redirect(url_for('auth.login'))
        
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

@client_bp.route('/profile')
@admin_required
def profile(user):
    """Client profile page"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user's client if associated
    client = None
    if user and 'id' in user:
        cursor.execute('''
        SELECT * FROM clients 
        WHERE user_id = ? AND active = 1
        ''', (user['id'],))
        client_row = cursor.fetchone()
        if client_row:
            client = dict(client_row)
    
    conn.close()
    
    return render_template(
        'admin/client-profile.html',
        user=user,
        client=client
    )

@client_bp.route('/clients')
@admin_required
def client_list(user):
    """Client management page"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    filters = {}
    if 'subscription' in request.args and request.args.get('subscription'):
        filters['subscription'] = request.args.get('subscription')
    if 'search' in request.args and request.args.get('search'):
        filters['search'] = request.args.get('search')
    if 'status' in request.args and request.args.get('status') and request.args.get('status') != 'all':
        filters['active'] = request.args.get('status') == 'active'
    
    # Get clients
    conn = get_db_connection()
    cursor = conn.cursor()
    clients_data = list_clients(cursor, page, per_page, filters)
    conn.close()
    
    return render_template(
        'admin/client-management.html',
        user=user,
        clients=clients_data.get('clients', []),
        pagination=clients_data.get('pagination', {}),
        subscription_filter=filters.get('subscription', ''),
        search=filters.get('search', '')
    )

@client_bp.route('/clients/<int:client_id>')
@admin_required
def client_view(user, client_id):
    """View client details"""
    # Get client data
    conn = get_db_connection()
    cursor = conn.cursor()
    client = get_client_by_id(cursor, client_id)
    conn.close()
    
    if not client:
        flash('Client not found', 'danger')
        return redirect(url_for('client.client_list'))
    
    return render_template(
        'admin/client-view.html',
        user=user,
        client=client
    )

@client_bp.route('/clients/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def client_edit(user, client_id):
    """Edit client information"""
    # Get client data
    conn = get_db_connection()
    cursor = conn.cursor()
    client = get_client_by_id(cursor, client_id)
    
    if not client:
        conn.close()
        flash('Client not found', 'danger')
        return redirect(url_for('client.client_list'))
    
    if request.method == 'POST':
        # Process form submission
        client_data = {
            'business_name': request.form.get('business_name'),
            'business_domain': request.form.get('business_domain'),
            'contact_email': request.form.get('contact_email'),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', ''),
            'subscription_level': request.form.get('subscription_level', 'basic'),
            'subscription_status': request.form.get('subscription_status', 'active'),
            'active': 1 if request.form.get('active') else 0
        }
        
        # Update client
        result = update_client(cursor, client_id, client_data, user['id'])
        conn.commit()
        
        if result and result.get('status') == 'success':
            flash('Client updated successfully', 'success')
            return redirect(url_for('client.client_list'))
        else:
            flash(f'Error updating client: {result.get("message", "Unknown error")}', 'danger')
    
    conn.close()
    
    return render_template(
        'admin/client-edit.html',
        user=user,
        client=client
    )

@client_bp.route('/clients/<int:client_id>/deactivate', methods=['POST'])
@admin_required
def client_deactivate(user, client_id):
    """Deactivate client"""
    # Since deactivate_client may not be available, we'll use a more generic approach
    try:
        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First check if client exists
        cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
        client = cursor.fetchone()
        
        if not client:
            conn.close()
            flash('Client not found', 'danger')
            return redirect(url_for('client.client_list'))
        
        # Update client status
        cursor.execute('''
        UPDATE clients 
        SET active = 0,
            updated_at = ?,
            updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user['id'], client_id))
        
        # Also update scanner status if available
        try:
            cursor.execute('''
            UPDATE deployed_scanners
            SET deploy_status = 'inactive',
                last_updated = ?
            WHERE client_id = ?
            ''', (datetime.now().isoformat(), client_id))
        except Exception as scanner_error:
            logger.warning(f"Error updating scanner status: {scanner_error}")
        
        # Add to audit log if the table exists
        try:
            cursor.execute('''
            INSERT INTO audit_log (
                user_id, action, entity_type, entity_id, 
                changes, timestamp, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user['id'],
                'deactivate',
                'client',
                client_id,
                '{"active": 0}',
                datetime.now().isoformat(),
                request.remote_addr
            ))
        except Exception as log_error:
            logger.warning(f"Error adding audit log: {log_error}")
        
        conn.commit()
        conn.close()
        
        flash('Client deactivated successfully', 'success')
    except Exception as e:
        logger.error(f"Error deactivating client: {e}")
        flash(f'Error deactivating client: {str(e)}', 'danger')
    
    return redirect(url_for('client.client_list'))
