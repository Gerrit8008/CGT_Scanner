# client_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from client_db import get_db_connection, list_clients, get_client_by_id, update_client, deactivate_client
from auth_utils import verify_session

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/admin')

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
    # Deactivate client
    conn = get_db_connection()
    cursor = conn.cursor()
    result = deactivate_client(cursor, client_id, user['id'])
    conn.commit()
    conn.close()
    
    if result and result.get('status') == 'success':
        flash('Client deactivated successfully', 'success')
    else:
        flash(f'Error deactivating client: {result.get("message", "Unknown error")}', 'danger')
    
    return redirect(url_for('client.client_list'))
