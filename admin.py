# admin.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import os
import logging
from datetime import datetime, timedelta
from client_db import get_db_connection, get_dashboard_summary, list_clients
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
    """Admin dashboard with summary statistics"""
    try:
        # Connect to the database
        from client_db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get dashboard summary data with the cursor parameter
        summary = get_dashboard_summary(cursor)
        
        # Get recent clients with proper parameters
        # Removed sort_by parameter that was causing an error
        recent_clients_result = list_clients(cursor, page=1, per_page=5)
        if recent_clients_result and 'clients' in recent_clients_result:
            recent_clients = recent_clients_result['clients']
        else:
            # Handle the case where 'clients' key is missing
            recent_clients = []
        
        # Close the connection
        conn.close()
        
        # Render dashboard template
        # Changed 'summary' to 'dashboard_stats' to match template expectations
        return render_template(
            'admin/admin-dashboard.html',
            user=user,
            dashboard_stats=summary,
            recent_clients=recent_clients
        )
    except Exception as e:
        import traceback
        print(f"Error in dashboard: {e}")
        print(traceback.format_exc())
        # Return a simple error page
        return render_template(
            'admin/error.html',
            error=f"Error loading dashboard: {str(e)}"
        )

# User management
@admin_bp.route('/users')
@admin_required
def user_list(user):
    """User management"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    filters = {}
    if 'role' in request.args and request.args.get('role'):
        filters['role'] = request.args.get('role')
    if 'search' in request.args and request.args.get('search'):
        filters['search'] = request.args.get('search')
    if 'status' in request.args and request.args.get('status') and request.args.get('status') != 'all':
        filters['active'] = request.args.get('status') == 'active'
    
    # Get users
    from client_db import list_users
    users = list_users(page, per_page, filters)
    
    return render_template(
        'admin/user-management.html',
        user=user,
        users=users.get('users', []),
        pagination=users.get('pagination', {}),
        role_filter=filters.get('role', ''),
        search=filters.get('search', '')
    )

# User creation route
@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def user_create(user):
    """Create new user"""
    if request.method == 'POST':
        # Process form submission
        from client_db import create_user
        
        # Extract form data
        user_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'role': request.form.get('role', 'client'),
            'full_name': request.form.get('full_name', '')
        }
        
        # Validate form data
        if not user_data['username'] or not user_data['email'] or not user_data['password']:
            flash('All required fields must be filled', 'danger')
            return render_template('admin/user-create.html', form_data=user_data)
            
        # Check password confirmation
        if request.form.get('password') != request.form.get('confirm_password'):
            flash('Passwords do not match', 'danger')
            return render_template('admin/user-create.html', form_data=user_data)
        
        # Create the user
        result = create_user(
            user_data['username'],
            user_data['email'],
            user_data['password'],
            user_data['role'],
            user_data['full_name']
        )
        
        if result.get('status') == 'success':
            flash('User created successfully', 'success')
            return redirect(url_for('admin.user_list'))
        else:
            flash(f'Error creating user: {result.get("message", "Unknown error")}', 'danger')
            return render_template('admin/user-create.html', form_data=user_data)
    
    # GET request - render form
    return render_template('admin/user-create.html', user=user)

@admin_bp.route('/clients')
@admin_required
def clients(user):
    """Admin clients management page"""
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
    
    try:
        # Try to use list_clients function
        clients_data = list_clients(cursor, page, per_page, filters)
    except Exception as e:
        # Fallback to direct DB query if function not available
        logging.error(f"Error using list_clients: {e}")
        try:
            # Direct query implementation
            cursor.execute("SELECT * FROM clients ORDER BY id DESC LIMIT ? OFFSET ?", 
                          (per_page, (page - 1) * per_page))
            clients = [dict(row) for row in cursor.fetchall()]
            
            # Get total count
            cursor.execute("SELECT COUNT(*) FROM clients")
            total_count = cursor.fetchone()[0]
            
            clients_data = {
                'clients': clients,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': total_count,
                    'total_pages': (total_count + per_page - 1) // per_page
                }
            }
        except Exception as direct_error:
            logging.error(f"Error with direct client query: {direct_error}")
            clients_data = {
                'clients': [],
                'pagination': {
                    'page': 1, 
                    'per_page': per_page,
                    'total_count': 0,
                    'total_pages': 1
                }
            }
    
    conn.close()
    
    return render_template(
        'admin/client-management.html',
        user=user,
        clients=clients_data.get('clients', []),
        pagination=clients_data.get('pagination', {}),
        subscription_filter=filters.get('subscription', ''),
        search=filters.get('search', '')
    )
    
@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def user_edit(user, user_id):
    """Edit existing user"""
    from client_db import get_user_by_id, update_user
    
    # Get user data
    target_user = get_user_by_id(user_id)
    if not target_user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.user_list'))
    
    if request.method == 'POST':
        # Process form submission
        user_data = {
            'username': request.form.get('username'),
            'email': request.form.get('email'),
            'role': request.form.get('role', 'client'),
            'full_name': request.form.get('full_name', ''),
            'active': 1 if request.form.get('active') else 0
        }
        
        # Check if password is being updated
        password = request.form.get('password')
        if password and password.strip():
            # Validate password confirmation
            if password != request.form.get('confirm_password'):
                flash('Passwords do not match', 'danger')
                return render_template('admin/user-edit.html', user=user, edit_user=target_user)
            
            user_data['password'] = password
        
        # Update the user
        result = update_user(user_id, user_data)
        
        if result.get('status') == 'success':
            flash('User updated successfully', 'success')
            return redirect(url_for('admin.user_list'))
        else:
            flash(f'Error updating user: {result.get("message", "Unknown error")}', 'danger')
            return render_template('admin/user-edit.html', user=user, edit_user=target_user)
    
    # GET request - render form
    return render_template('admin/user-edit.html', user=user, edit_user=target_user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def user_delete(user, user_id):
    """Delete/deactivate user"""
    from client_db import deactivate_user
    
    # Cannot delete yourself
    if user_id == user['id']:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin.user_list'))
    
    # Deactivate the user
    result = deactivate_user(user_id)
    
    if result.get('status') == 'success':
        flash('User deleted successfully', 'success')
    else:
        flash(f'Error deleting user: {result.get("message", "Unknown error")}', 'danger')
    
    return redirect(url_for('admin.user_list'))
