# client_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import logging
from datetime import datetime
from client_db import get_db_connection, list_clients, get_client_by_id, update_client
# Import authentication utilities
from auth_utils import verify_session
from scanner_preview import save_scanner_configuration, get_scanner_configuration
import uuid

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@client_bp.route('/scanner/create', methods=['GET', 'POST'])
@admin_required
def create_scanner(user):
    """Create a new scanner configuration"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            client_id = get_client_id_from_session()
            
            # Generate scanner ID
            scanner_id = str(uuid.uuid4())
            
            # Set default configuration if not provided
            scanner_config = {
                'scannerName': data.get('scannerName', 'Default Scanner'),
                'businessDomain': data.get('businessDomain', ''),
                'scanTypes': data.get('scanTypes', ['security_headers', 'ssl_certificate', 'email_security']),
                'primaryColor': data.get('primaryColor', '#FF6900'),
                'secondaryColor': data.get('secondaryColor', '#808588'),
                'logoUrl': data.get('logoUrl', ''),
                'customCss': data.get('customCss', ''),
                'scanFrequency': data.get('scanFrequency', 'daily'),
                'notificationEmail': data.get('notificationEmail', user.get('email', '')),
                'webhookUrl': data.get('webhookUrl', '')
            }
            
            # Save scanner configuration
            result = save_scanner_configuration(
                scanner_id=scanner_id,
                client_id=client_id,
                config_data=scanner_config
            )
            
            if result['status'] == 'success':
                flash('Scanner created successfully!', 'success')
                return jsonify({
                    'status': 'success',
                    'scanner_id': result['scanner_id'],
                    'preview_url': url_for('client.preview_scanner', 
                                         api_key=result['api_key'], 
                                         _external=True),
                    'html_snippet': result['html_snippet'],
                    'embed_script': result['embed_script']
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create scanner'
                }), 500
                
        except Exception as e:
            logging.error(f"Error creating scanner: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    # GET request - show the creation form
    return render_template('client/create_scanner.html', user=user)

@client_bp.route('/scanner/customize/<scanner_id>', methods=['GET', 'POST'])
@admin_required
def customize_scanner(user, scanner_id):
    """Scanner customization page"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Save scanner configuration
            result = save_scanner_configuration(
                scanner_id=scanner_id,
                client_id=get_client_id_from_session(),
                config_data=data
            )
            
            return jsonify({
                'status': 'success',
                'preview_url': url_for('client.preview_scanner', 
                                     api_key=result['api_key'], 
                                     _external=True),
                'html_snippet': result['html_snippet'],
                'embed_script': result['embed_script']
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    # Get existing configuration if any
    scanner = get_scanner_by_id(scanner_id)
    
    return render_template('client/customize_scanner.html', 
                         scanner=scanner,
                         user=user)

@client_bp.route('/scanner/preview/<api_key>')
def preview_scanner(api_key):
    """Preview scanner with specific configuration"""
    config = get_scanner_configuration(api_key)
    if not config:
        abort(404)
    
    return render_template('client/scanner_preview.html',
                         config=config['configuration'],
                         scanner_id=config['scanner_id'])

@client_bp.route('/api/scanner/<api_key>', methods=['GET'])
def get_scanner_config(api_key):
    """Get scanner configuration by API key"""
    try:
        config = get_scanner_configuration(api_key)
        if config:
            return jsonify({
                'status': 'success',
                'configuration': config
            })
        return jsonify({'status': 'error', 'message': 'Scanner not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@client_bp.route('/api/scanner/<api_key>/scan', methods=['POST'])
def run_scanner_scan(api_key):
    """Run a scan using scanner configuration"""
    try:
        config = get_scanner_configuration(api_key)
        if not config:
            return jsonify({'status': 'error', 'message': 'Scanner not found'}), 404
        
        # Get scan parameters from request
        scan_data = request.get_json()
        
        # Validate scan request
        if not scan_data.get('target'):
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400
            
        # Run the scan
        scan_results = run_consolidated_scan({
            'target': scan_data['target'],
            'email': scan_data.get('email'),
            'scan_types': config['configuration']['scan_types']
        })
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_results['scan_id'],
            'results': scan_results
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
