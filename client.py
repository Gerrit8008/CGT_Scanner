from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import os
import logging
import json
from datetime import datetime
from functools import wraps

# Import authentication utilities
from auth_utils import verify_session
from client_db import (
    get_client_by_user_id, 
    get_deployed_scanners_by_client_id,
    get_scan_history_by_client_id,
    get_scanner_by_id,
    update_scanner_config,
    regenerate_scanner_api_key,
    log_scan
)

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
    
@client_bp.route('/dashboard')
@client_required
def dashboard(user):
    """Client dashboard"""
    try:
        # Get client info for this user
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            # Client record doesn't exist yet - redirect to complete profile
            logger.info(f"User {user['username']} has no client profile, redirecting to complete_profile")
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get client's scanners
        scanners = get_deployed_scanners_by_client_id(client['id'])
        
        # Get scan history
        scan_history = get_scan_history_by_client_id(client['id'], limit=5)
        
        # Count total scans
        total_scans = len(get_scan_history_by_client_id(client['id']))
        
        # Pass client as user_client for template compatibility
        return render_template(
            'client/client-dashboard.html',
            user=user,
            client=client,
            user_client=client,  # Add this line to make user_client available
            scanners=scanners.get('scanners', []),
            scan_history=scan_history,
            total_scans=total_scans
        )
    except Exception as e:
        logger.error(f"Error displaying client dashboard: {str(e)}")
        # Pass empty user_client to avoid template errors
        return render_template('client/client-dashboard.html', 
                              user=user, 
                              error=str(e),
                              user_client={})  # Add this to provide an empty user_client

@client_bp.route('/scanners')
@client_required
def scanners(user):
    """List all scanners for the client"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Get filters
        filters = {}
        if 'status' in request.args and request.args.get('status'):
            filters['status'] = request.args.get('status')
        if 'search' in request.args and request.args.get('search'):
            filters['search'] = request.args.get('search')
        
        # Get client's scanners with pagination
        result = get_deployed_scanners_by_client_id(client['id'], page, per_page, filters)
        
        return render_template(
            'client/scanners.html',
            user=user,
            client=client,
            scanners=result.get('scanners', []),
            pagination=result.get('pagination', {}),
            filters=filters
        )
    except Exception as e:
        logger.error(f"Error displaying client scanners: {str(e)}")
        flash('An error occurred while loading your scanners', 'danger')
        return redirect(url_for('client.dashboard'))

@client_bp.route('/scanners/<int:scanner_id>/view')
@client_required
def scanner_view(user, scanner_id):
    """View details of a specific scanner"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get scanner details
        scanner = get_scanner_by_id(scanner_id)
        
        if not scanner or scanner['client_id'] != client['id']:
            flash('Scanner not found', 'danger')
            return redirect(url_for('client.scanners'))
        
        # Get scan history for this scanner
        scan_history = get_scan_history_by_client_id(client['id'], limit=10)
        
        return render_template(
            'client/scanner-view.html',
            user=user,
            client=client,
            scanner=scanner,
            scan_history=scan_history
        )
    except Exception as e:
        logger.error(f"Error displaying scanner details: {str(e)}")
        flash('An error occurred while loading scanner details', 'danger')
        return redirect(url_for('client.scanners'))

@client_bp.route('/scanners/<int:scanner_id>/edit', methods=['GET', 'POST'])
@client_required
def scanner_edit(user, scanner_id):
    """Edit scanner configuration"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get scanner details
        scanner = get_scanner_by_id(scanner_id)
        
        if not scanner or scanner['client_id'] != client['id']:
            flash('Scanner not found', 'danger')
            return redirect(url_for('client.scanners'))
        
        if request.method == 'POST':
            # Process form submission
            scanner_data = {
                'scanner_name': request.form.get('scanner_name'),
                'business_domain': request.form.get('business_domain'),
                'contact_email': request.form.get('contact_email'),
                'contact_phone': request.form.get('contact_phone'),
                'primary_color': request.form.get('primary_color'),
                'secondary_color': request.form.get('secondary_color'),
                'email_subject': request.form.get('email_subject'),
                'email_intro': request.form.get('email_intro'),
                'default_scans': request.form.getlist('default_scans[]')
            }
            
            # Handle file uploads
            if 'logo' in request.files and request.files['logo'].filename:
                logo_file = request.files['logo']
                # Save logo file (implement file handling)
                # scanner_data['logo_path'] = saved_path
            
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                # Save favicon file (implement file handling)
                # scanner_data['favicon_path'] = saved_path
            
            # Update scanner
            result = update_scanner_config(scanner_id, scanner_data, user['user_id'])
            
            if result['status'] == 'success':
                flash('Scanner updated successfully', 'success')
                return redirect(url_for('client.scanner_view', scanner_id=scanner_id))
            else:
                flash(f'Failed to update scanner: {result.get("message", "Unknown error")}', 'danger')
        
        return render_template(
            'client/scanner-edit.html',
            user=user,
            client=client,
            scanner=scanner
        )
    except Exception as e:
        logger.error(f"Error editing scanner: {str(e)}")
        flash('An error occurred while editing the scanner', 'danger')
        return redirect(url_for('client.scanners'))

@client_bp.route('/scanners/<int:scanner_id>/stats')
@client_required
def scanner_stats(user, scanner_id):
    """View scanner statistics"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get scanner details
        scanner = get_scanner_by_id(scanner_id)
        
        if not scanner or scanner['client_id'] != client['id']:
            flash('Scanner not found', 'danger')
            return redirect(url_for('client.scanners'))
        
        # Get scan statistics
        from client_db import get_scanner_stats
        stats = get_scanner_stats(scanner_id)
        
        return render_template(
            'client/scanner-stats.html',
            user=user,
            client=client,
            scanner=scanner,
            stats=stats
        )
    except Exception as e:
        logger.error(f"Error displaying scanner stats: {str(e)}")
        flash('An error occurred while loading scanner statistics', 'danger')
        return redirect(url_for('client.scanners'))

@client_bp.route('/scanners/<int:scanner_id>/regenerate-api-key', methods=['POST'])
@client_required
def scanner_regenerate_api_key(user, scanner_id):
    """Regenerate API key for a scanner"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            return jsonify({'status': 'error', 'message': 'Client not found'})
        
        # Get scanner details
        scanner = get_scanner_by_id(scanner_id)
        
        if not scanner or scanner['client_id'] != client['id']:
            return jsonify({'status': 'error', 'message': 'Scanner not found'})
        
        # Regenerate API key
        result = regenerate_scanner_api_key(scanner_id, user['user_id'])
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error regenerating API key: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@client_bp.route('/reports')
@client_required
def reports(user):
    """List scan reports for the client"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Get filters
        filters = {}
        if 'scanner' in request.args and request.args.get('scanner'):
            filters['scanner_id'] = request.args.get('scanner')
        if 'date_from' in request.args and request.args.get('date_from'):
            filters['date_from'] = request.args.get('date_from')
        if 'date_to' in request.args and request.args.get('date_to'):
            filters['date_to'] = request.args.get('date_to')
        
        # Get scan history with pagination
        from client_db import get_scan_history
        result = get_scan_history(client['id'], page=page, per_page=per_page)
        
        # Get list of client's scanners for filter dropdown
        scanners_result = get_deployed_scanners_by_client_id(client['id'])
        scanners = scanners_result.get('scanners', [])
        
        return render_template(
            'client/reports.html',
            user=user,
            client=client,
            scans=result.get('scans', []),
            pagination=result.get('pagination', {}),
            scanners=scanners,
            filters=filters
        )
    except Exception as e:
        logger.error(f"Error displaying reports: {str(e)}")
        flash('An error occurred while loading reports', 'danger')
        return redirect(url_for('client.dashboard'))

@client_bp.route('/reports/<scan_id>')
@client_required
def report_view(user, scan_id):
    """View a specific scan report"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get scan details
        from db import get_scan_results
        scan = get_scan_results(scan_id)
        
        if not scan:
            flash('Scan report not found', 'danger')
            return redirect(url_for('client.reports'))
        
        # Verify this scan belongs to the client
        # Note: You may need to add client_id to scan results table
        # or verify through scanner relationship
        
        return render_template(
            'client/report-view.html',
            user=user,
            client=client,
            scan=scan
        )
    except Exception as e:
        logger.error(f"Error displaying report: {str(e)}")
        flash('An error occurred while loading the report', 'danger')
        return redirect(url_for('client.reports'))

@client_bp.route('/settings', methods=['GET', 'POST'])
@client_required
def settings(user):
    """Client settings and profile management"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        if request.method == 'POST':
            # Process settings update
            settings_data = {
                'business_name': request.form.get('business_name'),
                'business_domain': request.form.get('business_domain'),
                'contact_email': request.form.get('contact_email'),
                'contact_phone': request.form.get('contact_phone'),
                'notification_email': request.form.get('notification_email', '1') == '1',
                'notification_frequency': request.form.get('notification_frequency', 'weekly')
            }
            
            # Update client settings
            from client_db import update_client
            result = update_client(client['id'], settings_data, user['user_id'])
            
            if result['status'] == 'success':
                flash('Settings updated successfully', 'success')
                return redirect(url_for('client.settings'))
            else:
                flash(f'Failed to update settings: {result.get("message", "Unknown error")}', 'danger')
        
        return render_template(
            'client/settings.html',
            user=user,
            client=client
        )
    except Exception as e:
        logger.error(f"Error in settings: {str(e)}")
        flash('An error occurred while loading settings', 'danger')
        return redirect(url_for('client.dashboard'))
        
@client_bp.route('/profile')
@client_required
def profile(user):
    """Client profile page"""
    try:
        # Get client info
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

@client_bp.route('/profile/update', methods=['POST'])
@client_required
def update_profile(user):
    """Update client profile"""
    try:
        # Get client info
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
        from client_db import update_client
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
