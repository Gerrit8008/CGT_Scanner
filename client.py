from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import logging
from functools import wraps
from datetime import datetime
from auth_utils import verify_session
from client_db import (
    get_client_by_user_id,
    get_deployed_scanners_by_client_id,
    get_scan_history_by_client_id,
    get_scanner_by_id,
    update_scanner_config,
    regenerate_scanner_api_key,
    log_scan,
    get_scan_history,
    get_scanner_stats,
    update_client,
    get_client_statistics,
    get_recent_activities,
    get_available_scanners_for_client,
    get_client_dashboard_data,
    format_scan_results_for_client
)

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Middleware to require client login with role check
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
            
            if result['user']['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
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
        # Changed from user['id'] to user['user_id']
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            logger.info(f"User {user['username']} has no client profile, redirecting to complete_profile")
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
        
        # Get dashboard data
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
        
@client_bp.route('/scanners')
@client_required
def scanners(user):
    """List client's scanners"""
    try:
        client = get_client_by_user_id(user['id'])
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
            
        deployed_scanners = get_deployed_scanners_by_client_id(client['id'])
        return render_template('client/scanners.html',
            user=user,
            client=client,
            scanners=deployed_scanners
        )
    except Exception as e:
        logger.error(f"Error in scanners page: {str(e)}")
        flash('An error occurred while loading scanners', 'danger')
        return redirect(url_for('client.dashboard'))

@client_bp.route('/reports')
@client_required
def reports(user):
    """View scan reports"""
    try:
        client = get_client_by_user_id(user['id'])
        if not client:
            flash('Please complete your client profile', 'info')
            return redirect(url_for('auth.complete_profile'))
            
        scan_history = get_scan_history_by_client_id(client['id'])
        return render_template('client/reports.html',
            user=user,
            client=client,
            scans=scan_history
        )
    except Exception as e:
        logger.error(f"Error in reports page: {str(e)}")
        flash('An error occurred while loading reports', 'danger')
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
        
        # Get scanner statistics
        stats = get_scanner_stats(scanner_id)
        
        return render_template(
            'client/scanner-view.html',
            user=user,
            client=client,
            scanner=scanner,
            scan_history=scan_history,
            stats=stats
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
                # TODO: Implement file handling
                # scanner_data['logo_path'] = save_uploaded_file(logo_file)
            
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                # TODO: Implement file handling
                # scanner_data['favicon_path'] = save_uploaded_file(favicon_file)
            
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
        stats = get_scanner_stats(scanner_id)
        
        # Get scan history for chart data
        scan_history = get_scan_history_by_client_id(client['id'])
        
        return render_template(
            'client/scanner-stats.html',
            user=user,
            client=client,
            scanner=scanner,
            stats=stats,
            scan_history=scan_history
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
        
        # Get scan history with pagination - FIXED: Removed transaction decorator issue
        try:
            # Use a simpler approach for now
            scan_history = get_scan_history_by_client_id(client['id'])
            
            # Apply basic pagination (simplified)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            scans = scan_history[start_idx:end_idx]
            
            total_count = len(scan_history)
            total_pages = (total_count + per_page - 1) // per_page
            
            result = {
                'scans': scans,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': total_count,
                    'total_pages': total_pages
                }
            }
        except Exception as e:
            logging.error(f"Error getting scan history: {e}")
            result = {
                'scans': [],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total_count': 0,
                    'total_pages': 0
                }
            }
        
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
        # TODO: Implement proper ownership verification
        
        # Format scan results for client-friendly display
        formatted_scan = format_scan_results_for_client(scan)
        
        return render_template(
            'client/report-view.html',
            user=user,
            client=client,
            scan=formatted_scan or scan
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
            action = request.form.get('action')
            
            if action == 'update_profile':
                # Process profile update
                settings_data = {
                    'business_name': request.form.get('business_name'),
                    'business_domain': request.form.get('business_domain'),
                    'contact_email': request.form.get('contact_email'),
                    'contact_phone': request.form.get('contact_phone')
                }
                
                result = update_client(client['id'], settings_data, user['user_id'])
                
                if result['status'] == 'success':
                    flash('Profile updated successfully', 'success')
                else:
                    flash(f'Failed to update profile: {result.get("message", "Unknown error")}', 'danger')
            
            elif action == 'update_notifications':
                # Process notification settings
                notification_data = {
                    'notification_email': request.form.get('notification_email', '0') == '1',
                    'notification_email_address': request.form.get('notification_email_address'),
                    'notify_scan_complete': request.form.get('notify_scan_complete', '0') == '1',
                    'notify_critical_issues': request.form.get('notify_critical_issues', '0') == '1',
                    'notify_weekly_reports': request.form.get('notify_weekly_reports', '0') == '1',
                    'notification_frequency': request.form.get('notification_frequency', 'weekly')
                }
                
                result = update_client(client['id'], notification_data, user['user_id'])
                
                if result['status'] == 'success':
                    flash('Notification preferences updated', 'success')
                else:
                    flash(f'Failed to update preferences: {result.get("message", "Unknown error")}', 'danger')
            
            # Handle other actions...
            
            return redirect(url_for('client.settings'))
        
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
        
        # Get statistics for profile display
        stats = get_client_statistics(client['id'])
        
        # Get recent activities
        recent_activities = get_recent_activities(client['id'], 5)
        
        # Get available scanners
        scanners = get_available_scanners_for_client(client['id'])
        
        return render_template(
            'client/profile.html',
            user=user,
            client=client,
            client_stats=stats,
            recent_activities=recent_activities,
            scanners=scanners
        )
    except Exception as e:
        logger.error(f"Error displaying client profile: {str(e)}")
        flash('An error occurred while loading your profile', 'danger')
        return redirect(url_for('client.dashboard'))
