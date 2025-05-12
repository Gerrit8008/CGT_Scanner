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
    log_scan,
    get_scan_history,
    get_scanner_stats,
    update_client,
    get_client_statistics,
    get_recent_activities,
    get_available_scanners_for_client,
    get_client_dashboard_data,
    format_scan_results_for_client,
    register_client  # Add this import
)

# Define client blueprint
client_bp = Blueprint('client', __name__, url_prefix='/client')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        
        # No changes to the create_scanner behavior - the critical part is that we
        # don't redirect to complete_profile, even if client is None
        # We will use default values for the dashboard if client is None
        
        if not client:
            logger.info(f"User {user['username']} has no client profile, using defaults for dashboard")
            # Create a default client object for the template
            client = {
                'id': 0,
                'business_name': user.get('full_name', '') or user.get('username', 'New Client'),
                'subscription_level': 'basic'
            }
            
            # Set default data for the dashboard
            scanners = []
            scan_history = []
            dashboard_data = {
                'client': client,
                'stats': {
                    'scanners_count': 0,
                    'total_scans': 0,
                    'avg_security_score': 0,
                    'reports_count': 0
                },
                'scanners': scanners,
                'scan_history': scan_history,
                'recent_activities': []
            }
        else:
            # Normal flow - get real data for existing client
            # Get comprehensive dashboard data - Pass client_id
            dashboard_data = get_client_dashboard_data(client['id'])
            
            if not dashboard_data:
                # Fallback to basic data if comprehensive fetch fails
                scanners = get_deployed_scanners_by_client_id(client['id'])
                scan_history = get_scan_history_by_client_id(client['id'], limit=5)
                total_scans = len(get_scan_history_by_client_id(client['id']))
                
                dashboard_data = {
                    'client': client,
                    'stats': {
                        'scanners_count': len(scanners.get('scanners', [])),
                        'total_scans': total_scans,
                        'avg_security_score': 75,  # Numeric default
                        'reports_count': 0
                    },
                    'scanners': scanners.get('scanners', []),
                    'scan_history': scan_history,
                    'recent_activities': []
                }
        
        # Ensure all required template variables are present
        stats = dashboard_data['stats']
        
        # FIXED: Ensure avg_security_score is a number
        try:
            avg_security_score = float(stats.get('avg_security_score', 0))
        except (ValueError, TypeError):
            avg_security_score = 0
        
        template_vars = {
            'user': user,
            'client': dashboard_data['client'],
            'user_client': dashboard_data['client'],
            'scanners': dashboard_data['scanners'],
            'scan_history': dashboard_data['scan_history'],
            'total_scans': stats.get('total_scans', 0),
            'client_stats': stats,
            'recent_activities': dashboard_data.get('recent_activities', []),
            # Add missing variables with proper types
            'scan_trends': {
                'scanner_growth': 0,
                'scan_growth': 0
            },
            'critical_issues': stats.get('critical_issues', 0),
            'avg_security_score': avg_security_score,  # Ensure this is a number
            'critical_issues_trend': 0,
            'security_score_trend': 0,
            'security_status': 'Good' if avg_security_score > 70 else 'Fair' if avg_security_score > 40 else 'Needs Improvement',
            'high_issues': stats.get('high_issues', 0),
            'medium_issues': stats.get('medium_issues', 0),
            'recommendations': [],  # Default empty recommendations
            'scans_used': 0,  # Default scans used
            'scans_limit': 50,  # Default scans limit
            'scanner_limit': 1  # Default scanner limit
        }
        
        # IMPORTANT: Ensure the correct URL for the "Create New Scanner" button
        # Make sure the button in the client-dashboard.html has the correct href
        # It should be: href="/preview/customize" instead of href="/customize"
        
        return render_template('client/client-dashboard.html', **template_vars)
        
    except Exception as e:
        logger.error(f"Error displaying client dashboard: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Fallback to basic dashboard with safe defaults
        return render_template('client/client-dashboard.html', 
                              user=user, 
                              error=str(e),
                              user_client={},
                              scanners=[],
                              scan_history=[],
                              total_scans=0,
                              client_stats={},
                              recent_activities=[],
                              scan_trends={'scanner_growth': 0, 'scan_growth': 0},
                              critical_issues=0,
                              avg_security_score=0,  # Numeric default
                              critical_issues_trend=0,
                              security_score_trend=0,
                              security_status='Unknown',
                              high_issues=0,
                              medium_issues=0,
                              recommendations=[],
                              scans_used=0,
                              scans_limit=50,
                              scanner_limit=1)
        
@client_bp.route('/scanners')
@client_required
def scanners(user):
    """List all scanners for the client"""
    try:
        # Get client info
        client = get_client_by_user_id(user['user_id'])
        
        if not client:
            # Instead of redirecting to complete_profile, just show empty scanner list
            flash('Please create your first scanner to get started', 'info')
            return render_template(
                'client/scanners.html',
                user=user,
                client={
                    'id': 0,
                    'business_name': user.get('full_name', '') or user.get('username', 'New Client'),
                    'subscription_level': 'basic'
                },
                scanners=[],
                pagination={'page': 1, 'per_page': 10, 'total_pages': 1, 'total_count': 0},
                filters={}
            )
        
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
            # Redirect to dashboard for auto-creation
            return redirect(url_for('client.dashboard'))
        
        # Create a default two_factor_secret for the template
        two_factor_secret = "ABCDEFGHIJKLMNOP"  # This would normally be generated
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            # Handle profile update
            if action == 'update_profile':
                # Process profile update
                settings_data = {
                    'business_name': request.form.get('business_name'),
                    'business_domain': request.form.get('business_domain'),
                    'contact_email': request.form.get('contact_email'),
                    'contact_phone': request.form.get('contact_phone')
                }
                
                # Log the data being submitted for debugging
                logger.info(f"Updating client profile with data: {settings_data}")
                
                # Update the client information in the database
                result = update_client(client['id'], settings_data, user['user_id'])
                
                if result['status'] == 'success':
                    flash('Profile updated successfully', 'success')
                    # Refresh client data after update
                    client = get_client_by_user_id(user['user_id'])
                else:
                    flash(f'Failed to update profile: {result.get("message", "Unknown error")}', 'danger')
            
            # Handle notification preferences
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
                
                # Update the client notification preferences
                result = update_client(client['id'], notification_data, user['user_id'])
                
                if result['status'] == 'success':
                    flash('Notification preferences updated', 'success')
                    # Refresh client data after update
                    client = get_client_by_user_id(user['user_id'])
                else:
                    flash(f'Failed to update preferences: {result.get("message", "Unknown error")}', 'danger')
            
            # Handle password change
            elif action == 'change_password':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                # Validate passwords
                if not current_password or not new_password or not confirm_password:
                    flash('All password fields are required', 'danger')
                elif new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                else:
                    # Verify current password and update to new password
                    try:
                        # Get user data for verification
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT password_hash, salt FROM users WHERE id = ?", (user['user_id'],))
                        user_data = cursor.fetchone()
                        conn.close()
                        
                        if not user_data:
                            flash('User not found', 'danger')
                        else:
                            # Verify current password
                            from auth_utils import hash_password
                            current_hash, _ = hash_password(current_password, user_data['salt'])
                            
                            if current_hash == user_data['password_hash']:
                                # Current password is correct, update to new password
                                new_hash, new_salt = hash_password(new_password)
                                
                                # Update password in database
                                conn = get_db_connection()
                                cursor = conn.cursor()
                                cursor.execute("""
                                    UPDATE users 
                                    SET password_hash = ?, salt = ? 
                                    WHERE id = ?
                                """, (new_hash, new_salt, user['user_id']))
                                conn.commit()
                                conn.close()
                                
                                flash('Password updated successfully', 'success')
                            else:
                                flash('Current password is incorrect', 'danger')
                    except Exception as e:
                        logger.error(f"Error updating password: {e}")
                        flash('An error occurred while updating your password', 'danger')
            
            # After processing form, redirect to same page to prevent form resubmission
            return redirect(url_for('client.settings'))
        
        # For GET requests, render the settings template with client data
        return render_template(
            'client/settings.html',
            user=user,
            client=client,
            two_factor_secret=two_factor_secret
        )
    except Exception as e:
        logger.error(f"Error in settings: {str(e)}")
        flash('An error occurred while loading settings', 'danger')
        return redirect(url_for('client.dashboard'))

def update_client(client_id, data, user_id):
    """Update client information"""
    try:
        # Log the update operation
        logger.info(f"Updating client {client_id} with data: {data}")
        
        # Connect to database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Start with an empty update_fields dictionary and params list
        update_fields = []
        params = []
        
        # Add non-empty fields to update
        if 'business_name' in data and data['business_name']:
            update_fields.append("business_name = ?")
            params.append(data['business_name'])
            
        if 'business_domain' in data and data['business_domain']:
            update_fields.append("business_domain = ?")
            params.append(data['business_domain'])
            
        if 'contact_email' in data and data['contact_email']:
            update_fields.append("contact_email = ?")
            params.append(data['contact_email'])
            
        if 'contact_phone' in data:  # Allow empty phone
            update_fields.append("contact_phone = ?")
            params.append(data['contact_phone'])
            
        # Handle subscription changes if present
        if 'subscription_level' in data:
            update_fields.append("subscription_level = ?")
            params.append(data['subscription_level'])
            
        # Handle notification preferences
        if 'notification_email' in data:
            # Convert boolean to integer
            notification_email = 1 if data['notification_email'] else 0
            update_fields.append("notification_email = ?")
            params.append(notification_email)
            
        if 'notification_email_address' in data:
            update_fields.append("notification_email_address = ?")
            params.append(data['notification_email_address'])
            
        if 'notify_scan_complete' in data:
            notify_scan_complete = 1 if data['notify_scan_complete'] else 0
            update_fields.append("notify_scan_complete = ?")
            params.append(notify_scan_complete)
            
        if 'notify_critical_issues' in data:
            notify_critical_issues = 1 if data['notify_critical_issues'] else 0
            update_fields.append("notify_critical_issues = ?")
            params.append(notify_critical_issues)
            
        if 'notify_weekly_reports' in data:
            notify_weekly_reports = 1 if data['notify_weekly_reports'] else 0
            update_fields.append("notify_weekly_reports = ?")
            params.append(notify_weekly_reports)
            
        if 'notification_frequency' in data:
            update_fields.append("notification_frequency = ?")
            params.append(data['notification_frequency'])
        
        # Add timestamp and user_id to update
        update_fields.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        
        update_fields.append("updated_by = ?")
        params.append(user_id)
        
        # Add client_id to params
        params.append(client_id)
        
        # If no fields to update, return success
        if not update_fields:
            return {"status": "success", "message": "No changes detected"}
        
        # Build and execute update query
        update_query = f"UPDATE clients SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(update_query, params)
        
        # Log the SQL query for debugging
        logger.debug(f"Executing SQL: {update_query} with params {params}")
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": "Client updated successfully"}
    except Exception as e:
        logger.error(f"Error updating client: {e}")
        if conn:
            conn.rollback()
            conn.close()
        return {"status": "error", "message": str(e)}

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
