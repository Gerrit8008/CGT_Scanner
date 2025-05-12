from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import json
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import base64
import re
import logging 
from werkzeug.utils import secure_filename
from contextlib import contextmanager

scanner_preview_bp = Blueprint('scanner_preview', __name__)

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads/logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max


# Setup logging configuration
logging.basicConfig(
    filename='scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('client_scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db():
    conn = None
    try:
        conn = get_db_connection()
        yield conn
    finally:
        if conn:
            conn.close()

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def get_client_id_from_session():
    """Get client ID from session"""
    user_id = session.get('user_id')
    if not user_id:
        return None
    
    conn = get_db_connection()
    client = conn.execute(
        "SELECT id FROM clients WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    
    return client['id'] if client else None

def generate_subdomain(scanner_name):
    """Generate a unique subdomain from scanner name"""
    # Clean the scanner name
    subdomain = re.sub(r'[^a-zA-Z0-9\s-]', '', scanner_name).strip()
    subdomain = re.sub(r'[\s-]+', '-', subdomain).lower()
    
    # Ensure subdomain is unique
    conn = get_db_connection()
    base_subdomain = subdomain
    counter = 1
    
    while True:
        existing = conn.execute(
            "SELECT id FROM deployed_scanners WHERE subdomain = ?",
            (subdomain,)
        ).fetchone()
        
        if not existing:
            break
        
        subdomain = f"{base_subdomain}-{counter}"
        counter += 1
    
    conn.close()
    return subdomain

def save_logo_from_base64(base64_data, scanner_id):
    """Save logo from base64 data with improved validation"""
    logger.info(f"Attempting to save logo for scanner {scanner_id}")
    
    if not base64_data:
        logger.warning(f"No logo data provided for scanner {scanner_id}")
        return None
        
    try:
        # Extract the image data from base64
        if ',' in base64_data:
            header, data = base64_data.split(',', 1)
        else:
            data = base64_data
            header = ''

        # Validate file size before processing
        decoded_data = base64.b64decode(data)
        file_size = len(decoded_data)
        if file_size > MAX_CONTENT_LENGTH:
            logger.error(f"Logo file size ({file_size/1024/1024:.2f}MB) exceeds limit of {MAX_CONTENT_LENGTH/1024/1024}MB")
            raise ValueError(f"File size exceeds maximum limit of {MAX_CONTENT_LENGTH/1024/1024}MB")
        
        # Determine file extension from header
        if 'png' in header:
            ext = 'png'
        elif 'jpeg' in header or 'jpg' in header:
            ext = 'jpg'
        elif 'gif' in header:
            ext = 'gif'
        elif 'svg' in header:
            ext = 'svg'
        else:
            ext = 'png'  # Default to png
        
        # Create filename and ensure it's secure
        filename = secure_filename(f"logo_{scanner_id}.{ext}")
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Ensure upload directory exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        
        # Save the file using a temporary file for atomic operation
        temp_filepath = f"{filepath}.tmp"
        with open(temp_filepath, 'wb') as f:
            f.write(decoded_data)
        
        # Atomic rename
        os.replace(temp_filepath, filepath)
        
        logger.info(f"Logo saved successfully for scanner {scanner_id}")
        return f"/static/uploads/logos/{filename}"
        
    except Exception as e:
        logger.error(f"Error saving logo for scanner {scanner_id}: {str(e)}")
        if 'temp_filepath' in locals() and os.path.exists(temp_filepath):
            os.unlink(temp_filepath)
        return None

@scanner_preview_bp.route('/preview/customize', methods=['GET', 'POST'])
@require_login
def customize_preview_scanner():
    """Main scanner creation/customization page for preview"""
    # Get the current user's ID from session at the start
    from flask import session, request, jsonify, render_template
    import logging
    from client_db import create_client, get_client_by_user_id

    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({
            'status': 'error',
            'message': 'User not authenticated'
        }), 401

    if request.method == 'POST':
        try:
            # Check content type
            if not request.is_json:
                return jsonify({
                    'status': 'error',
                    'message': 'Content-Type must be application/json'
                }), 400

            client_data = request.get_json()
            if not client_data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
                
            # Validate required fields
            if not client_data.get('scannerName') or not client_data.get('businessDomain'):
                return jsonify({
                    'status': 'error', 
                    'message': 'Scanner name and business domain are required'
                }), 400
            
            # Format the client data properly
            formatted_client_data = {
                'business_name': client_data.get('scannerName'),
                'business_domain': client_data.get('businessDomain'),
                'contact_email': client_data.get('contactEmail'),
                'contact_phone': client_data.get('contactPhone', ''),
                'scanner_name': client_data.get('scannerName'),
                'primary_color': client_data.get('primaryColor', '#FF6900'),
                'secondary_color': client_data.get('secondaryColor', '#808588'),
                'email_subject': client_data.get('emailSubject', 'Your Security Scan Report'),
                'email_intro': client_data.get('emailIntro', ''),
                'subscription': client_data.get('subscription', 'basic'),
                'default_scans': client_data.get('defaultScans', [])
            }
            
            # Call create_client with both required parameters
            result = create_client(formatted_client_data, user_id)
            
            # Handle the result
            if result and result.get('status') == 'success':
                return jsonify({
                    'status': 'success',
                    'preview_url': f"/preview/scanner/{result.get('client_id')}"
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': result.get('message', 'Failed to create scanner')
                }), 400
                
        except ValueError as ve:
            logging.error(f"Value error in customize_preview_scanner: {str(ve)}")
            return jsonify({'status': 'error', 'message': str(ve)}), 400
        except Exception as e:
            logging.error(f"Error creating scanner: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    
    # For GET requests, get the client data and render the template
    try:
        client = get_client_by_user_id(user_id)
        return render_template('client/customize_scanner.html', client=client)
    except Exception as e:
        logging.error(f"Error fetching client data: {str(e)}")
        # Even if there's an error, render the template with client=None
        return render_template('client/customize_scanner.html', client=None)

@scanner_preview_bp.route('/preview/<scanner_id>')
@require_login
def preview_scanner(scanner_id):
    """Show live preview of the scanner"""
    current_user = session.get('user_id')
    logger.info(f"Accessing scanner preview - ID: {scanner_id} - User: {current_user}")
    
    try:
        conn = get_db_connection()
    
        # Get scanner details
        scanner = conn.execute(
            "SELECT s.*, c.scanner_name as client_scanner_name, c.business_name, c.business_domain "
            "FROM deployed_scanners s "
            "JOIN clients c ON s.client_id = c.id "
            "WHERE s.id = ?",
            (scanner_id,)
        ).fetchone()
    
        if not scanner:
            conn.close()
            return "Scanner not found", 404
    
        # Get customization details
        customization = conn.execute(
            "SELECT * FROM customizations WHERE client_id = ?",
            (scanner['client_id'],)
        ).fetchone()
    
        conn.close()
    
        # Prepare preview data
        preview_data = {
            'scanner_id': scanner_id,
            'scanner_name': scanner['client_scanner_name'] or 'Security Scanner',
            'business_name': scanner['business_name'],
            'business_domain': scanner['business_domain'] or 'example.com',
            'subdomain': scanner['subdomain'],
            'primary_color': customization['primary_color'] if customization else '#FF6900',
            'secondary_color': customization['secondary_color'] if customization else '#808588',
            'logo_path': customization['logo_path'] if customization else None,
            'email_subject': customization['email_subject'] if customization else 'Your Security Scan Report',
            'email_intro': customization['email_intro'] if customization else 'Thank you for using our security scanner.',
            'default_scans': json.loads(customization['default_scans']) if customization and customization['default_scans'] else ['network', 'web', 'email', 'ssl']
        }
        logger.info(f"Preview loaded successfully - Scanner ID: {scanner_id}")
        return render_template('client/scanner_preview.html', **preview_data)
    except Exception as e:
        logger.error(f"Error loading preview - Scanner ID: {scanner_id} - Error: {str(e)}")
        return "Error loading preview", 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()
        
@scanner_preview_bp.route('/api/scanner/run-scan', methods=['POST'])
@require_login
def run_preview_scan():
    """Simulate running a security scan for preview"""
    logger.info(f"Starting preview scan - User: {session.get('user_id')}")
    
    try:
        data = request.get_json()
        target = data.get('target', '')
        scanner_id = data.get('scanner_id', '')
        
        if not target:        
            logger.warning(f"No target URL provided for scanner {scanner_id}")
            return jsonify({'status': 'error', 'message': 'Target URL required'}), 400
        
        # Generate simulated scan results based on target
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]
        
        # Simulate scan progress
        import time
        import random
        
        # Create realistic scan results
        overall_score = random.randint(65, 95)
        risk_level = get_risk_level(overall_score)
        
        findings = [
            {
                'id': str(uuid.uuid4()),
                'category': 'SSL Certificate',
                'status': 'Valid certificate detected' if random.random() > 0.3 else 'Certificate issues detected',
                'severity': 'Low' if random.random() > 0.3 else 'High',
                'color': 'success' if random.random() > 0.3 else 'danger',
                'details': 'Certificate is valid until 2025-12-31' if random.random() > 0.3 else 'Certificate expired or improperly configured'
            },
            # ... other findings
        ]
        
        recommendations = [
            'Implement missing security headers (Content-Security-Policy, X-Frame-Options)',
            'Close unnecessary open ports (3389, 5900, 1433)',
            'Enable HSTS preloading for enhanced security',
            'Consider implementing DNSSEC for domain security',
            'Schedule regular security scans to monitor changes',
            'Update SSL certificate to include all subdomains'
        ]
        
        # Select relevant recommendations based on findings
        selected_recommendations = []
        for finding in findings:
            if finding['severity'] in ['High', 'Medium']:
                if finding['category'] == 'Security Headers':
                    selected_recommendations.append(recommendations[0])
                elif finding['category'] == 'Open Ports':
                    selected_recommendations.append(recommendations[1])
                elif finding['category'] == 'SSL Certificate':
                    selected_recommendations.append(recommendations[5])
        
        # Add general recommendations
        selected_recommendations.extend(recommendations[4:5])
        
        scan_results = {
            'scan_id': str(uuid.uuid4()),
            'target': target,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'overall_score': overall_score,
            'risk_level': risk_level,
            'findings': findings,
            'recommendations': list(set(selected_recommendations))[:5],  # Remove duplicates and limit to 5
            'scan_duration': random.randint(15, 45),  # Seconds
            'scanned_items': random.randint(25, 50)
        }
        
        # Save scan results to database
        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO scan_history (client_id, scan_id, timestamp, target, scan_type, status, report_path) "
                "VALUES ((SELECT client_id FROM deployed_scanners WHERE id = ?), ?, ?, ?, 'full', 'completed', ?)",
                (scanner_id, scan_results['scan_id'], scan_results['timestamp'], target, f"/reports/{scan_results['scan_id']}.json")
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error saving scan history: {e}")
        finally:
            conn.close()
            
        logger.info(f"Preview scan completed successfully for scanner {scanner_id}")
        return jsonify(scan_results)
    except Exception as e:
        logger.error(f"Error in run_preview_scan: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def get_risk_level(score):
    """Determine risk level from score"""
    if score >= 90:
        return 'Excellent'
    elif score >= 75:
        return 'Good'
    elif score >= 60:
        return 'Fair'
    elif score >= 40:
        return 'Poor'
    else:
        return 'Critical'

@scanner_preview_bp.route('/api/scanner/save', methods=['POST'])
@require_login
def save_scanner():
    """Save the scanner configuration"""
    current_user = session.get('user_id')
    logger.info(f"Attempting to save scanner configuration - User: {current_user}")
    data = request.get_json()
    if not data:
        logger.warning(f"No data provided in save request - User: {current_user}")
        return jsonify({
            'status': 'error',
            'message': 'No data provided'
        }), 400
    
    # Sanitize input data
    sanitized_data = {
        'scannerName': data.get('scannerName', '').strip(),
        'businessDomain': data.get('businessDomain', '').strip(),
        # Add other fields as needed
    }
    
    # Validate data
    if not sanitized_data['scannerName']:
        logger.warning(f"Scanner name missing in save request - User: {current_user}")
        return jsonify({
            'status': 'error',
            'message': 'Scanner name is required'
        }), 400
        
    try:
        result = create_scanner(sanitized_data)
        if result['status'] == 'error':
            return jsonify(result), 400
            
        return jsonify({
            'success': True,
            'status': 'success',
            'scannerId': result['scanner_id'],
            'message': 'Scanner saved successfully',
            'preview_url': url_for('scanner_preview.preview_scanner', 
                                 scanner_id=result['scanner_id'])
        })
    except Exception as e:
        logger.error(f"Error saving scanner - User: {current_user} - Error: {str(e)}")
        return jsonify({
            'success': False,
            'status': 'error',
            'message': str(e)
        }), 500

def save_scanner_config(scanner_id, data):
    """Validate and save scanner configuration"""
    required_fields = ['scannerName', 'businessDomain']
    for field in required_fields:
        if not data.get(field):
            raise ValueError(f"Missing required field: {field}")
            
    config_path = os.path.join('config', f"{scanner_id}.json")
    
    # Ensure config directory exists
    os.makedirs('config', exist_ok=True)
    
    config_data = {
        'scanner_name': data.get('scannerName'),
        'business_domain': data.get('businessDomain'),
        'configuration_version': '1.0',
        'last_updated': datetime.now().isoformat(),
        'status': 'deployed'
    }
    
    # Use atomic write operation
    temp_path = f"{config_path}.tmp"
    try:
        with open(temp_path, 'w') as f:
            json.dump(config_data, f, indent=4)
        os.replace(temp_path, config_path)  # Atomic operation
    except Exception as e:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise
    
    return config_path

@scanner_preview_bp.route('/deploy/<scanner_id>')
@require_login
def deploy_scanner(scanner_id):
    """Deploy the scanner (make it live)"""
    conn = get_db_connection()
    try:
        # Check if scanner exists and is pending
        scanner = conn.execute(
            "SELECT deploy_status FROM deployed_scanners WHERE id = ?",
            (scanner_id,)
        ).fetchone()
        
        if not scanner:
            return jsonify({'status': 'error', 'message': 'Scanner not found'}), 404
            
        # Update scanner status to deployed
        conn.execute(
            "UPDATE deployed_scanners SET deploy_status = 'deployed', deploy_date = ? WHERE id = ?",
            (datetime.now().isoformat(), scanner_id)
        )
        conn.commit()
        
        return jsonify({'status': 'success', 'message': 'Scanner deployed successfully'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()

def create_scanner(data):
    """Create a new scanner configuration"""
    # Use context manager instead of direct connection
    try:
        with get_db() as conn:
            client_id = get_client_id_from_session()
            if not client_id:
                return {'status': 'error', 'message': 'Client ID not found'}
            
            # Generate scanner ID and subdomain
            scanner_id = str(uuid.uuid4())
            subdomain = generate_subdomain(data.get('scannerName', 'scanner'))
            
            # Validate data before inserting
            if not data.get('scannerName'):
                return {'status': 'error', 'message': 'Scanner name is required'}
                
            # Insert scanner record with initial deployed status
            conn.execute(
                """INSERT INTO deployed_scanners 
                   (id, client_id, subdomain, domain, deploy_status, deploy_date, 
                    config_path, template_version) 
                   VALUES (?, ?, ?, ?, 'deployed', ?, ?, '1.0')""",
                (scanner_id, client_id, subdomain, data.get('businessDomain', ''), 
                 datetime.now().isoformat(), f"/config/{scanner_id}.json")
            )
            
            # Save configuration and commit
            save_scanner_config(scanner_id, data)
            conn.commit()
            return {'status': 'success', 'scanner_id': scanner_id}
            
    except sqlite3.Error as e:
        return {'status': 'error', 'message': f'Database error: {str(e)}'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
            
@scanner_preview_bp.route('/api/scanner/download-report', methods=['POST'])
@require_login
def download_report():
    """Generate and download a scan report"""
    data = request.get_json()
    scan_results = data.get('scan_results', {})
    
    # Generate a simple text report
    report_content = f"""SECURITY SCAN REPORT
====================

Target: {scan_results.get('target', 'N/A')}
Scan Date: {scan_results.get('timestamp', 'N/A')}
Overall Score: {scan_results.get('overall_score', 'N/A')}/100
Risk Level: {scan_results.get('risk_level', 'N/A')}

FINDINGS
--------
"""
    
    for finding in scan_results.get('findings', []):
        report_content += f"""
{finding.get('category', 'N/A')}
  Status: {finding.get('status', 'N/A')}
  Severity: {finding.get('severity', 'N/A')}
  Details: {finding.get('details', 'N/A')}
"""
    
    report_content += """
RECOMMENDATIONS
---------------
"""
    
    for i, rec in enumerate(scan_results.get('recommendations', []), 1):
        report_content += f"{i}. {rec}\n"
    
    return jsonify({
        'status': 'success',
        'report_content': report_content,
        'filename': f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    })

# Error handlers
@scanner_preview_bp.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@scanner_preview_bp.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
