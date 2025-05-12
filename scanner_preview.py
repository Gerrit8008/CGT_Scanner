import sqlite3
import json
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import base64
import re
from werkzeug.utils import secure_filename

scanner_preview_bp = Blueprint('scanner_preview', __name__)

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads/logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('client_scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

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
    """Save logo from base64 data"""
    # Extract the image data from base64
    if ',' in base64_data:
        header, data = base64_data.split(',', 1)
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
    else:
        data = base64_data
        ext = 'png'
    
    # Create filename
    filename = f"logo_{scanner_id}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    
    # Ensure upload directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Save the file
    try:
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(data))
        return f"/static/uploads/logos/{filename}"
    except Exception as e:
        print(f"Error saving logo: {e}")
        return None

@scanner_preview_bp.route('/customize', methods=['GET', 'POST'])
@require_login
def customize_scanner():
    """Render the scanner customization form"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'status': 'error', 'message': 'No data provided'}), 400
                
            # Validate required fields
            if not data.get('scannerName') or not data.get('businessDomain'):
                return jsonify({'status': 'error', 'message': 'Scanner name and business domain are required'}), 400
            
            result = create_scanner(data)
            return jsonify(result)
            
        except ValueError as ve:
            return jsonify({'status': 'error', 'message': str(ve)}), 400
        except Exception as e:
            logging.error(f"Error creating scanner: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500
    
    # For GET requests, render the template
    return render_template('admin/customization-form.html')

@scanner_preview_bp.route('/preview/<scanner_id>')
@require_login
def preview_scanner(scanner_id):
    """Show live preview of the scanner"""
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
    
    return render_template('client/scanner_preview.html', **preview_data)

@scanner_preview_bp.route('/api/scanner/run-scan', methods=['POST'])
@require_login
def run_preview_scan():
    """Simulate running a security scan for preview"""
    data = request.get_json()
    target = data.get('target', '')
    scanner_id = data.get('scanner_id', '')
    
    if not target:
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
        {
            'id': str(uuid.uuid4()),
            'category': 'Security Headers',
            'status': 'Security headers properly configured' if random.random() > 0.4 else 'Missing critical security headers',
            'severity': 'Low' if random.random() > 0.4 else 'Medium',
            'color': 'success' if random.random() > 0.4 else 'warning',
            'details': 'All recommended headers present' if random.random() > 0.4 else 'Content-Security-Policy and X-Frame-Options missing'
        },
        {
            'id': str(uuid.uuid4()),
            'category': 'Open Ports',
            'status': f'{random.randint(0, 5)} open ports detected',
            'severity': 'Low' if random.randint(0, 5) <= 1 else 'High',
            'color': 'success' if random.randint(0, 5) <= 1 else 'danger',
            'details': 'Ports: 80, 443' if random.randint(0, 5) <= 1 else 'Ports: 80, 443, 3389, 5900'
        },
        {
            'id': str(uuid.uuid4()),
            'category': 'Email Security',
            'status': 'SPF and DMARC configured' if random.random() > 0.3 else 'Email security issues detected',
            'severity': 'Low' if random.random() > 0.3 else 'Medium',
            'color': 'success' if random.random() > 0.3 else 'warning',
            'details': 'SPF: pass, DMARC: pass' if random.random() > 0.3 else 'SPF: fail, DMARC: not configured'
        }
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
    
    # Save scan results for later reference
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO scan_history (client_id, scan_id, timestamp, target, scan_type, status, report_path) "
            "VALUES ((SELECT client_id FROM deployed_scanners WHERE id = ?), ?, ?, ?, 'full', 'completed', ?)",
            (scanner_id, scan_results['scan_id'], scan_results['timestamp'], target, f"/reports/{scan_results['scan_id']}.json")
        )
        conn.commit()
    except Exception as e:
        print(f"Error saving scan history: {e}")
    finally:
        conn.close()
    
    return jsonify(scan_results)

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
    data = request.get_json()
    
    try:
        scanner_id = create_scanner(data)
        return jsonify({
            'status': 'success',
            'scanner_id': scanner_id,
            'message': 'Scanner saved successfully',
            'preview_url': url_for('scanner_preview.preview_scanner', scanner_id=scanner_id)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def save_scanner_config(scanner_id, data):
    """Validate and save scanner configuration"""
    required_fields = ['scannerName', 'businessDomain']
    for field in required_fields:
        if not data.get(field):
            raise ValueError(f"Missing required field: {field}")
            
    config_path = f"/config/{scanner_id}.json"
    config_data = {
        'scanner_name': data.get('scannerName'),
        'business_domain': data.get('businessDomain'),
        'configuration_version': '1.0',
        'last_updated': datetime.now().isoformat(),
        'status': 'deployed'  # Set initial status to deployed
    }
    
    # Save configuration file
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=4)
    
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
    conn = get_db_connection()
    client_id = get_client_id_from_session()
    
    try:
        # Generate scanner ID and subdomain
        scanner_id = str(uuid.uuid4())
        subdomain = generate_subdomain(data.get('scannerName', 'scanner'))
        
        # Check for duplicate subdomain
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM deployed_scanners WHERE subdomain = ?", (subdomain,))
        if cursor.fetchone():
            raise ValueError("Scanner with this name already exists")
            
        # Insert scanner record with pending status
        cursor.execute(
            "INSERT INTO deployed_scanners (id, client_id, subdomain, domain, deploy_status, deploy_date, config_path, template_version) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?, '1.0')",
            (scanner_id, client_id, subdomain, data.get('businessDomain', ''), 
             datetime.now().isoformat(), f"/config/{scanner_id}.json")
        )
        
        # Save configuration
        config_data = {
            'scanner_name': data.get('scannerName'),
            'business_domain': data.get('businessDomain'),
            'contact_email': data.get('contactEmail'),
            'primary_color': data.get('primaryColor'),
            'secondary_color': data.get('secondaryColor'),
            'default_scans': data.get('defaultScans', []),
            'created_at': datetime.now().isoformat()
        }
        
        config_path = f"/config/{scanner_id}.json"
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=4)
            
        conn.commit()
        return {'status': 'success', 'scanner_id': scanner_id}
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error creating scanner: {str(e)}")
        raise
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
