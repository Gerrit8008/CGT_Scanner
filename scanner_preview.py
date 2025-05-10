import sqlite3
import json
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import base64

scanner_preview_bp = Blueprint('scanner_preview', __name__)

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

@scanner_preview_bp.route('/customize', methods=['GET', 'POST'])
@require_login
def customize_scanner():
    """Main scanner creation/customization page"""
    if request.method == 'POST':
        # Handle scanner creation
        data = request.get_json()
        if data:
            # Create new scanner
            scanner_id = create_scanner(data)
            return jsonify({
                'status': 'success',
                'scanner_id': scanner_id,
                'preview_url': url_for('scanner_preview.preview_scanner', scanner_id=scanner_id),
                'deploy_url': url_for('scanner_preview.deploy_scanner', scanner_id=scanner_id)
            })
    
    # Load existing scanners for the client
    conn = get_db_connection()
    client_id = get_client_id_from_session()
    
    existing_scanners = conn.execute(
        "SELECT * FROM deployed_scanners WHERE client_id = ? ORDER BY deploy_date DESC LIMIT 5",
        (client_id,)
    ).fetchall()
    
    conn.close()
    
    return render_template('customize_scanner.html', scanners=existing_scanners)

@scanner_preview_bp.route('/preview/<scanner_id>')
@require_login
def preview_scanner(scanner_id):
    """Show live preview of the scanner"""
    conn = get_db_connection()
    
    # Get scanner details
    scanner = conn.execute(
        "SELECT s.*, c.* FROM deployed_scanners s "
        "JOIN clients c ON s.client_id = c.id "
        "JOIN customizations cu ON c.id = cu.client_id "
        "WHERE s.id = ?",
        (scanner_id,)
    ).fetchone()
    
    if not scanner:
        return "Scanner not found", 404
    
    # Get customization details
    customization = conn.execute(
        "SELECT * FROM customizations WHERE client_id = ?",
        (scanner['client_id'],)
    ).fetchone()
    
    conn.close()
    
    # Prepare preview data
    preview_data = {
        'scanner_name': scanner['scanner_name'],
        'business_domain': scanner['business_domain'],
        'primary_color': customization['primary_color'] if customization else '#FF6900',
        'secondary_color': customization['secondary_color'] if customization else '#808588',
        'logo_path': customization['logo_path'] if customization else None,
        'email_subject': customization['email_subject'] if customization else 'Your Security Scan Report',
        'email_intro': customization['email_intro'] if customization else 'Thank you for using our security scanner.',
        'default_scans': json.loads(customization['default_scans']) if customization and customization['default_scans'] else ['network', 'web', 'email', 'ssl']
    }
    
    return render_template('scanner_preview.html', **preview_data)

@scanner_preview_bp.route('/api/scanner/run-scan', methods=['POST'])
@require_login
def run_preview_scan():
    """Simulate running a security scan for preview"""
    data = request.get_json()
    target = data.get('target', '')
    
    if not target:
        return jsonify({'status': 'error', 'message': 'Target URL required'}), 400
    
    # Simulate scan results
    scan_results = {
        'scan_id': str(uuid.uuid4()),
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'status': 'completed',
        'overall_score': 85,
        'risk_level': 'Good',
        'findings': [
            {
                'category': 'SSL Certificate',
                'status': 'Valid certificate detected',
                'severity': 'Low',
                'color': 'success'
            },
            {
                'category': 'Security Headers',
                'status': 'Missing security headers detected',
                'severity': 'Medium',
                'color': 'warning'
            },
            {
                'category': 'Open Ports',
                'status': '3 high-risk ports detected',
                'severity': 'High',
                'color': 'danger'
            },
            {
                'category': 'Email Security',
                'status': 'SPF and DMARC properly configured',
                'severity': 'Low',
                'color': 'success'
            }
        ],
        'recommendations': [
            'Implement missing security headers (Content-Security-Policy, X-Frame-Options)',
            'Close unnecessary open ports (3389, 5900, 1433)',
            'Enable HSTS preloading for enhanced security',
            'Consider implementing DNSSEC for domain security'
        ]
    }
    
    return jsonify(scan_results)

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
            'message': 'Scanner saved successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scanner_preview_bp.route('/deploy/<scanner_id>')
@require_login
def deploy_scanner(scanner_id):
    """Deploy the scanner (make it live)"""
    conn = get_db_connection()
    
    # Update scanner status to deployed
    conn.execute(
        "UPDATE deployed_scanners SET deploy_status = 'deployed', deploy_date = ? WHERE id = ?",
        (datetime.now().isoformat(), scanner_id)
    )
    conn.commit()
    
    # Get scanner details for confirmation
    scanner = conn.execute(
        "SELECT * FROM deployed_scanners WHERE id = ?",
        (scanner_id,)
    ).fetchone()
    
    conn.close()
    
    if scanner:
        # Create the deployment URL
        deploy_url = f"https://{scanner['subdomain']}.yourscannerdomain.com"
        return render_template('scanner_deployed.html', 
                             scanner=scanner, 
                             deploy_url=deploy_url)
    
    return "Scanner not found", 404

def create_scanner(data):
    """Create a new scanner configuration"""
    conn = get_db_connection()
    client_id = get_client_id_from_session()
    
    # Generate scanner ID and subdomain
    scanner_id = str(uuid.uuid4())
    subdomain = generate_subdomain(data.get('scannerName', 'scanner'))
    
    # Insert scanner record
    conn.execute(
        "INSERT INTO deployed_scanners (id, client_id, subdomain, domain, deploy_status, deploy_date, config_path, template_version) "
        "VALUES (?, ?, ?, ?, 'pending', ?, ?, '1.0')",
        (scanner_id, client_id, subdomain, data.get('businessDomain', ''), datetime.now().isoformat(), f"/config/{scanner_id}.json")
    )
    
    # Update client record with scanner name
    conn.execute(
        "UPDATE clients SET scanner_name = ? WHERE id = ?",
        (data.get('scannerName', 'Security Scanner'), client_id)
    )
    
    # Save customization
    logo_path = None
    if 'logo' in data and data['logo'].startswith('data:image'):
        # Save logo file
        logo_path = save_logo_from_base64(data['logo'], scanner_id)
    
    conn.execute(
        "INSERT OR REPLACE INTO customizations "
        "(client_id, primary_color, secondary_color, logo_path, email_subject, email_intro, default_scans, last_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            client
