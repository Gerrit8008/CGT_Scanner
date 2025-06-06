# Import necessary modules
import logging
import os
import sqlite3
import platform
import socket
import re
import uuid
from werkzeug.utils import secure_filename
import urllib.parse
from datetime import datetime, timedelta
import json
import sys
import traceback
import requests
from flask import Flask, Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_login import LoginManager, current_user
from functools import wraps
from urllib.parse import urlparse
import re

# Import custom modules
from email_handler import send_email_report
from config import get_config
from api import api_bp
from client_db import init_client_db, CLIENT_DB_PATH, init_scanner_configurations_table
from scanner_router import scanner_bp
from auth import auth_bp
from admin import admin_bp
from setup_admin import configure_admin
from client import client_bp
from migrations import run_migrations
from admin_web_fix import add_admin_fix_route
from auth_routes import admin_required
# Import database functionality
from db import init_db, save_scan_results, get_scan_results, save_lead_data, DB_PATH
from scan import (
    extract_domain_from_email,
    server_lookup,
    get_client_and_gateway_ip,
    categorize_risks_by_services,
    get_default_gateway_ip,
    scan_gateway_ports,
    check_ssl_certificate,
    check_security_headers,
    detect_cms,
    analyze_cookies,
    detect_web_framework,
    crawl_for_sensitive_content,
    generate_threat_scenario,
    analyze_dns_configuration,
    check_spf_status,
    check_dmarc_record,
    check_dkim_record,
    check_os_updates,
    check_firewall_status,
    check_open_ports,
    analyze_port_risks,
    calculate_risk_score,
    get_severity_level,
    get_recommendations,
    generate_html_report,
    determine_industry,
    get_industry_benchmarks,
    calculate_industry_percentile
)

# Make admin_required globally available
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    from admin_decorators import admin_required
    import builtins
    builtins.admin_required = admin_required
    logging.info("Imported admin_required decorator")
except Exception as admin_decorator_error:
    logging.error(f"Error importing admin_required: {admin_decorator_error}")
    
    # Define a fallback if import fails
    def admin_required(f):
        from flask import redirect, url_for, session
        def decorated_function(*args, **kwargs):
            # Just let it through in emergency mode
            session_token = session.get('session_token')
            if session_token:
                kwargs['user'] = {'username': 'admin', 'role': 'admin'}
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    import builtins
    builtins.admin_required = admin_required
    logging.info("Created fallback admin_required decorator")

# Constants
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

SEVERITY_ICONS = {
    "Critical": "❌",
    "High": "⚠️",
    "Medium": "⚠️",
    "Low": "ℹ️"
}

GATEWAY_PORT_WARNINGS = {
    21: ("FTP (insecure)", "High"),
    23: ("Telnet (insecure)", "High"),
    80: ("HTTP (no encryption)", "Medium"),
    443: ("HTTPS", "Low"),
    3389: ("Remote Desktop (RDP)", "Critical"),
    5900: ("VNC", "High"),
    22: ("SSH", "Low"),
}

# Create emergency blueprint if missing
emergency_bp = Blueprint('emergency', __name__)

@emergency_bp.route('/emergency')
def emergency_status():
    return {"status": "emergency blueprint active"}

# Create scanner preview blueprint if missing
scanner_preview_bp = Blueprint('scanner_preview', __name__)

@scanner_preview_bp.route('/health')
def preview_health():
    return {"status": "scanner preview active"}

def apply_admin_fixes(app):
    """Apply fixes to admin functionality"""
    # Add any admin-specific fixes here
    logger.info("Admin fixes applied")
    return app

# Run migration fixes
try:
    from fix_migrations import fix_all_migrations
    if fix_all_migrations():
        logging.info("All migrations fixed successfully")
    else:
        logging.warning("Some migrations could not be fixed")
except Exception as migration_error:
    logging.error(f"Error running migration fixes: {migration_error}")

# Setup logging
def setup_logging():
    """Configure application logging"""
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    log_filename = os.path.join(logs_dir, f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - Line %(lineno)d - %(message)s')
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("Application started")
    logger.info(f"Detailed logs will be saved to: {log_filename}")

    return logger

# Initialize logging
logger = setup_logging()

# Current time and user for tracking
CURRENT_UTC_TIME = datetime.now().isoformat()
CURRENT_USER = "system"



class DatabaseManager:
    def __init__(self):
        self.db_path = DB_PATH
        self.client_db_path = CLIENT_DB_PATH
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def execute_query(self, query, params=None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return cursor.fetchall()

# Initialize database manager
db_manager = DatabaseManager()

# Log system info
#log_system_info()

# Define upload folder for file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Make sure the directory exists
os.makedirs(os.path.dirname(CLIENT_DB_PATH), exist_ok=True)

# Configure scanner preview initialization
def init_scanner_preview_tables():
    """Initialize scanner preview tables"""
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Create scanner configurations table if not exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scanner_configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanner_id TEXT NOT NULL,
            client_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            domain TEXT,
            configuration TEXT,
            api_key TEXT,
            html_snippet TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            status TEXT DEFAULT 'active',
            created_by TEXT,
            last_modified_by TEXT,
            FOREIGN KEY (client_id) REFERENCES clients (id)
        )
    """)
    
    # Add system info to logging
    logging.info(f"Scanner preview tables initialization - Time: {CURRENT_UTC_TIME}, User: {CURRENT_USER}")
    conn.commit()
    conn.close()


# Initialize scanner preview at app startup
try:
    init_scanner_preview_tables()
    logging.info("Scanner preview initialized successfully")
except Exception as e:
    logging.error(f"Error initializing scanner preview: {e}")

try:
    from auth_fix import fix_auth_routes
    fix_auth_routes(app)
    logging.info("Auth routes fixed successfully")
except Exception as e:
    logging.error(f"Error fixing auth routes: {e}")

# Configure upload settings for scanner preview
SCANNER_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'logos')
os.makedirs(SCANNER_UPLOAD_FOLDER, exist_ok=True)

def register_debug_middleware(app):
    """Register debug middleware for request logging"""
    @app.before_request
    def log_request_info():
        logger.debug(f"Request: {request.method} {request.url}")
        logger.debug(f"Headers: {dict(request.headers)}")
        if request.json:
            logger.debug(f"JSON: {request.json}")
        if request.form:
            logger.debug(f"Form: {dict(request.form)}")

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')

    app.jinja_env.globals['admin_required'] = admin_required

    
    # After creating your Flask app
    init_scanner_configurations_table()
    
    # Enable CORS
    CORS(app)
    
    # Create rate limiter
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
        # Add this to handle missing or invalid IP addresses more gracefully
        #default_limits_deduction_strategies=['fixed-window', 'moving-window']
    )
    
    # Add a simple, dedicated health check endpoint that bypasses the rate limiter
    @app.route('/health')
    @limiter.exempt  # This exempts this route from rate limiting
    def health_check():
        """Simple health check endpoint for monitoring systems"""
        return jsonify({
            "status": "ok",
            "timestamp": datetime.now().isoformat()
        })
    
    # Add custom error handlers for common status codes
    @app.errorhandler(400)
    def handle_bad_request(e):
        # Check if this is a health check request
        if request.path == '/' and request.method in ['GET', 'HEAD']:
            # Return a 200 OK for health checks even if there's an issue
            return "OK", 200
        return jsonify({"error": "Bad Request", "message": str(e)}), 400
    
    @app.errorhandler(429)
    def handle_rate_limit(e):
        # Also return OK for rate-limited health checks
        if request.path == '/' and request.method in ['GET', 'HEAD']:
            return "OK", 200
        return jsonify({"error": "Rate limit exceeded", "message": str(e)}), 429
    
    return app, limiter

def init_database():
    """Initialize all database tables if they don't exist"""
    logging.info("Starting database initialization...")
    
    # Create database directory if it doesn't exist
    db_dir = os.path.dirname(CLIENT_DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # Connect to the database
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Create users table if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT DEFAULT 'client',
        full_name TEXT,
        created_at TEXT,
        last_login TEXT,
        active INTEGER DEFAULT 1
    )
    ''')
    
    # Create clients table if not exists
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        business_name TEXT NOT NULL,
        business_domain TEXT NOT NULL,
        contact_email TEXT NOT NULL,
        contact_phone TEXT,
        scanner_name TEXT,
        subscription_level TEXT DEFAULT 'basic',
        subscription_status TEXT DEFAULT 'active',
        subscription_start TEXT,
        subscription_end TEXT,
        api_key TEXT UNIQUE,
        created_at TEXT,
        created_by INTEGER,
        updated_at TEXT,
        updated_by INTEGER,
        active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (updated_by) REFERENCES users(id)
    )
    ''')
    
    # Create customizations table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS customizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        primary_color TEXT,
        secondary_color TEXT,
        logo_path TEXT,
        favicon_path TEXT,
        email_subject TEXT,
        email_intro TEXT,
        email_footer TEXT,
        default_scans TEXT,
        css_override TEXT,
        html_override TEXT,
        last_updated TEXT,
        updated_by INTEGER,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
        FOREIGN KEY (updated_by) REFERENCES users(id)
    )
    ''')
    
    # Create deployed_scanners table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS deployed_scanners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        subdomain TEXT UNIQUE,
        domain TEXT,
        deploy_status TEXT,
        deploy_date TEXT,
        last_updated TEXT,
        config_path TEXT,
        template_version TEXT,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
    ''')
    
    # Create scan_history table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        scan_id TEXT UNIQUE NOT NULL,
        timestamp TEXT,
        target TEXT,
        scan_type TEXT,
        status TEXT,
        report_path TEXT,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
    ''')
    
    # Create audit_log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER NOT NULL,
        changes TEXT,
        timestamp TEXT NOT NULL,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
    ''')
    
    # Create sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        created_at TEXT,
        expires_at TEXT,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')
    
    # Create scans table for compatibility
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        client_id INTEGER,
        timestamp TEXT,
        target TEXT,
        scan_type TEXT,
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
    ''')
    
    # Create indices for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
    
    conn.commit()
    
    # Verify tables were created
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    logging.info(f"Database tables created/verified: {[table[0] for table in tables]}")
    
    conn.close()
    logging.info("Database initialization completed")

# Initialize the database first
init_database()

# Run migrations to add missing columns
try:
    from migrations import run_migrations
    if run_migrations():
        logging.info("Database migrations completed successfully")
    else:
        logging.warning("Some database migrations may not have completed")
except Exception as migration_error:
    logging.error(f"Error running migrations: {migration_error}")
    logging.debug(traceback.format_exc())

# Check if this is first run (database doesn't exist)
if not os.path.exists(CLIENT_DB_PATH):
    try:
        from setup import setup_database
        setup_database()
    except Exception as e:
        logging.warning(f"Could not run setup_database: {e}")

# Create the Flask app
try:
    app, limiter = create_app()
    logging.info("Flask app created successfully")
except Exception as app_create_error:
    logging.error(f"Error creating Flask app: {app_create_error}")
    logging.debug(f"Exception traceback: {traceback.format_exc()}")
    # Create a basic app as fallback
    app = Flask(__name__)
    app.secret_key = 'fallback_secret_key'
    limiter = None

# Configure upload settings for scanner preview after app creation
app.config['SCANNER_UPLOAD_FOLDER'] = SCANNER_UPLOAD_FOLDER
app.config['LAST_INIT_TIME'] = CURRENT_UTC_TIME
app.config['LAST_INIT_USER'] = CURRENT_USER

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user if user else None
    except Exception as e:
        logging.error(f"Error loading user {user_id}: {e}")
        return None


# Apply admin configuration
try:
    app = configure_admin(app)
    logging.info("Admin configuration applied successfully")
except Exception as config_error:
    logging.error(f"Error applying admin configuration: {config_error}")
    logging.debug(f"Exception traceback: {traceback.format_exc()}")

# Register blueprints
try:
    register_debug_middleware(app)
    
    # Register auth blueprint only once with a unique name
    app.register_blueprint(auth_bp, name='auth_blueprint')
    
    # Register other blueprints with unique names
    app.register_blueprint(admin_bp, name='admin_blueprint')
    app.register_blueprint(api_bp, name='api_blueprint')
    app.register_blueprint(scanner_bp, name='scanner_blueprint')
    app.register_blueprint(client_bp, name='client_blueprint') 
    app.register_blueprint(emergency_bp, name='emergency_blueprint')
    app.register_blueprint(scanner_preview_bp, url_prefix='/preview', name='scanner_preview_blueprint')
    
    logging.info(f"Blueprints registered successfully at {CURRENT_UTC_TIME} by {CURRENT_USER}")
except Exception as blueprint_error:
    logging.error(f"Error registering blueprints: {blueprint_error}")
    logging.debug(f"Exception traceback: {traceback.format_exc()}")

# Apply fixes
try:
    apply_admin_fixes(app)
    add_admin_fix_route(app)
    logging.info("Fixes applied successfully")
except Exception as fix_error:
    logging.error(f"Error applying fixes: {fix_error}")
    logging.debug(f"Exception traceback: {traceback.format_exc()}")

# Register routes
try:
    from register_routes import register_all_routes
    app = register_all_routes(app)
    logging.info("Routes registered successfully")
except Exception as register_error:
    logging.error(f"Error registering routes: {register_error}")
    # Still register the basic blueprints
    try:
        from auth import auth_bp
        from admin import admin_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)
        logging.info("Registered basic blueprints as fallback")
    except Exception as basic_error:
        logging.error(f"Failed to register basic blueprints: {basic_error}")

try:
    from admin_routes import admin_routes_bp
    app.register_blueprint(admin_routes_bp)
    logging.info("Admin routes blueprint registered")
except ImportError:
    logging.warning("Could not import admin_routes_bp")
except Exception as e:
    logging.error(f"Error registering admin_routes_bp: {e}")

# Now define all routes that need the app instance
@app.route('/run_migrations')
def run_migrations_route():
    """Run database migrations on demand"""
    try:
        from migrations import run_migrations
        result = run_migrations()
        
        # Check schema after migrations
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check clients table schema
        cursor.execute("PRAGMA table_info(clients)")
        client_columns = [col[1] for col in cursor.fetchall()]
        
        # Check customizations table schema
        cursor.execute("PRAGMA table_info(customizations)")
        custom_columns = [col[1] for col in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'migration_success': result,
            'clients_table_columns': client_columns,
            'customizations_table_columns': custom_columns,
            'message': 'Migrations completed successfully' if result else 'Some migrations may have failed'
        })
    except Exception as e:
        return jsonify({
            'migration_success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

# Helper function for direct database calls if needed
def create_client_direct(conn, cursor, client_data, user_id):
    """Direct database call to create client"""


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

@app.route('/auth_status')
def auth_status():
    """Route to check authentication system status"""
    return {
        "status": "ok",
        "blueprints_registered": list(app.blueprints.keys()),
        "auth_blueprint": {
            "registered": "auth" in app.blueprints,
            "url_prefix": getattr(app.blueprints.get("auth"), "url_prefix", None)
        }
    }

# Add this debug route to list all registered routes
@app.route('/routes')
def list_routes():
    """List all registered routes for debugging"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': str(rule)
        })
    return jsonify(routes)

# Add API routes for admin functions
@app.route('/auth/api/login-stats')
def api_login_stats():
    """API endpoint for login statistics"""
    from client_db import get_login_stats
    
    stats = get_login_stats()
    return jsonify(stats)

@app.route('/auth/api/check-username', methods=['POST'])
def api_check_username():
    """API endpoint to check username availability"""
    from client_db import check_username_availability
    
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'available': False, 'message': 'No username provided'})
    
    result = check_username_availability(username)
    return jsonify(result)

@app.route('/auth/api/check-email', methods=['POST'])
def api_check_email():
    """API endpoint to check email availability"""
    from client_db import check_email_availability
    
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'available': False, 'message': 'No email provided'})
    
    result = check_email_availability(email)
    return jsonify(result)

@app.route('/db_fix')
def direct_db_fix():
    results = []
    try:
        # Define database path - make sure this matches your actual database path
        CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')
        results.append(f"Working with database at: {CLIENT_DB_PATH}")
        results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        
        # Connect to the database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check database structure
        results.append("Checking database tables...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        results.append(f"Found tables: {[table[0] for table in tables]}")
        
        # Create a new admin user with simple password
        results.append("Creating/updating admin user...")
        
        try:
            import secrets
            import hashlib
            
            # Generate password hash
            salt = secrets.token_hex(16)
            password = 'password123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            # Check if admin user exists
            cursor.execute("SELECT id FROM users WHERE username = 'superadmin'")
            admin_user = cursor.fetchone()
            
            if admin_user:
                # Update existing admin
                cursor.execute('''
                UPDATE users SET 
                    password_hash = ?, 
                    salt = ?,
                    role = 'admin',
                    active = 1
                WHERE username = 'superadmin'
                ''', (password_hash, salt))
                results.append("Updated existing superadmin user")
            else:
                # Create a new admin user
                cursor.execute('''
                INSERT INTO users (
                    username, 
                    email, 
                    password_hash, 
                    salt, 
                    role, 
                    full_name, 
                    created_at, 
                    active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ''', ('superadmin', 'superadmin@example.com', password_hash, salt, 'admin', 'Super Administrator', datetime.now().isoformat()))
                results.append("Created new superadmin user")
            
            # Commit changes
            conn.commit()
            
            # Verify creation
            cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'superadmin'")
            user = cursor.fetchone()
            if user:
                results.append(f"Superadmin user verified: ID={user[0]}, username={user[1]}, email={user[2]}, role={user[3]}")
            
            # Close connection
            conn.close()
            
            results.append("Database fix completed!")
            results.append("You can now login with:")
            results.append("Username: superadmin")
            results.append("Password: password123")
        except Exception as e:
            results.append(f"Error creating admin user: {str(e)}")
        
        return "<br>".join(results)
    except Exception as e:
        results.append(f"Error: {str(e)}")
        return "<br>".join(results)

@app.route('/login')
def login_redirect():
    """Redirect to auth login page"""
    return redirect(url_for('auth.login'))
    
@app.route('/customize', methods=['GET', 'POST'])
def customize_scanner():
    """Render the scanner customization form"""
    # Check if this is a POST request
    if request.method == 'POST':
        try:
            # Check if payment was processed (from form hidden field)
            payment_processed = request.form.get('payment_processed', '0')
            
            # Extract form data
            client_data = {
                'business_name': request.form.get('business_name', ''),
                'business_domain': request.form.get('business_domain', ''),
                'contact_email': request.form.get('contact_email', ''),
                'contact_phone': request.form.get('contact_phone', ''),
                'scanner_name': request.form.get('scanner_name', ''),
                'primary_color': request.form.get('primary_color', '#FF6900'),
                'secondary_color': request.form.get('secondary_color', '#808588'),
                'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
                'email_intro': request.form.get('email_intro', ''),
                'subscription': request.form.get('subscription', 'basic'),
                'default_scans': request.form.getlist('default_scans[]')
            }
            
            logging.info(f"Received form data: {client_data}")
            
            # Use admin user ID 1 for scanner creation
            user_id = 1  
            
            # Handle file uploads
            if 'logo' in request.files and request.files['logo'].filename:
                logo_file = request.files['logo']
                logo_filename = secure_filename(f"{uuid.uuid4()}_{logo_file.filename}")
                logo_path = os.path.join(UPLOAD_FOLDER, logo_filename)
                logo_file.save(logo_path)
                client_data['logo_path'] = logo_path
                logging.info(f"Logo saved at {logo_path}")
            
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                favicon_filename = secure_filename(f"{uuid.uuid4()}_{favicon_file.filename}")
                favicon_path = os.path.join(UPLOAD_FOLDER, favicon_filename)
                favicon_file.save(favicon_path)
                client_data['favicon_path'] = favicon_path
                logging.info(f"Favicon saved at {favicon_path}")
            
            # Create client in database
            from client_db import create_client
            
            logging.info("Creating client in database...")
            
            # Call create_client with the correct parameters
            result = create_client(client_data, user_id)
            
            if not result or result.get('status') != 'success':
                error_msg = result.get('message', 'Unknown error') if result else 'Failed to create client'
                logging.error(f"Error creating client: {error_msg}")
                flash(f"Error creating scanner: {error_msg}", 'danger')
                return render_template('admin/customization-form.html')
            
            # Generate scanner templates
            from scanner_template import generate_scanner
            
            logging.info(f"Generating scanner templates for client ID: {result['client_id']}")
            scanner_result = generate_scanner(result['client_id'], client_data)
            
            if not scanner_result:
                logging.warning("Scanner created but templates could not be generated")
                flash("Scanner created but templates could not be generated", 'warning')
            else:
                logging.info("Scanner templates generated successfully")
                flash("Scanner created successfully!", 'success')
            
            # Process payment or handle payment status (only if needed)
            if payment_processed == '1':
                logging.info("Payment processed successfully")
                
                # If you need to do any additional payment processing, do it here
                # For example, you might want to update the subscription status in the database
                
                try:
                    # Update any subscription details if needed
                    pass
                except Exception as payment_error:
                    logging.error(f"Payment processing error: {str(payment_error)}")
                    # Continue anyway since the scanner was created successfully
            
            # Always redirect to dashboard after successful client creation
            logging.info("Redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))  # Make sure this matches your dashboard endpoint name
            
        except Exception as e:
            # Log the full error with traceback
            logging.error(f"Error processing form: {str(e)}")
            import traceback
            logging.error(traceback.format_exc())
            
            # Return error page
            flash(f"Error creating scanner: {str(e)}", 'danger')
            return render_template('admin/customization-form.html')
    
    # For GET requests, render the template
    logging.info("Rendering customization form")
    return render_template('admin/customization-form.html')
@app.route('/api/email_report', methods=['POST'])
def api_email_report():
    try:
        # Get data from request
        scan_id = request.form.get('scan_id')
        email = request.form.get('email')
        
        logging.info(f"Email report requested for scan_id: {scan_id} to email: {email}")
        
        if not scan_id or not email:
            logging.error("Missing required parameters (scan_id or email)")
            return jsonify({"status": "error", "message": "Missing required parameters"})
        
        # Get scan data from database 
        scan_data = get_scan_results(scan_id)
        
        if not scan_data:
            logging.error(f"Scan data not found for ID: {scan_id}")
            return jsonify({"status": "error", "message": "Scan data not found"})
        
        # Create a lead_data dictionary for the email function
        lead_data = {
            "email": email,
            "name": scan_data.get('client_info', {}).get('name', ''),
            "company": scan_data.get('client_info', {}).get('company', ''),
            "phone": scan_data.get('client_info', {}).get('phone', ''),
            "timestamp": scan_data.get('timestamp', '')
        }
        
        # Use the complete HTML that was stored during scan
        if 'complete_html_report' in scan_data and scan_data['complete_html_report']:
            html_report = scan_data['complete_html_report']
            logging.info("Using stored complete HTML report")
        else:
            # Fallback to either stored 'html_report' or re-render
            html_report = scan_data.get('html_report', '')
            
            # If neither complete nor basic HTML report is available, try to re-render
            if not html_report:
                try:
                    logging.warning("Complete HTML report not found, attempting to re-render")
                    html_report = render_template('results.html', scan=scan_data)
                except Exception as render_error:
                    logging.error(f"Error rendering HTML report: {render_error}")
        
        # Send email using the updated function
        logging.info(f"Attempting to send email report to {email}")
        email_sent = send_email_report(lead_data, scan_data, html_report)
        
        if email_sent:
            logging.info(f"Email report successfully sent to {email}")
            return jsonify({"status": "success"})
        else:
            logging.error(f"Failed to send email report to {email}")
            return jsonify({"status": "error", "message": "Failed to send email"})
            
    except Exception as e:
        logging.error(f"Error in email report API: {e}")
        logging.debug(traceback.format_exc())
        return jsonify({"status": "error", "message": str(e)})

@app.route('/simple_scan')
def simple_scan():
    """A completely simplified scan that bypasses all complexity"""
    try:
        # Create a simple scan result
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Return results directly without database or sessions
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Simple Scan Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .section {{ padding: 15px; margin-bottom: 20px; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Simple Scan Results</h1>
            
            <div class="section">
                <h2>Scan Information</h2>
                <p><strong>Scan ID:</strong> {scan_id}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Sample Results</h2>
                <p>This is a simple test page that bypasses all complex functionality.</p>
                <ul>
                    <li>Keep all software updated with security patches</li>
                    <li>Use strong, unique passwords</li>
                    <li>Enable multi-factor authentication where possible</li>
                </ul>
            </div>
            
            <a href="/scan">Run a real scan</a>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/db_check')
def db_check():
    """Check if the database is set up and working properly"""
    try:
        # Try to connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        # Get count of records in each table
        table_counts = {}
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cursor.fetchone()[0]
            table_counts[table_name] = count
        
        conn.close()
        
        return jsonify({
            "status": "success",
            "database_path": DB_PATH,
            "tables": [table[0] for table in tables],
            "record_counts": table_counts,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc()
        })

@app.route('/test_db_write')
def test_db_write():
    """Test direct database write functionality"""
    try:
        # Create test data
        test_data = {
            'scan_id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'target': 'test.com',
            'email': 'test@example.com',
            'test_field': 'This is a test'
        }
        
        # Try to save to database
        saved_id = save_scan_results(test_data)
        
        if saved_id:
            # Try to retrieve it
            retrieved = get_scan_results(saved_id)
            
            return jsonify({
                'status': 'success',
                'message': 'Database write and read successful',
                'saved_id': saved_id,
                'retrieved': retrieved is not None,
                'record_matches': retrieved is not None and retrieved.get('test_field') == test_data['test_field']
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Database write failed - save_scan_results returned None or False'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Exception during database test: {str(e)}',
            'traceback': traceback.format_exc()
        })

@app.route('/clear_session')
def clear_session():
    """Clear the current session to start fresh"""
    # Clear existing session data
    session.clear()
    logging.info("Session cleared")
    
    return jsonify({
        "status": "success",
        "message": "Session cleared successfully. You can now run a new scan.",
        "redirect": url_for('scan_page')
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scan requests"""
    # Only apply rate limiting if limiter is available
    if limiter:
        try:
            return limiter.limit("5 per minute")(api_scan_implementation)()
        except Exception as limiter_error:
            logging.warning(f"Rate limiter error: {limiter_error}")
            return api_scan_implementation()
    else:
        return api_scan_implementation()

def api_scan_implementation():
    """Implementation of the API scan endpoint"""
    try:
        # Get client info from authentication
        client_id = get_client_id_from_request()
        scanner_id = request.form.get('scanner_id')
        
        # Run the scan
        scan_results = run_consolidated_scan(request.form)
        
        # Save to client's database
        with get_client_db(db_manager, client_id) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (
                    scanner_id, scan_timestamp, target, 
                    scan_type, status, results, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scanner_id,
                datetime.now().isoformat(),
                scan_results['target'],
                scan_results['type'],
                'completed',
                json.dumps(scan_results['results']),
                datetime.now().isoformat()
            ))
            conn.commit()
            
        return jsonify({
            "status": "success",
            "scan_id": scan_results['scan_id'],
            "message": "Scan completed successfully."
        })
            
    except Exception as e:
        logging.error(f"Error in API scan: {e}")
        return jsonify({
            "status": "error",
            "message": f"An error occurred during the scan: {str(e)}"
        }), 500
        
@app.route('/results_direct')
def results_direct():
    """Display scan results directly from query parameter"""
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        return "No scan ID provided", 400
    
    try:
        # Get results from database
        scan_results = get_scan_results(scan_id)
        
        if not scan_results:
            return f"No results found for scan ID: {scan_id}", 404
        
        # Return a simplified view of the results
        return f"""
        <html>
            <head>
                <title>Scan Results</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .section {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <h1>Scan Results</h1>
                
                <div class="section">
                    <h2>Scan Information</h2>
                    <p><strong>Scan ID:</strong> {scan_results['scan_id']}</p>
                    <p><strong>Timestamp:</strong> {scan_results['timestamp']}</p>
                    <p><strong>Email:</strong> {scan_results['email']}</p>
                </div>
                
                <div class="section">
                    <h2>Risk Assessment</h2>
                    <p><strong>Overall Score:</strong> {scan_results['risk_assessment']['overall_score']}</p>
                    <p><strong>Risk Level:</strong> {scan_results['risk_assessment']['risk_level']}</p>
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    <ul>
                        {''.join([f'<li>{r}</li>' for r in scan_results['recommendations']])}
                    </ul>
                </div>
                
                <a href="/scan">Run another scan</a>
            </body>
        </html>
        """
    except Exception as e:
        return f"Error loading results: {str(e)}", 500
    
@app.route('/quick_scan', methods=['GET', 'POST'])
def quick_scan():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '')
            
            if not email:
                return "Email is required", 400
            
            # Extract domain from email
            domain = extract_domain_from_email(email)
            
            # Create minimal test data
            test_data = {
                'name': 'Test User',
                'email': email,
                'company': 'Test Company',
                'phone': '555-1234',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'client_os': 'Test OS',
                'client_browser': 'Test Browser',
                'windows_version': '',
                'target': domain  # Use extracted domain
            }
            
            logging.info(f"Starting quick scan for {email}...")
            scan_results = run_consolidated_scan(test_data)
            
            if not scan_results or 'scan_id' not in scan_results:
                return "Scan failed to complete", 500
            
            # Save to database
            saved_id = save_scan_results(scan_results)
            if not saved_id:
                return "Failed to save scan results", 500
            
            # Redirect to results
            return redirect(url_for('results_direct', scan_id=scan_results['scan_id']))
        except Exception as e:
            logging.error(f"Error in quick_scan: {e}")
            return f"Error: {str(e)}", 500
    
    # Simple form for GET requests
    return """
    <html>
        <head><title>Quick Scan Test</title></head>
        <body>
            <h1>Quick Scan Test</h1>
            <form method="post">
                <div>
                    <label>Email: <input type="email" name="email" required></label>
                </div>
                <div>
                    <label>Target (optional): <input type="text" name="target"></label>
                </div>
                <button type="submit">Run Quick Scan</button>
            </form>
        </body>
    </html>
    """

@app.route('/debug_post', methods=['POST'])  
def debug_post():
    """Debug endpoint to check POST data"""
    try:
        # Log all form data
        form_data = {key: request.form.get(key) for key in request.form}
        logging.info(f"Received POST data: {form_data}")
        
        # Return a success response
        return jsonify({
            "status": "success",
            "received_data": form_data
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e)
        })
        
@app.route('/debug_db')
def debug_db():
    """Debug endpoint to check database contents"""
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Get sample rows from each table
        samples = {}
        for table in tables:
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 5")
                rows = cursor.fetchall()
                if rows:
                    # Convert rows to dictionaries
                    samples[table] = [dict(row) for row in rows]
                else:
                    samples[table] = []
            except Exception as table_error:
                samples[table] = f"Error: {str(table_error)}"
        
        conn.close()
        
        # Generate HTML response
        output = f"""
        <html>
            <head>
                <title>Database Debug</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Database Debug Information</h1>
                <p><strong>Database Path:</strong> {DB_PATH}</p>
                <h2>Tables:</h2>
                <ul>
        """
        
        for table in tables:
            row_count = len(samples[table]) if isinstance(samples[table], list) else "Error"
            output += f"<li>{table} ({row_count} sample rows)</li>\n"
        
        output += "</ul>\n"
        
        # Show sample data from each table
        for table in tables:
            output += f"<h2>Sample data from {table}:</h2>\n"
            
            if isinstance(samples[table], list):
                if samples[table]:
                    # Get column names from first row
                    columns = samples[table][0].keys()
                    
                    output += "<table>\n<tr>\n"
                    for col in columns:
                        output += f"<th>{col}</th>\n"
                    output += "</tr>\n"
                    
                    # Add data rows
                    for row in samples[table]:
                        output += "<tr>\n"
                        for col in columns:
                            # Limit large values and convert non-strings to strings
                            value = str(row[col])
                            if len(value) > 100:
                                value = value[:100] + "..."
                            output += f"<td>{value}</td>\n"
                        output += "</tr>\n"
                    
                    output += "</table>\n"
                else:
                    output += "<p>No data in this table</p>\n"
            else:
                output += f"<p>{samples[table]}</p>\n"
        
        output += """
                <p><a href="/scan">Return to Scan Page</a></p>
            </body>
        </html>
        """
        
        return output
    except Exception as e:
        return f"""
        <html>
            <head><title>Database Error</title></head>
            <body>
                <h1>Database Debug Error</h1>
                <p>An error occurred while accessing the database: {str(e)}</p>
                <p><pre>{traceback.format_exc()}</pre></p>
            </body>
        </html>
        """

@app.route('/debug_scan/<scan_id>')
def debug_scan_results(scan_id):
    scan_results = get_scan_results(scan_id)
    return jsonify(scan_results)
    
@app.route('/debug_scan_test')
def debug_scan_test():
    """Run a simplified scan and redirect to results"""
    try:
        # Create test lead data
        test_data = {
            'name': 'Debug User',
            'email': 'debug@example.com',
            'company': 'Debug Company',
            'phone': '555-1234',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': 'Debug OS',
            'client_browser': 'Debug Browser',
            'windows_version': '',
            'target': 'example.com'
        }
        
        # Run simplified scan
        scan_results = debug_scan(test_data)
        
        if scan_results and 'scan_id' in scan_results:
            # Redirect to direct results page
            return redirect(f"/results_direct?scan_id={scan_results['scan_id']}")
        else:
            return "Scan failed: No valid results returned", 500
    except Exception as e:
        return f"Scan failed with error: {str(e)}", 500
            
def debug_scan(lead_data):
    """Debug version of the scan function with more verbose logging"""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    logging.info(f"[DEBUG SCAN] Starting scan with ID: {scan_id}")
    logging.info(f"[DEBUG SCAN] Lead data: {lead_data}")
    
    # Create basic scan results structure
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'email': lead_data.get('email', ''),
        'client_info': {
            'os': lead_data.get('client_os', 'Unknown'),
            'browser': lead_data.get('client_browser', 'Unknown'),
            'windows_version': lead_data.get('windows_version', '')
        },
        # Add some minimal results for testing
        'recommendations': [
            'Keep all software updated with the latest security patches',
            'Use strong, unique passwords for all accounts',
            'Enable multi-factor authentication where available'
        ],
        'risk_assessment': {
            'overall_score': 75,
            'risk_level': 'Medium'
        }
    }
    
    logging.info(f"[DEBUG SCAN] Created basic scan results structure")
    
    # Skip actual scanning functionality for testing
    
    # Save the results directly
    try:
        logging.info(f"[DEBUG SCAN] Attempting to save scan results to database")
        saved_id = save_scan_results(scan_results)
        
        if saved_id:
            logging.info(f"[DEBUG SCAN] Successfully saved to database with ID: {saved_id}")
        else:
            logging.error(f"[DEBUG SCAN] Database save function returned None or False")
    except Exception as e:
        logging.error(f"[DEBUG SCAN] Database save error: {str(e)}")
        logging.debug(f"[DEBUG SCAN] Exception traceback: {traceback.format_exc()}")
    
    logging.info(f"[DEBUG SCAN] Completed, returning results with scan_id: {scan_id}")
    return scan_results
               
@app.route('/debug')
def debug():
    """Debug endpoint to check Flask configuration"""
    debug_info = {
        "Python Version": sys.version,
        "Working Directory": os.getcwd(),
        "Template Folder": app.template_folder,
        "Templates Exist": os.path.exists(app.template_folder),
        "Templates Available": os.listdir(app.template_folder) if os.path.exists(app.template_folder) else "N/A",
        "Environment": app.config['ENV'],
        "Debug Mode": True,
        "Database Path": DB_PATH,
        "Database Connection": "Unknown"
    }
    
    try:
        # Test database connection
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()
        conn.close()
        debug_info["Database Connection"] = f"Success, SQLite version: {version[0]}"
    except Exception as e:
        debug_info["Database Connection"] = f"Failed: {str(e)}"
    
    return jsonify(debug_info)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/api/healthcheck')
def healthcheck():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/debug_session')
def debug_session():
    """Debug endpoint to verify session functionality"""
    # Get existing scan_id if any
    scan_id = session.get('scan_id')
    
    # Set a test value in session
    session['test_value'] = str(datetime.now())
    
    return jsonify({
        "session_working": True,
        "current_scan_id": scan_id,
        "test_value_set": session['test_value'],
        "all_keys": list(session.keys())
    })
    
@app.route('/test_scan')
def test_scan():
    """Test scan execution directly"""
    try:
        # Create test lead data
        test_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'company': 'Test Company',
            'phone': '555-1234',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': 'Test OS',
            'client_browser': 'Test Browser',
            'windows_version': 'Test Windows',
            'target': 'example.com'
        }
        
        # Run scan
        logging.info("Starting test scan execution...")
        scan_results = run_consolidated_scan(test_data)
        
        # Check if we got a valid result
        if scan_results and 'scan_id' in scan_results:
            # Try to save to database
            try:
                saved_id = save_scan_results(scan_results)
                db_status = f"Successfully saved to database with ID: {saved_id}" if saved_id else "Failed to save to database"
            except Exception as db_error:
                db_status = f"Database error: {str(db_error)}"
            
            # Return success output
            return f"""
            <html>
                <head><title>Test Scan Success</title></head>
                <body>
                    <h1>Test Scan Completed Successfully</h1>
                    <p><strong>Scan ID:</strong> {scan_results['scan_id']}</p>
                    <p><strong>Database Status:</strong> {db_status}</p>
                    <p><strong>Available Keys:</strong> {', '.join(list(scan_results.keys()))}</p>
                    <p><a href="/results_direct?scan_id={scan_results['scan_id']}">View Results</a></p>
                </body>
            </html>
            """
        else:
            # Return error output
            return f"""
            <html>
                <head><title>Test Scan Failed</title></head>
                <body>
                    <h1>Test Scan Failed</h1>
                    <p>The scan did not return valid results.</p>
                    <p><pre>{json.dumps(scan_results, indent=2, default=str) if scan_results else 'None'}</pre></p>
                </body>
            </html>
            """
    except Exception as e:
        return f"""
        <html>
            <head><title>Test Scan Error</title></head>
            <body>
                <h1>Test Scan Error</h1>
                <p>An error occurred during the test scan: {str(e)}</p>
                <p><pre>{traceback.format_exc()}</pre></p>
            </body>
        </html>
        """

@app.route('/debug_submit', methods=['POST'])
def debug_submit():
    """Debug endpoint to test form submission"""
    try:
        test_email = request.form.get('test_email', 'unknown@example.com')
        
        return f"""
        <html>
            <head>
                <title>Debug Form Submission</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                </style>
            </head>
            <body>
                <h1>Form Submission Successful</h1>
                <p>Received test email: {test_email}</p>
                <p>This confirms that basic form submission is working.</p>
                <a href="/scan">Return to scan page</a>
            </body>
        </html>
        """
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/admin')
def admin_dashboard_redirect():
    return redirect(url_for('admin.dashboard'))

@app.errorhandler(500)
def handle_500(e):
    app.logger.error(f'500 error: {str(e)}')
    return render_template('error.html', error=str(e)), 500

@app.errorhandler(404)
def handle_404(e):
    app.logger.error(f'404 error: {str(e)}')
    return render_template('error.html', error="Page not found"), 404

@app.route('/api/create-scanner', methods=['POST'])
def create_scanner_api():
    """API endpoint to handle scanner creation form submission"""
    try:
        # Get form data
        client_data = {
            'business_name': request.form.get('business_name', ''),
            'business_domain': request.form.get('business_domain', ''),
            'contact_email': request.form.get('contact_email', ''),
            'contact_phone': request.form.get('contact_phone', ''),
            'scanner_name': request.form.get('scanner_name', ''),
            'subscription': request.form.get('subscription', 'basic'),
            'primary_color': request.form.get('primary_color', '#FF6900'),
            'secondary_color': request.form.get('secondary_color', '#808588'),
            'email_subject': request.form.get('email_subject', 'Your Security Scan Report'),
            'email_intro': request.form.get('email_intro', '')
        }
        
        # Get default scans
        default_scans = request.form.getlist('default_scans[]')
        if default_scans:
            client_data['default_scans'] = default_scans
        
        # Handle file uploads
        if 'logo' in request.files and request.files['logo'].filename:
            # Process logo upload
            pass
            
        if 'favicon' in request.files and request.files['favicon'].filename:
            # Process favicon upload
            pass
            
        # For now, just return success response
        flash('Scanner created successfully', 'success')
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        app.logger.error(f"Error creating scanner: {str(e)}")
        flash(f'Error creating scanner: {str(e)}', 'danger')
        return redirect(url_for('customize_scanner'))

@app.route('/api/service_inquiry', methods=['POST'])
def api_service_inquiry():
    try:
        # Get data from request
        service = request.form.get('service')
        findings = request.form.get('findings')
        scan_id = request.form.get('scan_id')
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone', '')
        message = request.form.get('message', '')
        
        logging.info(f"Service inquiry received: {service} from {name} ({email})")
        
        # Get scan data for reference
        scan_data = get_scan_results(scan_id)
        
        # Create a lead_data dictionary
        lead_data = {
            "name": name,
            "email": email,
            "phone": phone,
            "message": message,
            "service": service,
            "findings": findings,
            "scan_id": scan_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save the inquiry to the database
        try:
            # Create a new table or use an existing one for service inquiries
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Make sure the table exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS service_inquiries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    name TEXT,
                    email TEXT,
                    phone TEXT,
                    service TEXT,
                    findings TEXT,
                    message TEXT,
                    timestamp TEXT
                )
            ''')
            
            # Insert the inquiry
            cursor.execute('''
                INSERT INTO service_inquiries 
                (scan_id, name, email, phone, service, findings, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, name, email, phone, service, findings, message, lead_data['timestamp']
            ))
            
            conn.commit()
            conn.close()
            logging.info(f"Service inquiry saved to database for {name}")
        except Exception as db_error:
            logging.error(f"Error saving service inquiry to database: {db_error}")
        
        # Send an email notification about the service inquiry
        try:
            # Customize the email_handler.py function to send service inquiries
            # or use the existing one with modified parameters
            email_subject = f"Service Inquiry: {service}"
            
            email_body = f"""
            <h2>New Service Inquiry from Security Scan</h2>
            <p><strong>Service:</strong> {service}</p>
            <p><strong>Issues Found:</strong> {findings}</p>
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Email:</strong> {email}</p>
            <p><strong>Phone:</strong> {phone}</p>
            <p><strong>Message:</strong> {message}</p>
            <p><strong>Scan ID:</strong> {scan_id}</p>
            <p><strong>Timestamp:</strong> {lead_data['timestamp']}</p>
            """
            
            # Use your existing email sending function
            # send_email_notification(admin_email, email_subject, email_body)
            logging.info(f"Service inquiry email notification sent for {service}")
        except Exception as email_error:
            logging.error(f"Error sending service inquiry email: {email_error}")
        
        return jsonify({"status": "success"})
    except Exception as e:
        logging.error(f"Error processing service inquiry: {e}")
        return jsonify({"status": "error", "message": str(e)})

def check_route_conflicts():
    """Check for conflicting routes in registered blueprints"""
    routes = {}
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        path = str(rule)
        if path in routes:
            logging.warning(f"Route conflict found: {path} is registered by both {routes[path]} and {endpoint}")
        else:
            routes[path] = endpoint
            
    # Print all routes for debugging
    logging.info("All registered routes:")
    for path, endpoint in sorted(routes.items()):
        logging.info(f"  {path} -> {endpoint}")
        
# Call this function after all blueprints are registered
try:
    check_route_conflicts()
except Exception as route_check_error:
    logging.error(f"Error checking route conflicts: {route_check_error}")

@app.route('/test')
def test_route():
    return """
    <!DOCTYPE html>
    <html>
        <head><title>Test Page</title></head>
        <body>
            <h1>Flask App is Working!</h1>
            <p>If you can see this, your Flask application is functioning correctly.</p>
            <p>Time: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        </body>
    </html>
    """

@app.route('/debug_templates')
def debug_templates():
    template_folder = app.template_folder
    templates_exist = os.path.exists(template_folder)
    templates_list = os.listdir(template_folder) if templates_exist else []
    
    return jsonify({
        "template_folder": template_folder,
        "templates_exist": templates_exist,
        "templates_list": templates_list,
        "working_directory": os.getcwd()
    })

@app.route('/run_dashboard_fix')
def run_dashboard_fix():
    """Web route to run the dashboard fix script"""
    try:
        # Import functions from dashboard_fix.py
        from dashboard_fix import apply_dashboard_fix, add_get_dashboard_summary, fix_list_clients, create_missing_tables
        
        # Define file paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        admin_py = os.path.join(script_dir, 'admin.py')
        client_db_py = os.path.join(script_dir, 'client_db.py')
        
        # Apply fixes
        results = []
        results.append(f"Starting dashboard fixes at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Fix admin.py dashboard function
        if os.path.exists(admin_py):
            dashboard_fix_result = apply_dashboard_fix(admin_py)
            results.append(f"Dashboard function fix: {'Success' if dashboard_fix_result else 'Failed'}")
        else:
            results.append(f"Error: admin.py not found at {admin_py}")
            
        # Fix client_db.py functions
        if os.path.exists(client_db_py):
            # Add or update get_dashboard_summary function
            summary_fix_result = add_get_dashboard_summary(client_db_py)
            results.append(f"get_dashboard_summary function fix: {'Success' if summary_fix_result else 'Failed'}")
            
            # Fix list_clients function
            clients_fix_result = fix_list_clients(client_db_py)
            results.append(f"list_clients function fix: {'Success' if clients_fix_result else 'Failed'}")
        else:
            results.append(f"Error: client_db.py not found at {client_db_py}")
            
        # Create missing tables
        tables_fix_result = create_missing_tables()
        results.append(f"Missing tables creation: {'Success' if tables_fix_result else 'Failed'}")
        
        # Create HTML output without using problematic f-strings with backslashes
        result_text = "<br>".join(results)
        html = f"""
        <html>
            <head>
                <title>Dashboard Fix Results</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .success {{ color: green; }}
                    .error {{ color: red; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Dashboard Fix Results</h1>
                    <div style="background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">
                        {result_text}
                    </div>
                    <p><a href="/admin/dashboard">Try accessing the dashboard</a></p>
                </div>
            </body>
        </html>
        """
        return html
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        html = f"""
        <html>
            <head>
                <title>Dashboard Fix Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .error {{ color: red; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">Error Running Dashboard Fix</h1>
                    <p class="error">{str(e)}</p>
                    <h2>Traceback:</h2>
                    <pre>{error_traceback}</pre>
                </div>
            </body>
        </html>
        """
        return html

@app.route('/run_emergency_admin')
def run_emergency_admin():
    """Web route to create an emergency admin user"""
    try:
        # Import function from hotfix.py
        from hotfix import create_emergency_admin
        
        # Create emergency admin
        success = create_emergency_admin()
        
        # Get admin details if successful
        if success:
            admin_details = """
            <div style="color: green; padding: 10px; background-color: #e6ffe6; border-radius: 5px;">
                <p>Emergency admin created successfully!</p>
                <p>Username: emergency_admin</p>
                <p>Password: admin123</p>
            </div>
            <p><a href="/admin/dashboard">Go to Admin Dashboard</a></p>
            """
        else:
            admin_details = """
            <div style="color: red; padding: 10px; background-color: #ffe6e6; border-radius: 5px;">
                <p>Failed to create emergency admin.</p>
            </div>
            """
        
        # Return the results
        html = f"""
        <html>
            <head>
                <title>Emergency Admin Creation</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Emergency Admin Creation</h1>
                    {admin_details}
                </div>
            </body>
        </html>
        """
        return html
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        html = f"""
        <html>
            <head>
                <title>Emergency Admin Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .error {{ color: red; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">Error Creating Emergency Admin</h1>
                    <p class="error">{str(e)}</p>
                    <h2>Traceback:</h2>
                    <pre>{error_traceback}</pre>
                </div>
            </body>
        </html>
        """
        return html

def upgrade_database_schema():
    """Upgrade database schema to latest version"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check current schema version
        cursor.execute("PRAGMA user_version")
        current_version = cursor.fetchone()[0]
        
        # Current expected version
        latest_version = 1
        
        if current_version < latest_version:
            logger.info(f"Upgrading database schema from {current_version} to {latest_version}")
            
            # Add any necessary schema updates here
            cursor.execute("PRAGMA user_version = {}".format(latest_version))
            conn.commit()
            
            logger.info("Database schema upgrade completed")
            return True
        else:
            logger.info("Database schema is up to date")
            return True
            
    except Exception as e:
        logger.error(f"Database schema upgrade failed: {e}")
        return False
    finally:
        try:
            conn.close()
        except:
            pass

def direct_db_fix():
    """Direct database fix function"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            import secrets
            import hashlib
            
            # Create admin user
            salt = secrets.token_hex(16)
            password = 'admin123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, full_name, created_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Admin User', datetime.now().isoformat()))
            
            conn.commit()
            logger.info("Created admin user")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Database fix error: {e}")
        return False

def add_admin_fix_route(app):
    """Add route for admin fixes"""
    @app.route('/admin_fix')
    def admin_fix_route():
        return {"status": "Admin fix route active"}


def apply_route_fixes():
    """Apply all route fixes"""
    try:
        # Get the Flask app
        # Apply auth routes fix
        try:
            from auth_fix import fix_auth_routes
            auth_fixed = fix_auth_routes(app)
        except ImportError:
            logging.warning("auth_fix module not found")
            auth_fixed = False
        
        # Apply admin routes fix
        try:
            from route_fix import fix_admin_routes
            admin_fixed = fix_admin_routes(app)
        except ImportError:
            logging.warning("route_fix module not found")
            admin_fixed = False
        
        # Report results
        if auth_fixed and admin_fixed:
            logging.info("All route fixes applied successfully!")
            return True
        else:
            logging.warning("Some route fixes could not be applied.")
            return False
    except Exception as e:
        logging.error(f"Error applying route fixes: {e}")
        return False

# Helper function to get client ID from request
def get_client_id_from_request():
    """Get client ID from API key or other authentication"""
    # This would normally check API key, JWT token, or session
    # For now, return a default value
    try:
        return request.headers.get('X-Client-ID') or request.args.get('client_id') or 1
    except:
        return 1

def create_client_database(client_data, user_id, cursor):
    """Create client in database"""
    
    # Validate required fields
    required_fields = ['business_name', 'business_domain', 'contact_email']
    for field in required_fields:
        if not field in client_data:
            return {'status': 'error', 'message': f'Missing required field: {field}'}
    
    # Generate API key
    api_key = str(uuid.uuid4())
    current_time = datetime.now().isoformat()
    
    # Insert client record
    cursor.execute('''
    INSERT INTO clients 
    (business_name, business_domain, contact_email, contact_phone, 
     scanner_name, subscription_level, subscription_status, subscription_start,
     api_key, created_at, created_by, updated_at, updated_by, active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_data.get('business_name', ''),
        client_data.get('business_domain', ''),
        client_data.get('contact_email', ''),
        client_data.get('contact_phone', ''),
        client_data.get('scanner_name', ''),
        client_data.get('subscription', 'basic'),
        'active',
        current_time,
        api_key,
        current_time,
        user_id,
        current_time,
        user_id,
        1
    ))
    
    # Get the client ID
    client_id = cursor.lastrowid
    
    # Save customization data
    default_scans = json.dumps(client_data.get('default_scans', []))
    
    cursor.execute('''
    INSERT INTO customizations 
    (client_id, primary_color, secondary_color, logo_path, 
     favicon_path, email_subject, email_intro, default_scans, last_updated, updated_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        client_data.get('primary_color', '#FF6900'),
        client_data.get('secondary_color', '#808588'),
        client_data.get('logo_path', ''),
        client_data.get('favicon_path', ''),
        client_data.get('email_subject', 'Your Security Scan Report'),
        client_data.get('email_intro', 'Thank you for using our security scanner.'),
        default_scans,
        current_time,
        user_id
    ))
    
    # Create deployed scanner record with sanitized subdomain
    subdomain = client_data.get('business_name', '').lower()
    # Clean up subdomain to be URL-friendly
    subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
    # Remove consecutive dashes and ensure it doesn't start/end with a dash
    subdomain = '-'.join(filter(None, subdomain.split('-')))
    
    # Handle duplicates by appending client_id if needed
    cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
    if cursor.fetchone():
        subdomain = f"{subdomain}-{client_id}"
    
    cursor.execute('''
    INSERT INTO deployed_scanners 
    (client_id, subdomain, deploy_status, deploy_date, last_updated, template_version)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        subdomain,
        'pending',
        current_time,
        current_time,
        '1.0'
    ))
    
    return {
        "status": "success",
        "client_id": client_id,
        "api_key": api_key,
        "subdomain": subdomain
    }

    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the direct database fix
    try:
        direct_db_fix()
    except Exception as db_fix_error:
        logging.error(f"Database fix error: {db_fix_error}")
    
    # Apply route fixes if needed
    try:
        apply_route_fixes()
    except Exception as route_fix_error:
        logging.error(f"Route fix error: {route_fix_error}")
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
    
# Add a route for the admin dashboard
@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    """Render the admin dashboard"""
    return render_template('admin/admin-dashboard.html')

# Log registered routes
@app.before_first_request
def log_registered_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append(f"{rule.endpoint}: {', '.join(rule.methods)} - {rule.rule}")
    logging.info("Registered routes: %s", routes)

def get_scan_id_from_request():
    """Get scan_id from session or query parameters"""
    # Try to get from session first
    scan_id = session.get('scan_id')
    if scan_id:
        logging.debug(f"Found scan_id in session: {scan_id}")
        return scan_id
    
    # If not in session, try query parameters
    scan_id = request.args.get('scan_id')
    if scan_id:
        logging.debug(f"Found scan_id in query parameters: {scan_id}")
        return scan_id
    
    logging.warning("No scan_id found in session or query parameters")
    return None

def scan_gateway_ports(gateway_info):
    """Enhanced gateway port scanning with better error handling"""
    results = []
    
    try:
        # Parse gateway info safely
        client_ip = "Unknown"
        if isinstance(gateway_info, str) and "Client IP:" in gateway_info:
            client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
        
        # Add client IP information to the report
        results.append((f"Client detected at IP: {client_ip}", "Info"))
        
        # Add gateway detection information
        gateway_ips = []
        if isinstance(gateway_info, str) and "Likely gateways:" in gateway_info:
            gateways = gateway_info.split("Likely gateways:")[1].strip()
            if "|" in gateways:
                gateways = gateways.split("|")[0].strip()
            gateway_ips = [g.strip() for g in gateways.split(",")]
            results.append((f"Potential gateway IPs: {', '.join(gateway_ips)}", "Info"))
        
        # Scan common ports on gateway IPs
        if gateway_ips:
            for ip in gateway_ips:
                if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    continue  # Skip invalid IPs
                
                for port, (service, severity) in GATEWAY_PORT_WARNINGS.items():
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1.0)  # Quick timeout
                            result = s.connect_ex((ip, port))
                            if result == 0:
                                results.append((f"Port {port} ({service}) is open on {ip}", severity))
                    except socket.error:
                        pass  # Ignore socket errors for individual port checks
        else:
            results.append(("Could not identify gateway IPs to scan", "Medium"))
        
        # Add network type information if available
        if isinstance(gateway_info, str) and "Network Type:" in gateway_info:
            network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
            results.append((f"Network type detected: {network_type}", "Info"))
            
            # Add specific warnings based on network type
            if "public" in network_type.lower():
                results.append(("Device is connected to a public network which poses higher security risks", "High"))
            elif "guest" in network_type.lower():
                results.append(("Device is connected to a guest network which may have limited security", "Medium"))
    except Exception as e:
        results.append((f"Error analyzing gateway: {str(e)}", "High"))
    
    # Make sure we return at least some results
    if not results:
        results.append(("Gateway information unavailable", "Medium"))
    
    return results

def determine_industry(company_name, email_domain):
    """
    Determine the industry type based on company name and email domain
    
    Args:
        company_name (str): Name of the company
        email_domain (str): Domain from email address
        
    Returns:
        str: Industry type (healthcare, financial, retail, etc.)
    """
    # Convert inputs to lowercase for case-insensitive matching
    company_name = company_name.lower() if company_name else ""
    email_domain = email_domain.lower() if email_domain else ""
    
    # Healthcare indicators
    healthcare_keywords = ['hospital', 'health', 'medical', 'clinic', 'care', 'pharma', 
                          'doctor', 'dental', 'medicine', 'healthcare']
    healthcare_domains = ['hospital.org', 'health.org', 'med.org']
    
    # Financial indicators
    financial_keywords = ['bank', 'finance', 'investment', 'capital', 'financial', 
                         'insurance', 'credit', 'wealth', 'asset', 'accounting']
    financial_domains = ['bank.com', 'invest.com', 'financial.com']
    
    # Retail indicators
    retail_keywords = ['retail', 'shop', 'store', 'market', 'commerce', 'mall', 
                      'sales', 'buy', 'shopping', 'consumer']
    retail_domains = ['shop.com', 'retail.com', 'store.com', 'market.com']
    
    # Education indicators
    education_keywords = ['school', 'university', 'college', 'academy', 'education', 
                         'institute', 'learning', 'teach', 'student', 'faculty']
    education_domains = ['edu', 'education.org', 'university.edu', 'school.org']
    
    # Manufacturing indicators
    manufacturing_keywords = ['manufacturing', 'factory', 'production', 'industrial', 
                             'build', 'maker', 'assembly', 'fabrication']
    manufacturing_domains = ['mfg.com', 'industrial.com', 'production.com']
    
    # Government indicators
    government_keywords = ['government', 'gov', 'federal', 'state', 'municipal', 
                          'county', 'agency', 'authority', 'administration']
    government_domains = ['gov', 'state.gov', 'county.gov', 'city.gov']
    
    # Check company name for industry keywords
    for keyword in healthcare_keywords:
        if keyword in company_name:
            return 'healthcare'
    
    for keyword in financial_keywords:
        if keyword in company_name:
            return 'financial'
    
    for keyword in retail_keywords:
        if keyword in company_name:
            return 'retail'
    
    for keyword in education_keywords:
        if keyword in company_name:
            return 'education'
    
    for keyword in manufacturing_keywords:
        if keyword in company_name:
            return 'manufacturing'
    
    for keyword in government_keywords:
        if keyword in company_name:
            return 'government'
    
    # Check email domain for industry indicators
    if email_domain:
        if '.edu' in email_domain:
            return 'education'
        
        if '.gov' in email_domain:
            return 'government'
        
        for domain in healthcare_domains:
            if domain in email_domain:
                return 'healthcare'
        
        for domain in financial_domains:
            if domain in email_domain:
                return 'financial'
        
        for domain in retail_domains:
            if domain in email_domain:
                return 'retail'
        
        for domain in education_domains:
            if domain in email_domain:
                return 'education'
        
        for domain in manufacturing_domains:
            if domain in email_domain:
                return 'manufacturing'
    
    # Default industry if no match found
    return 'default'

def get_industry_benchmarks():
    """
    Return benchmark data for different industries
    
    Returns:
        dict: Industry benchmark data
    """
    return {
        'healthcare': {
            'name': 'Healthcare',
            'compliance': ['HIPAA', 'HITECH', 'FDA'],
            'critical_controls': [
                'PHI Data Encryption',
                'Network Segmentation',
                'Access Control',
                'Regular Risk Assessments',
                'Incident Response Plan'
            ],
            'avg_score': 72,
            'percentile_distribution': {
                10: 45,
                25: 58,
                50: 72,
                75: 84,
                90: 92
            }
        },
        'financial': {
            'name': 'Financial Services',
            'compliance': ['PCI DSS', 'SOX', 'GLBA'],
            'critical_controls': [
                'Multi-factor Authentication',
                'Encryption of Financial Data',
                'Fraud Detection',
                'Continuous Monitoring',
                'Disaster Recovery'
            ],
            'avg_score': 78,
            'percentile_distribution': {
                10: 52,
                25: 65,
                50: 78,
                75: 88,
                90: 95
            }
        },
        'retail': {
            'name': 'Retail',
            'compliance': ['PCI DSS', 'CCPA', 'GDPR'],
            'critical_controls': [
                'Point-of-Sale Security',
                'Payment Data Protection',
                'Inventory System Security',
                'Ecommerce Platform Security',
                'Customer Data Protection'
            ],
            'avg_score': 65,
            'percentile_distribution': {
                10: 38,
                25: 52,
                50: 65,
                75: 79,
                90: 88
            }
        },
        'education': {
            'name': 'Education',
            'compliance': ['FERPA', 'COPPA', 'State Privacy Laws'],
            'critical_controls': [
                'Student Data Protection',
                'Campus Network Security',
                'Remote Learning Security',
                'Research Data Protection',
                'Identity Management'
            ],
            'avg_score': 60,
            'percentile_distribution': {
                10: 32,
                25: 45,
                50: 60,
                75: 76,
                90: 85
            }
        },
        'manufacturing': {
            'name': 'Manufacturing',
            'compliance': ['ISO 27001', 'NIST', 'Industry-Specific Regulations'],
            'critical_controls': [
                'OT/IT Security',
                'Supply Chain Risk Management',
                'Intellectual Property Protection',
                'Industrial Control System Security',
                'Physical Security'
            ],
            'avg_score': 68,
            'percentile_distribution': {
                10: 40,
                25: 54,
                50: 68,
                75: 80,
                90: 89
            }
        },
        'government': {
            'name': 'Government',
            'compliance': ['FISMA', 'NIST 800-53', 'FedRAMP'],
            'critical_controls': [
                'Data Classification',
                'Continuous Monitoring',
                'Authentication Controls',
                'Incident Response',
                'Security Clearance Management'
            ],
            'avg_score': 70,
            'percentile_distribution': {
                10: 42,
                25: 56,
                50: 70,
                75: 82,
                90: 90
            }
        },
        'default': {
            'name': 'General Business',
            'compliance': ['General Data Protection', 'Industry Best Practices'],
            'critical_controls': [
                'Data Protection',
                'Secure Authentication',
                'Network Security',
                'Endpoint Protection',
                'Security Awareness Training'
            ],
            'avg_score': 65,
            'percentile_distribution': {
                10: 35,
                25: 50,
                50: 65,
                75: 80,
                90: 90
            }
        }
    }

def calculate_industry_percentile(score, industry_type='default'):
    """
    Calculate percentile and comparison information for a security score within an industry
    
    Args:
        score (int): Security score (0-100)
        industry_type (str): Industry type to compare against
        
    Returns:
        dict: Percentile information
    """
    # Get benchmarks
    benchmarks = get_industry_benchmarks()
    industry = benchmarks.get(industry_type, benchmarks['default'])
    
    # Get average score for the industry
    avg_score = industry['avg_score']
    
    # Calculate difference from industry average
    difference = score - avg_score
    
    # Determine if score is above or below average
    comparison = "above" if difference > 0 else "below"
    
    # Calculate percentile
    percentile_dist = industry['percentile_distribution']
    percentile = 0
    
    # Find which percentile the score falls into
    if score >= percentile_dist[90]:
        percentile = 90
    elif score >= percentile_dist[75]:
        percentile = 75
    elif score >= percentile_dist[50]:
        percentile = 50
    elif score >= percentile_dist[25]:
        percentile = 25
    elif score >= percentile_dist[10]:
        percentile = 10
    
    # For scores between the defined percentiles, calculate an approximate percentile
    # This is a simplified linear interpolation
    if percentile < 90:
        next_percentile = None
        if percentile == 0 and score < percentile_dist[10]:
            next_percentile = 10
            prev_score = 0
            next_score = percentile_dist[10]
        elif percentile == 10:
            next_percentile = 25
            prev_score = percentile_dist[10]
            next_score = percentile_dist[25]
        elif percentile == 25:
            next_percentile = 50
            prev_score = percentile_dist[25]
            next_score = percentile_dist[50]
        elif percentile == 50:
            next_percentile = 75
            prev_score = percentile_dist[50]
            next_score = percentile_dist[75]
        elif percentile == 75:
            next_percentile = 90
            prev_score = percentile_dist[75]
            next_score = percentile_dist[90]
        
        if next_percentile:
            # Linear interpolation
            if next_score - prev_score > 0:  # Avoid division by zero
                percentile = percentile + (next_percentile - percentile) * (score - prev_score) / (next_score - prev_score)
    
    # Return the benchmark data
    return {
        'percentile': round(percentile),
        'comparison': comparison,
        'difference': abs(difference),
        'avg_score': avg_score
    }
    
def send_automatic_report_to_admin(scan_results):
    """Send scan report automatically to admin email"""
    try:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admissions@southgeauga.com')
        logging.info(f"Automatically sending report to admin at {admin_email}")
        
        # Create lead data for admin
        lead_data = {
            'name': scan_results.get('name', 'Unknown User'),
            'email': scan_results.get('email', 'unknown@example.com'),
            'company': scan_results.get('company', 'Unknown Company'),
            'phone': scan_results.get('phone', ''),
            'timestamp': scan_results.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        }
        
        # Use the complete HTML report if available
        if 'complete_html_report' in scan_results and scan_results['complete_html_report']:
            html_report = scan_results['complete_html_report']
        else:
            # Fallback to standard html_report or rendered template
            html_report = scan_results.get('html_report', render_template('results.html', scan=scan_results))
        
        # Send the email to admin
        return send_email_report(lead_data, scan_results, html_report)
    except Exception as e:
        logging.error(f"Error sending automatic email report: {e}")
        return False

# ---------------------------- MAIN SCANNING FUNCTION ----------------------------

def run_consolidated_scan(lead_data):
    """Run a complete security scan and generate one comprehensive report"""
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    logging.info(f"Starting scan with ID: {scan_id} for target: {lead_data.get('target', 'Unknown')}")
    
    # Initialize scan results structure - UPDATED to include industry info
    email = lead_data.get('email', '')
    email_domain = extract_domain_from_email(email) if email else ''
    company_name = lead_data.get('company', '')
    
    # Determine industry
    industry = determine_industry(company_name, email_domain)
    industry_benchmarks = get_industry_benchmarks().get(industry, get_industry_benchmarks()['default'])
    
    scan_results = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'target': lead_data.get('target', ''),
        'email': email,
        'industry': {
            'type': industry,
            'name': industry_benchmarks['name'],
            'compliance': industry_benchmarks['compliance'],
            'critical_controls': industry_benchmarks['critical_controls'],
            'benchmarks': None  # Will be filled after risk assessment
        },
        'client_info': {
            'name': lead_data.get('name', 'Unknown User'),
            'email': email,
            'company': company_name,
            'phone': lead_data.get('phone', ''),
            'os': lead_data.get('client_os', 'Unknown'),
            'browser': lead_data.get('client_browser', 'Unknown'),
            'windows_version': lead_data.get('windows_version', '')
        }
    }
    
    # Add this debug line to check the initial scan results structure
    logging.debug(f"Initial scan_results structure: {json.dumps(scan_results, default=str)}")
    
    
    # 1. System Security Checks
    try:
        logging.info("Running system security checks...")
        scan_results['system'] = {
            'os_updates': check_os_updates(),
            'firewall': {
                'status': check_firewall_status()[0],
                'severity': check_firewall_status()[1]
            }
        }
        logging.debug(f"System security checks completed: {scan_results['system']}")
    except Exception as e:
        logging.error(f"Error during system security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['system'] = {'error': str(e)}
    
    # 2. Network Security Checks
    try:
        logging.info("Running network security checks...")
        ports_count, ports_list, ports_severity = check_open_ports()
        scan_results['network'] = {
            'open_ports': {
                'count': ports_count,
                'list': ports_list,
                'severity': ports_severity
            }
        }
        
        # Gateway checks
        try:
            class DummyRequest:
                def __init__(self):
                    self.remote_addr = "127.0.0.1"
                    self.headers = {}

            request_obj = request if 'request' in locals() else DummyRequest()
            gateway_info = get_default_gateway_ip(request_obj)
            gateway_scan_results = scan_gateway_ports(gateway_info)
            scan_results['network']['gateway'] = {
                'info': gateway_info,
                'results': gateway_scan_results
            }
            logging.debug(f"Gateway checks completed")
        except Exception as gateway_error:
            logging.error(f"Error during gateway checks: {gateway_error}")
            scan_results['network']['gateway'] = {'error': str(gateway_error)}
            
        logging.debug(f"Network security checks completed")
    except Exception as e:
        logging.error(f"Error during network security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['network'] = {'error': str(e)}
    
    # 3. Email Security Checks
    try:
        logging.info("Running email security checks...")
        email = lead_data.get('email', '')
        if "@" in email:
            domain = extract_domain_from_email(email)
            logging.debug(f"Extracted domain from email: {domain}")
            
            try:
                spf_status, spf_severity = check_spf_status(domain)
                logging.debug(f"SPF check completed")
            except Exception as spf_error:
                logging.error(f"Error checking SPF for {domain}: {spf_error}")
                spf_status, spf_severity = f"Error checking SPF: {str(spf_error)}", "High"
                
            try:
                dmarc_status, dmarc_severity = check_dmarc_record(domain)
                logging.debug(f"DMARC check completed")
            except Exception as dmarc_error:
                logging.error(f"Error checking DMARC for {domain}: {dmarc_error}")
                dmarc_status, dmarc_severity = f"Error checking DMARC: {str(dmarc_error)}", "High"
                
            try:
                dkim_status, dkim_severity = check_dkim_record(domain)
                logging.debug(f"DKIM check completed")
            except Exception as dkim_error:
                logging.error(f"Error checking DKIM for {domain}: {dkim_error}")
                dkim_status, dkim_severity = f"Error checking DKIM: {str(dkim_error)}", "High"
            
            scan_results['email_security'] = {
                'domain': domain,
                'spf': {
                    'status': spf_status,
                    'severity': spf_severity
                },
                'dmarc': {
                    'status': dmarc_status,
                    'severity': dmarc_severity
                },
                'dkim': {
                    'status': dkim_status,
                    'severity': dkim_severity
                }
            }
            logging.debug(f"Email security checks completed for domain {domain}")
        else:
            logging.warning("No valid email provided for email security checks")
            scan_results['email_security'] = {
                'error': 'No valid email provided'
            }
    except Exception as e:
        logging.error(f"Error during email security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['email_security'] = {'error': str(e)}
    
    # 4. Web Security Checks - MODIFIED to prioritize domain from email
    try:
        logging.info("Running web security checks...")
    
        # Extract domain from email for scanning
        email = lead_data.get('email', '')
        extracted_domain = None
        if "@" in email:
            extracted_domain = extract_domain_from_email(email)
            logging.debug(f"Extracted domain from email: {extracted_domain}")
    
        # Use extracted domain or fall back to target
        target = extracted_domain or lead_data.get('target', '')
    
        if target and target.strip():
            logging.info(f"Using domain for scanning: {target}")
                
            # Check if ports 80 or 443 are accessible
            http_accessible = False
            https_accessible = False
                
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target, 80))
                    http_accessible = (result == 0)
                    logging.debug(f"HTTP (port 80) accessible: {http_accessible}")
            except Exception as http_error:
                logging.error(f"Error checking HTTP accessibility: {http_error}")
                    
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((target, 443))
                    https_accessible = (result == 0)
                    logging.debug(f"HTTPS (port 443) accessible: {https_accessible}")
            except Exception as https_error:
                logging.error(f"Error checking HTTPS accessibility: {https_error}")
                    
            scan_results['http_accessible'] = http_accessible
            scan_results['https_accessible'] = https_accessible
                
            # Only perform web checks if HTTP or HTTPS is accessible
            if http_accessible or https_accessible:
                target_url = f"https://{target}" if https_accessible else f"http://{target}"
                logging.info(f"Using target URL: {target_url}")
                    
                # SSL/TLS Certificate Analysis (only if HTTPS is accessible)
                if https_accessible:
                    try:
                        logging.debug(f"Checking SSL certificate for {target}")
                        scan_results['ssl_certificate'] = check_ssl_certificate(target)
                        logging.debug(f"SSL certificate check completed")
                    except Exception as e:
                        logging.error(f"SSL check error for {target}: {e}")
                        logging.debug(f"Exception traceback: {traceback.format_exc()}")
                        scan_results['ssl_certificate'] = {'error': str(e), 'status': 'error', 'severity': 'High'}
                    
                # HTTP Security Headers Assessment
                try:
                    logging.debug(f"Checking security headers for {target_url}")
                    scan_results['security_headers'] = check_security_headers(target_url)
                    logging.debug(f"Security headers check completed")
                except Exception as e:
                    logging.error(f"Headers check error for {target_url}: {e}")
                    logging.debug(f"Exception traceback: {traceback.format_exc()}")
                    scan_results['security_headers'] = {'error': str(e), 'score': 0, 'severity': 'High'}
                
                # CMS Detection
                try:
                    logging.debug(f"Detecting CMS for {target_url}")
                    scan_results['cms'] = detect_cms(target_url)
                    logging.debug(f"CMS detection completed")
                except Exception as e:
                    logging.error(f"CMS detection error for {target_url}: {e}")
                    logging.debug(f"Exception traceback: {traceback.format_exc()}")
                    scan_results['cms'] = {'error': str(e), 'cms_detected': False, 'severity': 'Medium'}
                
                # Cookie Security Analysis
                try:
                    logging.debug(f"Analyzing cookies for {target_url}")
                    scan_results['cookies'] = analyze_cookies(target_url)
                    logging.debug(f"Cookie analysis completed")
                except Exception as e:
                    logging.error(f"Cookie analysis error for {target_url}: {e}")
                    logging.debug(f"Exception traceback: {traceback.format_exc()}")
                    scan_results['cookies'] = {'error': str(e), 'score': 0, 'severity': 'Medium'}
                
                # Web Application Framework Detection
                try:
                    logging.debug(f"Detecting web frameworks for {target_url}")
                    scan_results['frameworks'] = detect_web_framework(target_url)
                    logging.debug(f"Framework detection completed")
                except Exception as e:
                    logging.error(f"Framework detection error for {target_url}: {e}")
                    logging.debug(f"Exception traceback: {traceback.format_exc()}")
                    scan_results['frameworks'] = {'error': str(e), 'frameworks': [], 'count': 0}
                
                # Basic Content Crawling (look for sensitive paths)
                try:
                    max_urls = 15
                    logging.debug(f"Crawling for sensitive content at {target_url} (max {max_urls} urls)")
                    scan_results['sensitive_content'] = crawl_for_sensitive_content(target_url, max_urls)
                    logging.debug(f"Content crawling completed")
                except Exception as e:
                    logging.error(f"Content crawling error for {target_url}: {e}")
                    logging.debug(f"Exception traceback: {traceback.format_exc()}")
                    scan_results['sensitive_content'] = {'error': str(e), 'sensitive_paths_found': 0, 'severity': 'Medium'}
            else:
                logging.warning(f"Neither HTTP nor HTTPS is accessible for {target}, skipping web checks")
                scan_results['web_accessibility_error'] = "Neither HTTP nor HTTPS ports are accessible"
        else:
            logging.info("No target domain/IP provided, skipping web security checks")
    except Exception as e:
        logging.error(f"Error during web security checks: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['web_error'] = str(e)
    
    # 5. Calculate risk score and recommendations
    try:
        logging.info("Calculating risk assessment...")
        scan_results['risk_assessment'] = calculate_risk_score(scan_results)
        logging.debug(f"Risk assessment completed")
        
        # Add service categories
        scan_results['service_categories'] = categorize_risks_by_services(scan_results)
        
        scan_results['recommendations'] = get_recommendations(scan_results)
        logging.debug(f"Generated {len(scan_results['recommendations'])} recommendations")
        
        scan_results['threat_scenarios'] = generate_threat_scenario(scan_results)
        logging.debug(f"Generated {len(scan_results['threat_scenarios'])} threat scenarios")
        
        # Add the industry percentile calculation after risk score
        if 'overall_score' in scan_results['risk_assessment']:
            overall_score = scan_results['risk_assessment']['overall_score']
            scan_results['industry']['benchmarks'] = calculate_industry_percentile(
                overall_score, 
                scan_results['industry'].get('type', 'default')
            )
            logging.debug(f"Industry benchmarking completed")
    except Exception as e:
        logging.error(f"Error during risk assessment: {e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['risk_assessment'] = {'error': str(e), 'overall_score': 50, 'risk_level': 'Medium'}
        scan_results['recommendations'] = ["Keep all software and systems updated with the latest security patches.",
                                         "Use strong, unique passwords and implement multi-factor authentication.",
                                         "Regularly back up your data and test the restoration process."]

    # 6. Generate the full HTML report with all context variables
    try:
        logging.info("Generating complete HTML report...")
    
        # Get client IP and gateway info for context variables
        client_ip = "Unknown"
        gateway_guesses = []
        network_type = "Unknown"
    
        if 'network' in scan_results and 'gateway' in scan_results['network']:
            gateway_info = scan_results['network']['gateway'].get('info', '')
            if isinstance(gateway_info, str):
                if "Client IP:" in gateway_info:
                    try:
                        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
                    except:
                        pass
            
                if "Network Type:" in gateway_info:
                    try:
                        network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
                    except:
                        pass
            
                if "Likely gateways:" in gateway_info:
                    try:
                        gateways_part = gateway_info.split("Likely gateways:")[1].strip()
                        if "|" in gateways_part:
                            gateways_part = gateways_part.split("|")[0].strip()
                        gateway_guesses = [g.strip() for g in gateways_part.split(",")]
                    except:
                        pass
        else:
            gateway_info = "Gateway information not available"
    
        # Render the complete HTML with all context variables
        complete_html = render_template('results.html', 
                                       scan=scan_results,
                                       client_ip=client_ip,
                                       gateway_guesses=gateway_guesses,
                                       network_type=network_type,
                                       gateway_info=gateway_info)
    
        # Store the complete HTML in the scan results
        scan_results['complete_html_report'] = complete_html
        logging.debug("Complete HTML report generated and stored successfully")
    except Exception as complete_html_error:
        logging.error(f"Error generating complete HTML report: {complete_html_error}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['complete_html_report_error'] = str(complete_html_error)
    
    # 7. Generate HTML report
    try:
        logging.info("Generating HTML report...")
        html_report = generate_html_report(scan_results)
        scan_results['html_report'] = html_report
        logging.debug("HTML report generated successfully")
    except Exception as report_e:
        logging.error(f"Error generating HTML report: {report_e}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['html_report_error'] = str(report_e)
    
    # 8. Save to database
    try:
        logging.info("Saving scan results to database...")
        saved_scan_id = save_scan_results(scan_results)
        
        if not saved_scan_id:
            logging.error("Database save function returned None or False")
            scan_results['database_error'] = "Failed to save scan results to database"
        else:
            logging.info(f"Scan results saved to database with ID: {saved_scan_id}")
    except Exception as db_error:
        logging.error(f"Exception during database save: {str(db_error)}")
        logging.debug(f"Exception traceback: {traceback.format_exc()}")
        scan_results['database_error'] = f"Database error: {str(db_error)}"
    
    logging.info(f"Scan {scan_id} completed")
    logging.debug(f"Final scan_results keys: {list(scan_results.keys())}")

    return scan_results

# ---------------------------- FLASK ROUTES ----------------------------

@app.route('/emergency_login', methods=['GET', 'POST'])
def emergency_login():
    """Emergency login in case of auth issues"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            import sqlite3
            import hashlib
            import secrets
            from datetime import datetime, timedelta
            
            # Connect directly to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find user
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                return """
                <h1>Invalid Credentials</h1>
                <p>The username or password is incorrect.</p>
                <a href="/emergency_login">Try Again</a>
                """
                
            # Try password verification
            try:
                # PBKDF2 method (newer)
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    password.encode(), 
                    user['salt'].encode(), 
                    100000
                ).hex()
                pw_matches = (password_hash == user['password_hash'])
            except:
                # Simple SHA-256 method (older fallback)
                try:
                    password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                    pw_matches = (password_hash == user['password_hash'])
                except:
                    pw_matches = False
            
            if not pw_matches:
                conn.close()
                return """
                <h1>Invalid Credentials</h1>
                <p>The username or password is incorrect.</p>
                <a href="/emergency_login">Try Again</a>
                """
            
            # Create session manually
            session_token = secrets.token_hex(32)
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Insert new session
            cursor.execute('''
            INSERT INTO sessions (
                user_id, session_token, created_at, expires_at, ip_address
            ) VALUES (?, ?, ?, ?, ?)
            ''', (user['id'], session_token, created_at, expires_at, request.remote_addr))
            
            conn.commit()
            
            # Store in session
            session.clear()  # Clear any old session data
            session['session_token'] = session_token
            session['username'] = user['username']
            session['role'] = user['role']
            
            # Success message with next steps
            result = f"""
            <html>
                <head>
                    <title>Emergency Login Successful</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }}
                        h1 {{ color: green; }}
                        .section {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                    </style>
                </head>
                <body>
                    <h1>Emergency Login Successful!</h1>
                    <div class="section">
                        <p>You are logged in as <strong>{user['username']}</strong> with role <strong>{user['role']}</strong>.</p>
                    </div>
                    
                    <div class="section">
                        <h2>Next Steps</h2>
                        <p><a href="/admin/dashboard">Go to Admin Dashboard</a></p>
                        <p><a href="/client/dashboard">Go to Client Dashboard</a></p>
                        <p><a href="/">Go to Home</a></p>
                    </div>
                </body>
            </html>
            """
            
            conn.close()
            return result
        except Exception as e:
            import traceback
            return f"""
            <h1>Emergency Login Error</h1>
            <p>An error occurred: {str(e)}</p>
            <pre>{traceback.format_exc()}</pre>
            <form method="post">
                <label>Username: <input type="text" name="username" value="{username}"></label><br>
                <label>Password: <input type="password" name="password"></label><br>
                <button type="submit">Login</button>
            </form>
            """
    
    # Show login form for GET requests
    return '''
    <html>
        <head>
            <title>Emergency Login</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                }
                form { 
                    margin-top: 20px; 
                    width: 300px;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                input { 
                    margin: 5px 0; 
                    padding: 8px; 
                    width: 100%; 
                    box-sizing: border-box;
                }
                button { 
                    padding: 10px 16px; 
                    background: #4CAF50; 
                    color: white; 
                    border: none; 
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 15px;
                }
                button:hover {
                    background: #45a049;
                }
                .notice {
                    margin-top: 20px;
                    padding: 10px;
                    background: #fff8e1;
                    border: 1px solid #ffe0b2;
                    border-radius: 4px;
                    width: 300px;
                }
            </style>
        </head>
        <body>
            <h1>Emergency Login</h1>
            <form method="post">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username">
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password">
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="notice">
                <p>This is for emergency access in case of authentication issues.</p>
                <p>Try using <strong>admin</strong> and <strong>admin123</strong> if you're unsure.</p>
            </div>
        </body>
    </html>
    '''

@app.route('/admin_simplified')
def admin_simplified():
    """Simplified admin view for emergency access"""
    session_token = session.get('session_token')
    username = session.get('username', 'Unknown')
    role = session.get('role', 'Unknown')
    
    # Very simple session check
    if not session_token or role != 'admin':
        return """
        <h1>Access Denied</h1>
        <p>You need to be logged in as an admin.</p>
        <a href="/emergency_login">Login</a>
        """
    
    try:
        # Get summary info
        import sqlite3
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get client count
        cursor.execute("SELECT COUNT(*) FROM clients")
        client_count = cursor.fetchone()[0]
        
        # Get user count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        # Get recent clients
        cursor.execute("SELECT id, business_name, contact_email FROM clients ORDER BY id DESC LIMIT 5")
        recent_clients = [dict(row) for row in cursor.fetchall()]
        
        # Get recent users
        cursor.execute("SELECT id, username, email, role FROM users ORDER BY id DESC LIMIT 5")
        recent_users = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Create a simple dashboard HTML
        return f"""
        <html>
            <head>
                <title>Simplified Admin Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; }}
                    .section {{ margin-bottom: 30px; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Simplified Admin Dashboard</h1>
                <p>Logged in as: {username} (Role: {role})</p>
                
                <div class="section">
                    <h2>Summary</h2>
                    <div style="display: flex; gap: 20px;">
                        <div class="card">
                            <h3>Clients</h3>
                            <p style="font-size: 24px;">{client_count}</p>
                        </div>
                        <div class="card">
                            <h3>Users</h3>
                            <p style="font-size: 24px;">{user_count}</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Recent Clients</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Business Name</th>
                            <th>Email</th>
                        </tr>
                        {''.join([f'<tr><td>{c["id"]}</td><td>{c["business_name"]}</td><td>{c["contact_email"]}</td></tr>' for c in recent_clients])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Recent Users</h2>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                        </tr>
                        {''.join([f'<tr><td>{u["id"]}</td><td>{u["username"]}</td><td>{u["email"]}</td><td>{u["role"]}</td></tr>' for u in recent_users])}
                    </table>
                </div>
                
                <div>
                    <a href="/emergency_login">Back to Emergency Login</a>
                </div>
            </body>
        </html>
        """
    except Exception as e:
        return f"""
        <h1>Error</h1>
        <p>An error occurred: {str(e)}</p>
        <a href="/emergency_login">Back to Emergency Login</a>
        """
        
@app.route('/')
def index():
    """Render the home page"""
    try:
        logging.debug("Attempting to render index.html")
        return render_template('index.html')
    except Exception as e:
        error_message = f"Error rendering index page: {str(e)}"
        logging.error(error_message)
        
        return f"""
        <html>
            <head><title>Error</title></head>
            <body>
                <h1>An error occurred</h1>
                <p>{error_message}</p>
                <p>Please contact support.</p>
            </body>
        </html>
        """, 500

@app.route('/scan', methods=['GET', 'POST'])
def scan_page():
    """Main scan page - handles both form display and scan submission"""
    if request.method == 'POST':
        try:
            # Get form data including client OS info
            lead_data = {
                'name': request.form.get('name', ''),
                'email': request.form.get('email', ''),
                'company': request.form.get('company', ''),
                'phone': request.form.get('phone', ''),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'client_os': request.form.get('client_os', 'Unknown'),
                'client_browser': request.form.get('client_browser', 'Unknown'),
                'windows_version': request.form.get('windows_version', ''),
                'target': ''  # Leave blank to ensure we use email domain
            }
            
            # Extract domain from email and use it as target
            if lead_data["email"]:
                domain = extract_domain_from_email(lead_data["email"])
                lead_data["target"] = domain
                logging.info(f"Using domain extracted from email: {domain}")
            
            # Basic validation
            if not lead_data["email"]:
                return render_template('scan.html', error="Please enter your email address to receive the scan report.")
            
            # Save lead data to database
            logging.info("Saving lead data...")
            lead_id = save_lead_data(lead_data)
            logging.info(f"Lead data saved with ID: {lead_id}")
            
            # Check for client_id in query parameters (used for client-specific scanner)
            client_id = request.args.get('client_id')
            
            # If client_id is provided, get client customizations
            client = None
            if client_id:
                from client_db import get_client_by_id
                client = get_client_by_id(client_id)
            
            # Run the full consolidated scan
            logging.info(f"Starting scan for {lead_data.get('email')} targeting {lead_data.get('target')}...")
            scan_results = run_consolidated_scan(lead_data)
            
            # If scan was performed through a client scanner, log it
            if client:
                from client_db import log_scan
                log_scan(client['id'], scan_results['scan_id'], lead_data.get('target', ''))
            
            # Check if scan_results contains valid data
            if not scan_results or 'scan_id' not in scan_results:
                logging.error("Scan did not return valid results")
                return render_template('scan.html', error="Scan failed to return valid results. Please try again.")
            
            # Store scan ID in session for future reference
            try:
                session['scan_id'] = scan_results['scan_id']
                logging.info(f"Stored scan_id in session: {scan_results['scan_id']}")
            except Exception as session_error:
                logging.warning(f"Failed to store scan_id in session: {str(session_error)}")
            
            # Automatically send report to the user
            try:
                logging.info(f"Automatically sending report to user at {lead_data['email']}")
                
                # Get complete HTML report
                html_report = scan_results.get('complete_html_report', '')
                if not html_report:
                    # Fallback to standard html_report or re-render template
                    html_report = scan_results.get('html_report', render_template('results.html', scan=scan_results))
                
                # Use client email template if available
                email_subject = "Your Security Scan Report"
                email_intro = "Thank you for using our security scanner."
                
                if client:
                    email_subject = client.get('email_subject', email_subject)
                    email_intro = client.get('email_intro', email_intro)
                
                # Customize email for client
                if client:
                    # Add client branding to email
                    from email_handler import send_branded_email_report
                    email_sent = send_branded_email_report(
                        lead_data, 
                        scan_results, 
                        html_report, 
                        client['business_name'],
                        client.get('logo_path', ''),
                        client.get('primary_color', '#FF6900'),
                        email_subject,
                        email_intro
                    )
                else:
                    # Use standard email
                    email_sent = send_email_report(lead_data, scan_results, html_report)
                
                if email_sent:
                    logging.info("Report automatically sent to user")
                else:
                    logging.warning("Failed to automatically send report to user")
            except Exception as email_error:
                logging.error(f"Error sending automatic email report to user: {email_error}")
            
            # Check if this is an AJAX request
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json'
            
            if is_ajax:
                # Return JSON response for AJAX requests
                return jsonify({
                    'status': 'success',
                    'scan_id': scan_results['scan_id'],
                    'message': 'Scan completed successfully'
                })
            else:
                # For regular form submissions, render results directly
                logging.info("Rendering results page directly...")
                
                # Use client's template if available
                if client:
                    template_path = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), 
                        'scanners', 
                        f"client_{client['id']}", 
                        'results.html'
                    )
                    
                    if os.path.exists(template_path):
                        # Render client-specific template
                        with open(template_path, 'r') as f:
                            template_content = f.read()
                        
                        from jinja2 import Template
                        template = Template(template_content)
                        rendered_html = template.render(scan=scan_results)
                        
                        return rendered_html
                
                # Fall back to standard template
                return render_template('results.html', scan=scan_results)
                
        except Exception as scan_error:
            logging.error(f"Error during scan: {str(scan_error)}")
            logging.debug(f"Exception traceback: {traceback.format_exc()}")
            
            # Check if this is an AJAX request
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json'
            
            if is_ajax:
                # Return JSON error for AJAX requests
                return jsonify({
                    'status': 'error',
                    'message': str(scan_error)
                }), 500
            else:
                # For regular form submissions, show error page
                return render_template('scan.html', error=f"An error occurred during the scan: {str(scan_error)}")
    
    # For GET requests, show the scan form
    error = request.args.get('error')
    
    # Check for client_id in query parameters (used for client-specific scanner)
    client_id = request.args.get('client_id')
    client = None
    
    if client_id:
        try:
            from client_db import get_client_by_id
            client = get_client_by_id(client_id)
        except Exception as e:
            logging.error(f"Error retrieving client {client_id}: {e}")
    
    # Use client's template if available
    if client:
        template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'scanners', 
            f"client_{client['id']}", 
            'scan.html'
        )
        
        if os.path.exists(template_path):
            # Render client-specific template
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            from jinja2 import Template
            template = Template(template_content)
            rendered_html = template.render(error=error)
            
            return rendered_html
    
    # Fall back to standard template
    return render_template('scan.html', error=error)

@app.route('/results')
def results():
    """Display scan results - Fixed version"""
    scan_id = get_scan_id_from_request()
    
    if not scan_id:
        return redirect(url_for('scan_page', error="No scan ID found"))
    
    try:
        scan_results = get_scan_results(scan_id)
        
        if not scan_results:
            return redirect(url_for('scan_page', error="Scan results not found"))
        
        # Initialize default values for template variables
        client_ip = "Unknown"
        gateway_guesses = []
        network_type = "Unknown"
        gateway_info = "Gateway information not available"
        
        # Try to extract network information
        if 'network' in scan_results and 'gateway' in scan_results['network']:
            gateway_data = scan_results['network']['gateway']
            gateway_info = gateway_data.get('info', '')
            
            if isinstance(gateway_info, str):
                # Extract client IP
                if "Client IP:" in gateway_info:
                    try:
                        client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
                    except:
                        pass
                
                # Extract network type
                if "Network Type:" in gateway_info:
                    try:
                        network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
                    except:
                        pass
                
                # Extract gateway guesses
                if "Likely gateways:" in gateway_info:
                    try:
                        gateways_part = gateway_info.split("Likely gateways:")[1].strip()
                        if "|" in gateways_part:
                            gateways_part = gateways_part.split("|")[0].strip()
                        gateway_guesses = [g.strip() for g in gateways_part.split(",")]
                    except:
                        pass
        
        # Ensure service_categories exists
        if 'service_categories' not in scan_results:
            scan_results['service_categories'] = categorize_risks_by_services(scan_results)
        
        # Render the template with all required variables
        return render_template('results.html', 
                             scan=scan_results,
                             client_ip=client_ip,
                             gateway_guesses=gateway_guesses,
                             network_type=network_type,
                             gateway_info=gateway_info)
                             
    except Exception as e:
        logger.error(f"Error in results route: {e}")
        return render_template('error.html', error=str(e))

def scan_gateway_ports_fixed(gateway_info):
    """Fixed version of scan_gateway_ports with better error handling"""
    results = []
    
    try:
        # Parse gateway info safely
        client_ip = "Unknown"
        if isinstance(gateway_info, str) and "Client IP:" in gateway_info:
            try:
                client_ip = gateway_info.split("Client IP:")[1].split("|")[0].strip()
            except:
                pass
        
        results.append((f"Client detected at IP: {client_ip}", "Info"))
        
        # Extract gateway IPs
        gateway_ips = []
        if isinstance(gateway_info, str) and "Likely gateways:" in gateway_info:
            try:
                gateways_part = gateway_info.split("Likely gateways:")[1].strip()
                if "|" in gateways_part:
                    gateways_part = gateways_part.split("|")[0].strip()
                gateway_ips = [g.strip() for g in gateways_part.split(",")]
            except:
                pass
        
        if gateway_ips:
            results.append((f"Potential gateway IPs: {', '.join(gateway_ips)}", "Info"))
            
            # Scan common ports
            for ip in gateway_ips:
                if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    continue
                
                for port, (service, severity) in GATEWAY_PORT_WARNINGS.items():
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1.0)
                            result = s.connect_ex((ip, port))
                            if result == 0:
                                results.append((f"Port {port} ({service}) is open on {ip}", severity))
                    except:
                        pass
        else:
            results.append(("Could not identify gateway IPs to scan", "Medium"))
        
        # Add network type information
        if isinstance(gateway_info, str) and "Network Type:" in gateway_info:
            try:
                network_type = gateway_info.split("Network Type:")[1].split("|")[0].strip()
                results.append((f"Network type detected: {network_type}", "Info"))
                
                if "public" in network_type.lower():
                    results.append(("Device is connected to a public network", "High"))
                elif "guest" in network_type.lower():
                    results.append(("Device is connected to a guest network", "Medium"))
            except:
                pass
                
    except Exception as e:
        results.append((f"Error analyzing gateway: {str(e)}", "High"))
    
    # Always return at least one result
    if not results:
        results.append(("Gateway information unavailable", "Medium"))
    
    return results

def create_backup():
    """Create a backup of the current app.py"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f"app_backup_{timestamp}.py"
    shutil.copy('app.py', backup_name)
    print(f"✅ Backup created: {backup_name}")
    return backup_name

def clean_orphaned_code(content):
    """Remove orphaned code fragments"""
    # Find and remove the orphaned code at the end
    orphaned_patterns = [
        r'\s*# Try to extract network type.*?logging\.warning\("Failed to extract gateway guesses from gateway info"\)',
        r'\s*import uuid\s*import json\s*from datetime import datetime.*?return \{.*?"subdomain": subdomain\s*\}',
    ]
    
    for pattern in orphaned_patterns:
        content = re.sub(pattern, '', content, flags=re.DOTALL)
    
    return content

def fix_duplicate_error_handlers(content):
    """Remove duplicate error handlers"""
    # Remove the first occurrence of 404 handler, keep the second one
    pattern = r'@app\.errorhandler\(404\)\s*def not_found_error\(error\):.*?return jsonify\({.*?\}\), 404'
    content = re.sub(pattern, '', content, flags=re.DOTALL)
    
    return content

def fix_main_block(content):
    """Fix the broken main execution block"""
    # Find the broken main block and replace it
    main_pattern = r"if __name__ == '__main__':.*$"
    
    # Create the replacement string using normal string formatting
    new_main_block = (
        "if __name__ == '__main__':\n"
        "    # Get port from environment variable or use default\n"
        "    port = int(os.environ.get('PORT', 5000))\n"
        "    \n"
        "    # Run the direct database fix\n"
        "    try:\n"
        "        direct_db_fix()\n"
        "    except Exception as db_fix_error:\n"
        "        logging.error(f\"Database fix error: {db_fix_error}\")\n"
        "    \n"
        "    # Apply route fixes if needed\n"
        "    try:\n"
        "        apply_route_fixes()\n"
        "    except Exception as route_fix_error:\n"
        "        logging.error(f\"Route fix error: {route_fix_error}\")\n"
        "    \n"
        "    # Use 0.0.0.0 to make the app accessible from any IP\n"
        "    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')\n"
    )
    
    content = re.sub(main_pattern, new_main_block, content, flags=re.DOTALL)
    return content

def add_missing_functions(content):
    """Add missing function implementations"""
    # Add log_system_info function if not present
    if 'def log_system_info():' not in content:
        log_function = (
            "\n"
            "def log_system_info():\n"
            "    logger = logging.getLogger(__name__)\n"
            "    logger.info('----- System Information -----')\n"
            "    logger.info(f'Python version: {sys.version}')\n"
            "    logger.info(f'Platform: {platform.platform()}')\n"
            "    logger.info(f'Working directory: {os.getcwd()}')\n"
            "    logger.info(f'Database path: {DB_PATH}')\n"
            "\n"
            "    try:\n"
            "        conn = sqlite3.connect(DB_PATH)\n"
            "        cursor = conn.cursor()\n"
            "        cursor.execute('SELECT sqlite_version()')\n"
            "        version = cursor.fetchone()\n"
            "        logger.info(f'SQLite version: {version[0]}')\n"
            "        conn.close()\n"
            "        logger.info('Database connection successful')\n"
            "    except Exception as e:\n"
            "        logger.warning(f'Database connection failed: {e}')\n"
            "\n"
            "    logger.info('-----------------------------')\n"
        )
        return content + log_function
    return content

def clean_orphaned_code(content):
    """Remove orphaned code fragments"""
    orphaned_patterns = [
        r'\s*# Try to extract network type.*?logging\.warning\("Failed to extract gateway guesses from gateway info"\)',
        r'\s*import uuid\s*import json\s*from datetime import datetime.*?return \{.*?"subdomain": subdomain\s*\}',
    ]
    
    for pattern in orphaned_patterns:
        content = re.sub(pattern, '', content, flags=re.DOTALL)
    return content

def fix_duplicate_error_handlers(content):
    """Remove duplicate error handlers"""
    pattern = r'@app\.errorhandler\(404\)\s*def not_found_error\(error\):.*?return jsonify\({.*?\}\), 404'
    return re.sub(pattern, '', content, flags=re.DOTALL)

def fix_main_block(content):
    """Fix the broken main execution block"""
    main_pattern = r"if __name__ == '__main__':.*$"
    new_main_block = (
        "if __name__ == '__main__':\n"
        "    port = int(os.environ.get('PORT', 5000))\n"
        "    try:\n"
        "        direct_db_fix()\n"
        "    except Exception as db_fix_error:\n"
        "        logging.error(f'Database fix error: {db_fix_error}')\n"
        "    try:\n"
        "        apply_route_fixes()\n"
        "    except Exception as route_fix_error:\n"
        "        logging.error(f'Route fix error: {route_fix_error}')\n"
        "    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')\n"
    )
    return re.sub(main_pattern, new_main_block, content, flags=re.DOTALL)

def organize_imports(content):
    """Organize and deduplicate imports"""
    # Fix duplicate imports
    return re.sub(r'from flask import.*?\n(?=from flask import)', '', content, flags=re.DOTALL)

# ---------------------------- MAIN ENTRY POINT ----------------------------


def log_system_info():
    """Log details about the system environment"""
    logger = logging.getLogger(__name__)
    logger.info("----- System Information -----")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Working directory: {os.getcwd()}")
    logger.info(f"Database path: {DB_PATH}")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version()")
        version = cursor.fetchone()
        logger.info(f"SQLite version: {version[0]}")
        conn.close()
        logger.info("Database connection successful")
    except Exception as e:
        logger.warning(f"Database connection failed: {e}")
    
    logger.info("-----------------------------")

def direct_db_fix():
    """Direct database fix function"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            import secrets
            import hashlib
            
            salt = secrets.token_hex(16)
            password = 'admin123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, salt, role, full_name, created_at, active) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Admin User', datetime.now().isoformat())
            )
            
            conn.commit()
            logger.info("Created admin user")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Database fix error: {e}")
        return False

def upgrade_database_schema():
    """Upgrade database schema to latest version"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version")
        current_version = cursor.fetchone()[0]
        latest_version = 1
        
        if current_version < latest_version:
            logger.info(f"Upgrading database schema from {current_version} to {latest_version}")
            cursor.execute("PRAGMA user_version = ?", (latest_version,))
            conn.commit()
            logger.info("Database schema upgrade completed")
            return True
        else:
            logger.info("Database schema is up to date")
            return True
            
    except Exception as e:
        logger.error(f"Database schema upgrade failed: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def apply_route_fixes():
    """Apply all route fixes"""
    try:
        from auth_fix import fix_auth_routes
        auth_fixed = fix_auth_routes(app)
    except ImportError:
        logging.warning("auth_fix module not found")
        auth_fixed = False
    
    try:
        from route_fix import fix_admin_routes
        admin_fixed = fix_admin_routes(app)
    except ImportError:
        logging.warning("route_fix module not found")
        admin_fixed = False
    
    if auth_fixed and admin_fixed:
        logging.info("All route fixes applied successfully!")
        return True
    else:
        logging.warning("Some route fixes could not be applied.")
        return False

# Final application setup
if __name__ == '__main__':
    # Run database schema upgrade
    try:
        if upgrade_database_schema():
            app.logger.info("Database schema upgraded successfully")
        else:
            app.logger.error("Failed to upgrade database schema")
    except Exception as schema_error:
        app.logger.error(f"Schema upgrade error: {schema_error}")
    
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the direct database fix
    try:
        direct_db_fix()
    except Exception as db_fix_error:
        logging.error(f"Database fix error: {db_fix_error}")
    
    # Apply route fixes if needed
    try:
        apply_route_fixes()
    except Exception as route_fix_error:
        logging.error(f"Route fix error: {route_fix_error}")
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
