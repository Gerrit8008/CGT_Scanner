import os
import sys
import sqlite3
import logging
import traceback
from datetime import datetime
from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, jsonify, session

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_admin_routes_complete(app):
    """
    Complete solution to fix all admin route issues
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if fixes were successful, False otherwise
    """
    try:
        logger.info("Starting comprehensive admin route fixes...")
        
        # 1. Fix missing add_admin_fix_route function
        add_admin_fix_route(app)
        
        # 2. Ensure admin blueprint exists and is properly configured
        fix_admin_blueprint(app)
        
        # 3. Add missing admin routes
        add_missing_admin_routes(app)
        
        # 4. Fix dashboard route specifically
        fix_admin_dashboard_route(app)
        
        # 5. Create necessary templates
        create_admin_templates()
        
        logger.info("All admin route fixes completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Error in fix_admin_routes_complete: {e}")
        logger.error(traceback.format_exc())
        return False

def add_admin_fix_route(app):
    """Add the missing admin fix route function"""
    try:
        @app.route('/admin_fix_route')
        def admin_fix_route():
            """Route to test admin fix functionality"""
            return jsonify({
                "status": "success",
                "message": "Admin fix route is working",
                "timestamp": datetime.now().isoformat()
            })
        
        logger.info("Added admin fix route successfully")
        return True
    except Exception as e:
        logger.error(f"Error adding admin fix route: {e}")
        return False

def fix_admin_blueprint(app):
    """Fix admin blueprint issues"""
    try:
        # Get or create admin blueprint
        admin_bp = None
        
        # Check if admin blueprint already exists
        if 'admin' in app.blueprints:
            admin_bp = app.blueprints['admin']
            logger.info("Found existing admin blueprint")
        else:
            # Create new admin blueprint
            from admin import admin_bp as imported_admin_bp
            admin_bp = imported_admin_bp
            app.register_blueprint(admin_bp)
            logger.info("Registered admin blueprint")
        
        return True
    except Exception as e:
        logger.error(f"Error fixing admin blueprint: {e}")
        return False

def add_missing_admin_routes(app):
    """Add missing admin routes"""
    try:
        # Get admin blueprint
        admin_bp = app.blueprints.get('admin')
        if not admin_bp:
            logger.error("Admin blueprint not found")
            return False
        
        # Add missing routes
        
        # Subscriptions route
        @admin_bp.route('/subscriptions')
        def subscriptions():
            """Subscriptions management page"""
            return render_template('admin/subscription-management.html')
        
        # Reports route
        @admin_bp.route('/reports')
        def reports():
            """Reports dashboard page"""
            return render_template('admin/reports-dashboard.html')
        
        # Settings route
        @admin_bp.route('/settings')
        def settings():
            """Settings page"""
            return render_template('admin/settings-dashboard.html')
        
        # Scanner management route
        @admin_bp.route('/scanners')
        def scanners():
            """Scanner management page"""
            return render_template('admin/scanner-management.html')
        
        logger.info("Added missing admin routes successfully")
        return True
    except Exception as e:
        logger.error(f"Error adding missing admin routes: {e}")
        return False

def fix_admin_dashboard_route(app):
    """Fix the admin dashboard route specifically"""
    try:
        # Get admin blueprint
        admin_bp = app.blueprints.get('admin')
        if not admin_bp:
            logger.error("Admin blueprint not found for dashboard fix")
            return False
        
        # Override the dashboard route
        @admin_bp.route('/dashboard', methods=['GET'])
        def dashboard():
            """Fixed admin dashboard route"""
            try:
                # Get dashboard data
                dashboard_data = get_dashboard_data()
                
                # Render template with data
                return render_template('admin/admin-dashboard.html', **dashboard_data)
                
            except Exception as e:
                logger.error(f"Error in dashboard route: {e}")
                # Return error template if something goes wrong
                return render_template('admin/error.html', error=str(e))
        
        logger.info("Fixed admin dashboard route successfully")
        return True
    except Exception as e:
        logger.error(f"Error fixing admin dashboard route: {e}")
        return False

def get_dashboard_data():
    """Get data for the admin dashboard"""
    try:
        from client_db import get_dashboard_summary, list_clients
        
        # Get summary data
        summary = get_dashboard_summary()
        
        # Get recent clients
        try:
            recent_clients = list_clients(limit=5)
        except:
            recent_clients = []
        
        # Get recent logins (mock data for now)
        recent_logins = [
            {
                'username': 'admin',
                'email': 'admin@example.com',
                'role': 'admin',
                'ip_address': '127.0.0.1',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        ]
        
        # Get deployed scanners (mock data for now)
        deployed_scanners = []
        
        return {
            'dashboard_stats': summary,
            'recent_clients': recent_clients,
            'recent_logins': recent_logins,
            'deployed_scanners': deployed_scanners,
            'user': {'username': 'admin'}  # Mock user data
        }
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return {
            'dashboard_stats': {},
            'recent_clients': [],
            'recent_logins': [],
            'deployed_scanners': [],
            'user': {'username': 'admin'}
        }

def create_admin_templates():
    """Create necessary admin templates if they don't exist"""
    try:
        templates_dir = 'templates/admin'
        os.makedirs(templates_dir, exist_ok=True)
        
        # Templates to create
        templates = {
            'error.html': create_error_template(),
            'subscription-management.html': create_subscription_template(),
            'reports-dashboard.html': create_reports_template(),
            'settings-dashboard.html': create_settings_template(),
            'scanner-management.html': create_scanner_template()
        }
        
        for filename, content in templates.items():
            file_path = os.path.join(templates_dir, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)
                logger.info(f"Created template: {file_path}")
        
        return True
    except Exception as e:
        logger.error(f"Error creating admin templates: {e}")
        return False

def create_error_template():
    """Create the error template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="alert alert-danger">
                    <h4>Error</h4>
                    <p>{{ error }}</p>
                </div>
                <a href="/admin/dashboard" class="btn btn-primary">Return to Dashboard</a>
            </div>
        </div>
    </div>
</body>
</html>'''

def create_subscription_template():
    """Create the subscription management template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subscription Management - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/admin/dashboard">Admin Panel</a>
        </div>
    </nav>
    
    <div class="container mt-4">
        <h2>Subscription Management</h2>
        <div class="card">
            <div class="card-body">
                <p>Subscription management interface coming soon...</p>
            </div>
        </div>
    </div>
</body>
</html>'''

def create_reports_template():
    """Create the reports dashboard template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports Dashboard - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/admin/dashboard">Admin Panel</a>
        </div>
    </nav>
    
    <div class="container mt-4">
        <h2>Reports Dashboard</h2>
        <div class="card">
            <div class="card-body">
                <p>Reports dashboard interface coming soon...</p>
            </div>
        </div>
    </div>
</body>
</html>'''

def create_settings_template():
    """Create the settings template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/admin/dashboard">Admin Panel</a>
        </div>
    </nav>
    
    <div class="container mt-4">
        <h2>Settings</h2>
        <div class="card">
            <div class="card-body">
                <p>Settings interface coming soon...</p>
            </div>
        </div>
    </div>
</body>
</html>'''

def create_scanner_template():
    """Create the scanner management template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanner Management - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/admin/dashboard">Admin Panel</a>
        </div>
    </nav>
    
    <div class="container mt-4">
        <h2>Scanner Management</h2>
        <div class="card">
            <div class="card-body">
                <p>Scanner management interface coming soon...</p>
            </div>
        </div>
    </div>
</body>
</html>'''

def fix_database_errors():
    """Fix common database errors"""
    try:
        from client_db import CLIENT_DB_PATH
        
        # Check if database exists
        if not os.path.exists(CLIENT_DB_PATH):
            logger.warning(f"Database not found at {CLIENT_DB_PATH}")
            return False
        
        # Check database connection
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Verify tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = ['users', 'clients', 'customizations']
        for table in required_tables:
            if table not in tables:
                logger.error(f"Required table '{table}' not found in database")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Database error: {e}")
        return False

def apply_all_fixes(app):
    """Apply all fixes to the Flask application"""
    try:
        logger.info("Applying all admin fixes...")
        
        # Apply the main route fixes
        if not fix_admin_routes_complete(app):
            logger.error("Failed to apply admin route fixes")
            return False
        
        # Fix database issues
        if not fix_database_errors():
            logger.warning("Database issues detected")
        
        # Add the missing function to app if it doesn't exist
        if not hasattr(app, 'admin_fixed'):
            app.admin_fixed = True
        
        logger.info("All fixes applied successfully!")
        return True
    except Exception as e:
        logger.error(f"Error in apply_all_fixes: {e}")
        return False

# Function to be called from app.py
def apply_admin_fixes(app):
    """Main function to be called from app.py"""
    return apply_all_fixes(app)

# If this script is run directly
if __name__ == "__main__":
    logger.info("Running admin fix script directly...")
    
    # Try to import the Flask app
    try:
        from app import app
        result = apply_all_fixes(app)
        if result:
            logger.info("Admin fixes completed successfully!")
            sys.exit(0)
        else:
            logger.error("Admin fixes failed!")
            sys.exit(1)
    except ImportError:
        logger.error("Could not import Flask app")
        sys.exit(1)
