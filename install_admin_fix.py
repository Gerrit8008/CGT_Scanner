# install_admin_fix.py
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_templates():
    """Create all necessary admin template files"""
    templates_dir = 'templates/admin'
    
    # Make sure the templates directory exists
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir, exist_ok=True)
        logger.info(f"Created templates directory: {templates_dir}")
    
    # Define templates to create (abbreviated to save space)
    templates = {
        'subscription-management.html': "<!-- Template content here -->",
        'reports-dashboard.html': "<!-- Template content here -->",
        'settings-dashboard.html': "<!-- Template content here -->",
        'scanner-management.html': "<!-- Template content here -->"
    }
    
    # Placeholder - in the actual implementation you would include the full template content
    
    # Create each template
    for template_name, template_content in templates.items():
        template_path = os.path.join(templates_dir, template_name)
        
        # Only create if it doesn't exist
        if not os.path.exists(template_path):
            with open(template_path, 'w') as f:
                f.write(template_content)
            logger.info(f"Created template: {template_name}")
        else:
            logger.info(f"Template already exists: {template_name}")
    
    return True

def create_admin_routes():
    """Create admin_routes.py with a blueprint for all missing routes"""
    content = """# admin_routes.py
# This module provides routes for the admin section that were missing

from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from auth_utils import verify_session

# Create a blueprint for the missing admin routes
admin_routes_bp = Blueprint('admin_routes', __name__, url_prefix='/admin')

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
    return decorated_function

@admin_routes_bp.route('/subscriptions')
@admin_required
def subscriptions(user):
    """Subscriptions management page"""
    return render_template('admin/subscription-management.html', user=user)

@admin_routes_bp.route('/reports')
@admin_required
def reports(user):
    """Reports dashboard page"""
    return render_template('admin/reports-dashboard.html', user=user)

@admin_routes_bp.route('/settings')
@admin_required
def settings(user):
    """Settings dashboard page"""
    return render_template('admin/settings-dashboard.html', user=user)

@admin_routes_bp.route('/scanners')
@admin_required
def scanners(user):
    """Scanner management page"""
    # In a real implementation, you'd retrieve data from the database
    return render_template(
        'admin/scanner-management.html',
        user=user,
        deployed_scanners={
            'scanners': [],
            'pagination': {
                'page': 1,
                'per_page': 10,
                'total_count': 0,
                'total_pages': 1
            }
        },
        filters={}
    )"""
    
    with open('admin_routes.py', 'w') as f:
        f.write(content)
    
    logger.info("Created admin_routes.py")
    return True

def create_fix_app():
    """Create a script to modify app.py to register the admin_routes blueprint"""
    content = """# fix_app.py
# This script modifies app.py to register the admin_routes blueprint

import os
import re
import logging

logger = logging.getLogger(__name__)

def fix_app():
    """Modify app.py to register the admin_routes blueprint"""
    try:
        # Make sure admin_routes.py exists
        if not os.path.exists('admin_routes.py'):
            logger.error("admin_routes.py does not exist")
            return False
        
        # Read app.py
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Create a backup
        with open('app.py.bak', 'w') as f:
            f.write(content)
        
        # Check if the admin_routes blueprint is already imported
        if 'from admin_routes import admin_routes_bp' in content:
            logger.info("admin_routes_bp is already imported in app.py")
            
            # Check if it's registered
            if 'app.register_blueprint(admin_routes_bp)' in content:
                logger.info("admin_routes_bp is already registered in app.py")
                return True
        
        # Find where blueprints are registered
        blueprint_patterns = [
            r'app\.register_blueprint\(admin_bp\)',
            r'app\.register_blueprint\(auth_bp\)',
            r'app\.register_blueprint\(client_bp\)',
            r'app\.register_blueprint\(api_bp\)'
        ]
        
        # Find the last blueprint registration
        last_position = -1
        for pattern in blueprint_patterns:
            match = re.search(pattern, content)
            if match and match.end() > last_position:
                last_position = match.end()
        
        if last_position == -1:
            # Fallback - try to find the end of app initialization
            match = re.search(r'app = Flask\(__name__\)', content)
            if match:
                last_position = match.end()
        
        if last_position == -1:
            logger.error("Could not find a good place to insert the blueprint registration")
            return False
        
        # Add the import and registration
        import_code = '''

# Import admin routes for missing pages
try:
    from admin_routes import admin_routes_bp
    app.register_blueprint(admin_routes_bp)
    print("Registered admin_routes_bp")
except ImportError:
    print("Could not import admin_routes - missing pages will not be available")
except Exception as e:
    print(f"Error registering admin_routes: {e}")
'''
        
        # Insert after the last blueprint registration
        new_content = content[:last_position] + import_code + content[last_position:]
        
        # Write the modified file
        with open('app.py', 'w') as f:
            f.write(new_content)
        
        logger.info("Successfully modified app.py to register admin_routes_bp")
        return True
    
    except Exception as e:
        logger.error(f"Error modifying app.py: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    # Run all fixes
    print("Creating admin templates...")
    templates_result = create_templates()
    print(f"Templates created: {templates_result}")
    
    print("\nCreating admin routes...")
    routes_result = create_admin_routes()
    print(f"Admin routes created: {routes_result}")
    
    print("\nCreating fix app script...")
    fix_app_result = create_fix_app()
    print(f"Fix app script created: {fix_app_result}")
    
    # Run the fix_app script if it was created successfully
    if fix_app_result:
        print("\nFixing app.py...")
        import fix_app
        app_result = fix_app.fix_app()
        print(f"App fixed: {app_result}")
    
    print("\nFix installation complete!")
