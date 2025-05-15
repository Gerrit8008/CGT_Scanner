
import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_app_py():
    """Fix the app.py file by adding missing functions"""
    try:
        # Read the current app.py file
        with open('app.py', 'r') as f:
            content = f.read()
        
        # Check if add_admin_fix_route is already defined
        if 'def add_admin_fix_route(' in content:
            logger.info("add_admin_fix_route already defined")
            return True
        
        # Find the location to insert the function
        # Insert before the first occurrence of apply_admin_fixes
        insert_location = content.find('apply_admin_fixes(app)')
        
        if insert_location == -1:
            logger.error("Could not find apply_admin_fixes call in app.py")
            return False
        
        # Define the function to insert
        function_to_insert = '''
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

'''
        
        # Insert the function at the appropriate location
        new_content = content[:insert_location] + function_to_insert + content[insert_location:]
        
        # Create a backup of the original file
        with open('app.py.backup', 'w') as f:
            f.write(content)
        
        # Write the new content
        with open('app.py', 'w') as f:
            f.write(new_content)
        
        logger.info("Successfully added add_admin_fix_route function to app.py")
        logger.info("Backup created as app.py.backup")
        return True
        
    except Exception as e:
        logger.error(f"Error fixing app.py: {e}")
        return False

def create_admin_route_fix_module():
    """Create a separate module for admin route fixes"""
    try:
        admin_fix_content = '''# admin_route_fix.py
# Module containing admin route fixes

from flask import Flask, jsonify
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

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

def apply_admin_fixes(app):
    """Apply all admin fixes"""
    try:
        # Add the missing route
        add_admin_fix_route(app)
        
        # Add other fixes as needed
        logger.info("Admin fixes applied successfully")
        return True
    except Exception as e:
        logger.error(f"Error applying admin fixes: {e}")
        return False
'''
        
        with open('admin_route_fix.py', 'w') as f:
            f.write(admin_fix_content)
        
        logger.info("Created admin_route_fix.py module")
        return True
        
    except Exception as e:
        logger.error(f"Error creating admin route fix module: {e}")
        return False

def main():
    """Main function to run the fixes"""
    logger.info("Starting admin route fixes...")
    
    # Option 1: Try to fix app.py directly
    if fix_app_py():
        logger.info("✅ Fixed app.py directly")
    else:
        logger.warning("❌ Could not fix app.py directly")
    
    # Option 2: Create a separate module
    if create_admin_route_fix_module():
        logger.info("✅ Created admin_route_fix module")
        logger.info("You can now import from admin_route_fix in your app.py:")
        logger.info("  from admin_route_fix import apply_admin_fixes, add_admin_fix_route")
    else:
        logger.warning("❌ Could not create admin route fix module")
    
    logger.info("Admin route fixes completed!")

if __name__ == "__main__":
    main()
