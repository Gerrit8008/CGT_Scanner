#!/usr/bin/env python3
"""
Auto-fix script for app.py
This script will automatically fix the issues in your app.py file
"""

import re
import os
import shutil
from datetime import datetime

def create_backup(file_path):
    """Create a backup of the file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{file_path}.backup_{timestamp}"
    shutil.copy2(file_path, backup_path)
    print(f"✅ Created backup: {backup_path}")
    return backup_path

def read_file(file_path):
    """Read the contents of a file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(file_path, content):
    """Write content to a file"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def fix_function_definitions(content):
    """Add missing function definitions at the beginning of the file"""
    # Define the functions to add
    functions_to_add = '''
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
    """Apply fixes to admin functionality"""
    try:
        # Add the missing admin fix route
        add_admin_fix_route(app)
        
        # Add any other admin fixes here
        logger.info("Admin fixes applied successfully")
        return True
    except Exception as e:
        logger.error(f"Error applying admin fixes: {e}")
        return False

'''
    
    # Find where to insert (after import statements but before other code)
    insert_position = content.find('# Setup logging')
    if insert_position == -1:
        insert_position = content.find('def setup_logging():')
    
    if insert_position != -1:
        content = content[:insert_position] + functions_to_add + content[insert_position:]
    
    return content

def fix_admin_fixes_call(content):
    """Fix the apply_admin_fixes call"""
    # Find and replace the problematic section
    old_pattern = r'try:\s*apply_admin_fixes\(app\)\s*add_admin_fix_route\(app\)\s*logging\.info\("Fixes applied successfully"\)'
    new_code = '''try:
    # Apply admin fixes (this will call add_admin_fix_route internally)
    apply_admin_fixes(app)
    logging.info("Fixes applied successfully")'''
    
    content = re.sub(old_pattern, new_code, content, flags=re.DOTALL)
    return content

def fix_blueprint_registration(content):
    """Fix blueprint registration to avoid duplicates"""
    blueprint_section = '''try:
    register_debug_middleware(app)
    
    # Check if blueprints are already registered before registering them
    if 'auth' not in app.blueprints:
        app.register_blueprint(auth_bp)
    else:
        logging.warning("auth blueprint already registered, skipping")
        
    if 'admin' not in app.blueprints:
        app.register_blueprint(admin_bp)
    else:
        logging.warning("admin blueprint already registered, skipping")
        
    if 'api' not in app.blueprints:
        app.register_blueprint(api_bp)
    else:
        logging.warning("api blueprint already registered, skipping")
        
    if 'scanner' not in app.blueprints:
        app.register_blueprint(scanner_bp)
    else:
        logging.warning("scanner blueprint already registered, skipping")
        
    if 'client' not in app.blueprints:
        app.register_blueprint(client_bp)
    else:
        logging.warning("client blueprint already registered, skipping")
        
    if 'emergency' not in app.blueprints:
        app.register_blueprint(emergency_bp)
    else:
        logging.warning("emergency blueprint already registered, skipping")
        
    if 'scanner_preview' not in app.blueprints:
        app.register_blueprint(scanner_preview_bp, url_prefix='/preview')
    else:
        logging.warning("scanner_preview blueprint already registered, skipping")
        
    logging.info(f"Blueprints registered successfully at {CURRENT_UTC_TIME} by {CURRENT_USER}")
except Exception as blueprint_error:
    logging.error(f"Error registering blueprints: {blueprint_error}")
    logging.debug(f"Exception traceback: {traceback.format_exc()}")'''
    
    # Find the original blueprint registration section
    pattern = r'try:\s*register_debug_middleware\(app\)\s*app\.register_blueprint\(auth_bp\).*?logging\.debug\(f"Exception traceback: {traceback\.format_exc\(\)}"\)'
    content = re.sub(pattern, blueprint_section, content, flags=re.DOTALL)
    
    return content

def fix_route_conflicts(content):
    """Fix route conflicts by renaming duplicate routes"""
    # Fix the duplicate /admin route
    pattern = r"@app\.route\('/admin', endpoint='main_admin_redirect'\)"
    replacement = "@app.route('/admin_main', endpoint='main_admin_redirect')"
    content = re.sub(pattern, replacement, content)
    
    return content

def fix_main_execution(content):
    """Clean up and fix the main execution section"""
    # Remove everything after the last proper function definition and add clean main section
    # Find the last proper function definition
    last_function_match = None
    for match in re.finditer(r'^def [a-zA-Z_][a-zA-Z0-9_]*\(.*?\):', content, re.MULTILINE):
        if 'if __name__ ==' not in content[match.start():match.start()+200]:
            last_function_match = match
    
    if last_function_match:
        # Find the end of the last function
        function_end = last_function_match.end()
        brace_count = 0
        in_function = True
        i = function_end
        
        while i < len(content) and in_function:
            if content[i] == '\n':
                # Check if next line is at the same indentation level or less
                j = i + 1
                while j < len(content) and content[j] in ' \t':
                    j += 1
                if j < len(content) and content[j] != '\n':
                    if j == i + 1 or (j > i + 1 and content[i+1:j].count(' ') == 0):
                        in_function = False
                        function_end = i
            i += 1
        
        # Clean main execution section
        main_section = '''
def apply_route_fixes():
    """Apply all route fixes"""
    try:
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
            
            cursor.execute(\'\'\'
                INSERT INTO users (username, email, password_hash, salt, role, full_name, created_at, active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            \'\'\', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Admin User', datetime.now().isoformat()))
            
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

# Main execution block
if __name__ == '__main__':
    # Log startup information
    logging.info("Starting application...")
    logging.info(f"Application startup time: {datetime.now().isoformat()}")
    
    # Run database schema upgrade
    try:
        if upgrade_database_schema():
            logging.info("Database schema upgraded successfully")
        else:
            logging.error("Failed to upgrade database schema")
    except Exception as schema_error:
        logging.error(f"Schema upgrade error: {schema_error}")
    
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # Run the direct database fix
    try:
        if direct_db_fix():
            logging.info("Database fix completed successfully")
        else:
            logging.warning("Database fix may have failed")
    except Exception as db_fix_error:
        logging.error(f"Database fix error: {db_fix_error}")
    
    # Apply route fixes if needed
    try:
        if apply_route_fixes():
            logging.info("Route fixes applied successfully")
        else:
            logging.warning("Some route fixes may have failed")
    except Exception as route_fix_error:
        logging.error(f"Route fix error: {route_fix_error}")
    
    # Apply admin fixes
    try:
        if apply_admin_fixes(app):
            logging.info("Admin fixes applied successfully")
        else:
            logging.warning("Admin fixes may have failed")
    except Exception as admin_fix_error:
        logging.error(f"Admin fix error: {admin_fix_error}")
    
    # Final pre-run checks
    try:
        logging.info("Performing final pre-run checks...")
        
        # Check if Flask app is properly initialized
        if app is None:
            logging.error("Flask app is not initialized!")
            sys.exit(1)
        else:
            logging.info(f"Flask app initialized: {type(app)}")
        
        # Log registered blueprints
        blueprints = list(app.blueprints.keys())
        logging.info(f"Registered blueprints: {blueprints}")
        
        # Log route count
        route_count = len(list(app.url_map.iter_rules()))
        logging.info(f"Total registered routes: {route_count}")
        
    except Exception as check_error:
        logging.error(f"Pre-run check error: {check_error}")
    
    # Start the Flask application
    try:
        logging.info(f"Starting Flask server on {host}:{port} (debug={debug_mode})...")
        app.run(host=host, port=port, debug=debug_mode)
    except Exception as run_error:
        logging.error(f"Failed to start Flask server: {run_error}")
        sys.exit(1)
'''
        
        content = content[:function_end] + main_section
    
    return content

def main():
    """Main function to apply all fixes"""
    file_path = 'app.py'
    
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found!")
        return
    
    print(f"🔧 Fixing {file_path}...")
    
    # Create backup
    backup_path = create_backup(file_path)
    
    # Read file
    content = read_file(file_path)
    
    # Apply fixes
    print("📝 Adding missing function definitions...")
    content = fix_function_definitions(content)
    
    print("🔄 Fixing admin fixes call...")
    content = fix_admin_fixes_call(content)
    
    print("📦 Fixing blueprint registration...")
    content = fix_blueprint_registration(content)
    
    print("🚫 Fixing route conflicts...")
    content = fix_route_conflicts(content)
    
    print("⚙️ Fixing main execution section...")
    content = fix_main_execution(content)
    
    # Write fixed content
    write_file(file_path, content)
    
    print(f"✅ Fixed {file_path}")
    print(f"📄 Backup saved as: {backup_path}")
    print("\n🚀 You can now run your app with: python app.py")

if __name__ == '__main__':
    main()
