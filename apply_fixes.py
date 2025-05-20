#!/usr/bin/env python3
# apply_fixes.py - Script to fix common issues in CybrScan application

import os
import sys
import logging
import importlib
import traceback
import sqlite3
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DB_PATH = os.path.join(BASE_DIR, 'client_scanner.db')

def fix_migrations():
    """Fix the migration issue with duplicate full_name column"""
    try:
        # Import the migrations module
        sys.path.append(BASE_DIR)
        from migrations import fix_users_table
        
        # Run the fix
        result = fix_users_table()
        
        if result:
            logger.info("Fixed migration for users table successfully")
        else:
            logger.error("Failed to fix migration for users table")
        
        return result
    except Exception as e:
        logger.error(f"Error fixing migrations: {e}")
        logger.error(traceback.format_exc())
        return False

def register_admin_fix_route(app):
    """Register the admin fix route with the app"""
    try:
        # Try to import from admin_web_fix.py
        from admin_web_fix import add_admin_fix_route
        
        # Apply the fix
        app = add_admin_fix_route(app)
        logger.info("Admin fix route added successfully")
        return True
    except ImportError:
        logger.warning("admin_web_fix module not found, trying admin_fix_page...")
        
        try:
            # Try to import from admin_fix_page.py
            from admin_fix_page import add_admin_fix_route
            
            # Apply the fix
            app = add_admin_fix_route(app)
            logger.info("Admin fix route added from admin_fix_page")
            return True
        except ImportError:
            logger.error("Could not find add_admin_fix_route function in any module")
            return False
    except Exception as e:
        logger.error(f"Error adding admin fix route: {e}")
        logger.error(traceback.format_exc())
        return False

def import_admin_required(app):
    """Import and register the admin_required decorator"""
    try:
        # Try to import from auth_routes.py
        from auth_routes import admin_required
        
        # Make it available globally
        globals()['admin_required'] = admin_required
        
        logger.info("admin_required decorator imported successfully")
        return True
    except ImportError:
        logger.warning("Could not import admin_required from auth_routes, trying auth_decorators...")
        
        try:
            # Try to create a minimal implementation
            from auth_decorators import admin_required
            globals()['admin_required'] = admin_required
            
            logger.info("admin_required decorator imported from auth_decorators")
            return True
        except ImportError:
            logger.error("Could not find admin_required decorator in any module")
            return False
    except Exception as e:
        logger.error(f"Error importing admin_required: {e}")
        logger.error(traceback.format_exc())
        return False

def fix_route_conflicts(app):
    """Fix route conflicts by applying auth_fix and blueprint_conflict_fix"""
    try:
        # Try to import and apply auth_fix
        from auth_fix import fix_auth_routes
        
        # Apply the fix
        result = fix_auth_routes(app)
        
        if result:
            logger.info("Auth routes fixed successfully")
        else:
            logger.warning("Failed to fix auth routes")
        
        # Try to import and apply blueprint_conflict_fix
        try:
            from blueprint_conflict_fix import resolve_route_conflicts
            
            # Apply the fix
            app = resolve_route_conflicts(app)
            logger.info("Route conflicts resolved successfully")
        except ImportError:
            logger.warning("blueprint_conflict_fix module not found, skipping route conflict resolution")
        
        return True
    except ImportError:
        logger.warning("auth_fix module not found, skipping auth route fixes")
        return False
    except Exception as e:
        logger.error(f"Error fixing route conflicts: {e}")
        logger.error(traceback.format_exc())
        return False

def create_admin_user():
    """Create or reset admin user for emergency access"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        admin_exists = cursor.fetchone()[0] > 0
        
        import secrets
        import hashlib
        
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        if admin_exists:
            # Update existing admin user
            cursor.execute('''
            UPDATE users 
            SET password_hash = ?, salt = ?, role = 'admin', active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            
            logger.info("Reset admin user password")
        else:
            # Create new admin user
            cursor.execute('''
            INSERT INTO users (
                username, email, password_hash, salt, role, full_name, created_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', datetime.now().isoformat()))
            
            logger.info("Created new admin user")
        
        conn.commit()
        conn.close()
        
        print("✅ Admin user ready")
        print("  Username: admin")
        print("  Password: admin123")
        
        return True
    except Exception as e:
        logger.error(f"Error creating/updating admin user: {e}")
        logger.error(traceback.format_exc())
        return False

def apply_all_fixes(app=None):
    """Apply all fixes to the application"""
    results = {
        'migrations': False,
        'admin_fix_route': False,
        'admin_required': False,
        'route_conflicts': False,
        'admin_user': False
    }
    
    # Fix migrations
    results['migrations'] = fix_migrations()
    
    # Fix admin_fix_route if app is provided
    if app:
        results['admin_fix_route'] = register_admin_fix_route(app)
        results['admin_required'] = import_admin_required(app)
        results['route_conflicts'] = fix_route_conflicts(app)
    
    # Create/reset admin user
    results['admin_user'] = create_admin_user()
    
    return results

def main():
    """Main function - can be called directly or imported"""
    print("=" * 60)
    print("CybrScan Application Fix Utility")
    print("=" * 60)
    
    # Try to import Flask app
    app = None
    try:
        sys.path.append(BASE_DIR)
        from app import app
        logger.info("Successfully imported Flask app")
    except ImportError:
        logger.warning("Could not import app from app.py - some fixes will be skipped")
    
    # Apply fixes
    results = apply_all_fixes(app)
    
    # Print results
    print("\nFix Results:")
    print(f"Database Migrations: {'✅ Fixed' if results['migrations'] else '❌ Failed'}")
    print(f"Admin Fix Route: {'✅ Fixed' if results['admin_fix_route'] else '❌ Failed or Skipped'}")
    print(f"Admin Required Decorator: {'✅ Fixed' if results['admin_required'] else '❌ Failed or Skipped'}")
    print(f"Route Conflicts: {'✅ Fixed' if results['route_conflicts'] else '❌ Failed or Skipped'}")
    print(f"Admin User: {'✅ Fixed' if results['admin_user'] else '❌ Failed'}")
    
    # Success criteria - migrations and admin user must be fixed
    if results['migrations'] and results['admin_user']:
        print("\n✅ Critical fixes applied successfully!")
        if not all([results['admin_fix_route'], results['admin_required'], results['route_conflicts']]):
            print("⚠️ Some non-critical fixes could not be applied.")
            print("   You may need to restart the application or apply them manually.")
        return 0
    else:
        print("\n⚠️ Some critical fixes could not be applied. Check the log for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
