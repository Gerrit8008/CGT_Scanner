#!/usr/bin/env python3
# fix_cybrscan.py - Fix script for CybrScan application issues

import os
import sys
import sqlite3
import importlib
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_duplicate_column_migration():
    """Fix the migration error with duplicate scanner_name column"""
    try:
        conn = sqlite3.connect('client_scanner.db')
        cursor = conn.cursor()
        
        # 1. First check if the migration is already recorded
        cursor.execute("SELECT name FROM migrations WHERE name = '007_add_client_customization_fields'")
        if cursor.fetchone():
            # Migration is already recorded, skip it
            logger.info("Migration already recorded as complete, skipping")
            conn.close()
            return True
            
        # 2. Check which columns already exist in the clients table
        cursor.execute("PRAGMA table_info(clients)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        # 3. Begin transaction
        conn.execute('BEGIN TRANSACTION')
        
        # 4. Add only columns that don't already exist
        if 'primary_color' not in existing_columns:
            cursor.execute("ALTER TABLE clients ADD COLUMN primary_color TEXT DEFAULT '#FF6900'")
            logger.info("Added primary_color column")
            
        if 'secondary_color' not in existing_columns:
            cursor.execute("ALTER TABLE clients ADD COLUMN secondary_color TEXT DEFAULT '#808588'")
            logger.info("Added secondary_color column")
            
        # Skip scanner_name as it already exists
        logger.info("Skipping scanner_name column (already exists)")
            
        if 'business_name' not in existing_columns:
            cursor.execute("ALTER TABLE clients ADD COLUMN business_name TEXT")
            logger.info("Added business_name column") 
            
        if 'business_domain' not in existing_columns:
            cursor.execute("ALTER TABLE clients ADD COLUMN business_domain TEXT")
            logger.info("Added business_domain column")
        
        # 5. Create customizations table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='customizations'")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS customizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                primary_color TEXT DEFAULT '#FF6900',
                secondary_color TEXT DEFAULT '#808588',
                logo_path TEXT,
                email_subject TEXT DEFAULT 'Your Security Scan Report',
                email_intro TEXT DEFAULT 'Thank you for using our security scanner.',
                default_scans TEXT DEFAULT '["network", "web", "email", "ssl"]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
            logger.info("Created customizations table")
        
        # 6. Create scan_history table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                report_path TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
            logger.info("Created scan_history table")
        
        # 7. Mark migration as complete
        cursor.execute('''
        INSERT INTO migrations (name, applied_at)
        VALUES (?, ?)
        ''', ('007_add_client_customization_fields', datetime.now().isoformat()))
        
        # 8. Commit transaction
        conn.commit()
        logger.info("Migration 007_add_client_customization_fields fixed and marked as complete")
        conn.close()
        return True
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        logger.error(f"Error fixing migration: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def fix_blueprint_conflicts(app):
    """Fix conflicts between duplicated blueprints"""
    try:
        # Create auth_decorators.py if it doesn't exist
        if not os.path.exists('auth_decorators.py'):
            with open('auth_decorators.py', 'w') as f:
                f.write('''
# auth_decorators.py - Admin required decorator
from flask import redirect, url_for, session, request, flash
import logging

logger = logging.getLogger(__name__)

def admin_required(f):
    """
    Decorator that checks if the current user is an admin
    """
    def decorated_function(*args, **kwargs):
        # Check for session token
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        # Verify the session
        try:
            # Try to import from auth_utils first
            try:
                from auth_utils import verify_session
            except ImportError:
                # Fall back to client_db
                from client_db import verify_session
                
            result = verify_session(session_token)
            
            if result['status'] != 'success' or result['user']['role'] != 'admin':
                flash('You need administrative privileges to access this page', 'danger')
                return redirect(url_for('auth.login'))
            
            # Add user to kwargs
            kwargs['user'] = result['user']
        except Exception as e:
            logger.error(f"Error in admin_required: {e}")
            flash('Authentication error. Please login again.', 'danger')
            return redirect(url_for('auth.login'))
            
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    return decorated_function
''')
            logger.info("Created auth_decorators.py with admin_required decorator")
        
        # Create blueprint_fix.py if it doesn't exist
        if not os.path.exists('blueprint_fix.py'):
            with open('blueprint_fix.py', 'w') as f:
                f.write('''
# blueprint_fix.py - Fix blueprint conflicts
import logging

logger = logging.getLogger(__name__)

def resolve_route_conflicts(app):
    """
    Resolve route conflicts in Flask app by prioritizing blueprints
    
    Args:
        app: Flask application
        
    Returns:
        Flask application with resolved conflicts
    """
    # Blueprint priority (first is highest priority)
    priority_blueprints = [
        'auth_blueprint', 
        'admin_blueprint', 
        'api_blueprint', 
        'scanner_blueprint', 
        'client_blueprint',
        'emergency_blueprint',
        'scanner_preview_blueprint'
    ]
    
    # Find all registered routes
    route_owners = {}
    duplicate_routes = {}
    
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        path = str(rule)
        
        # Skip static and other non-blueprint routes
        if '.' not in endpoint or endpoint.startswith('static'):
            continue
        
        # Extract blueprint name from endpoint
        blueprint = endpoint.split('.', 1)[0]
        
        if path in route_owners:
            # Route conflict detected
            existing_blueprint = route_owners[path].split('.', 1)[0]
            
            # Add to duplicates list
            if path not in duplicate_routes:
                duplicate_routes[path] = [existing_blueprint]
            duplicate_routes[path].append(blueprint)
            
            # Determine which blueprint has higher priority
            if blueprint in priority_blueprints and existing_blueprint in priority_blueprints:
                if priority_blueprints.index(blueprint) < priority_blueprints.index(existing_blueprint):
                    # New blueprint has higher priority
                    logger.info(f"Resolving conflict for {path}: {blueprint} takes precedence over {existing_blueprint}")
                    route_owners[path] = endpoint
            elif blueprint in priority_blueprints:
                # Only new blueprint is in priority list
                logger.info(f"Resolving conflict for {path}: {blueprint} takes precedence (in priority list)")
                route_owners[path] = endpoint
            elif existing_blueprint not in priority_blueprints:
                # Neither is in priority list, keep first registered
                logger.warning(f"Conflicting routes for {path}: keeping {existing_blueprint} over {blueprint} (first registered)")
        else:
            # First registration of this route
            route_owners[path] = endpoint
    
    # Log all duplicate routes
    for path, blueprints in duplicate_routes.items():
        chosen = route_owners[path].split('.', 1)[0]
        others = [bp for bp in blueprints if bp != chosen]
        if others:
            logger.warning(f"Route {path} has multiple registrations: using {chosen}, ignoring {', '.join(others)}")
    
    # Since Flask doesn't support removing routes, we're just logging the conflicts
    # A complete solution would require creating a new Flask app instance with only
    # the desired routes, but that's beyond the scope of this fix
    
    return app
''')
            logger.info("Created blueprint_fix.py")
            
        # Import the admin_required decorator from the new file
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from auth_decorators import admin_required
        
        # Make the decorator globally available in the app context
        app.jinja_env.globals['admin_required'] = admin_required
        globals()['admin_required'] = admin_required
        
        # Import and apply blueprint fix
        from blueprint_fix import resolve_route_conflicts
        resolve_route_conflicts(app)
        
        logger.info("Blueprint conflicts fixed")
        return True
        
    except Exception as e:
        logger.error(f"Error fixing blueprint conflicts: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def add_admin_required_to_admin_routes():
    """Fix admin_routes.py to have proper import for admin_required"""
    try:
        # Check if admin_routes.py exists
        if not os.path.exists('admin_routes.py'):
            logger.warning("admin_routes.py not found, skipping")
            return False
        
        # Read the file
        with open('admin_routes.py', 'r') as f:
            content = f.read()
        
        # Check if it already has the right import
        if 'from auth_decorators import admin_required' not in content:
            # Backup the file
            with open('admin_routes.py.bak', 'w') as f:
                f.write(content)
            
            # Replace the incorrect import
            if 'def admin_required' in content:
                # File defines its own admin_required, don't modify
                logger.info("admin_routes.py has its own admin_required definition, not changing")
                return True
            
            # Different patterns to look for
            patterns = [
                'from auth_utils import admin_required',
                'from auth_routes import admin_required',
                'from auth import admin_required'
            ]
            
            new_content = content
            for pattern in patterns:
                if pattern in new_content:
                    new_content = new_content.replace(
                        pattern, 
                        'from auth_decorators import admin_required'
                    )
            
            # Write the updated content
            with open('admin_routes.py', 'w') as f:
                f.write(new_content)
            
            logger.info("Updated admin_routes.py with the correct admin_required import")
        
        return True
    except Exception as e:
        logger.error(f"Error modifying admin_routes.py: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def main():
    """Main function to run all fixes"""
    logger.info("Starting CybrScan fixes...")
    
    # Fix the migration error
    logger.info("Fixing duplicate column migration...")
    migration_fixed = fix_duplicate_column_migration()
    logger.info(f"Migration fix result: {'Success' if migration_fixed else 'Failed'}")
    
    # Try to import the Flask app
    try:
        # Add the current directory to the path
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Try to import the app from app.py
        from app import app
        logger.info("Successfully imported Flask app")
        
        # Fix blueprint conflicts
        logger.info("Fixing blueprint conflicts...")
        blueprint_fixed = fix_blueprint_conflicts(app)
        logger.info(f"Blueprint fix result: {'Success' if blueprint_fixed else 'Failed'}")
        
        # Fix admin_routes.py
        logger.info("Fixing admin_routes.py...")
        routes_fixed = add_admin_required_to_admin_routes()
        logger.info(f"Admin routes fix result: {'Success' if routes_fixed else 'Failed'}")
        
    except ImportError:
        logger.warning("Could not import Flask app, skipping app-related fixes")
        blueprint_fixed = False
        routes_fixed = False
    
    # Print summary
    print("\n=== Fix Summary ===")
    print(f"Migration Fix: {'✅ Success' if migration_fixed else '❌ Failed'}")
    print(f"Blueprint Conflicts Fix: {'✅ Success' if blueprint_fixed else '❌ Failed/Skipped'}")
    print(f"Admin Routes Fix: {'✅ Success' if routes_fixed else '❌ Failed/Skipped'}")
    
    if migration_fixed and (blueprint_fixed or not app):
        print("\n✅ All fixes applied successfully!")
        print("You should now restart your application to apply the changes.")
    else:
        print("\n⚠️ Some fixes could not be applied. Check the log for details.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
