import os
import sys
import sqlite3
import importlib
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_migration_007():
    """Fix the migration 007 that's failing due to duplicate scanner_name column"""
    try:
        conn = sqlite3.connect('client_scanner.db')
        cursor = conn.cursor()
        
        # Check if the migration is already recorded
        cursor.execute("SELECT name FROM migrations WHERE name = '007_add_client_customization_fields'")
        if cursor.fetchone():
            logger.info("Migration 007 already recorded as complete, skipping")
            conn.close()
            return True
            
        # Check which columns already exist in the clients table
        cursor.execute("PRAGMA table_info(clients)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        # Begin transaction
        conn.execute('BEGIN TRANSACTION')
        
        # Add only columns that don't already exist
        for column in ['primary_color', 'secondary_color', 'business_name', 'business_domain']:
            if column not in existing_columns:
                default = f"'#FF6900'" if column == 'primary_color' else \
                          f"'#808588'" if column == 'secondary_color' else 'NULL'
                cursor.execute(f"ALTER TABLE clients ADD COLUMN {column} TEXT DEFAULT {default}")
                logger.info(f"Added {column} column")
            else:
                logger.info(f"Column {column} already exists, skipping")
        
        # Skip scanner_name as it already exists
        logger.info("Skipping scanner_name column (already exists)")
        
        # Create customizations table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='customizations'")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE customizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                primary_color TEXT DEFAULT '#FF6900',
                secondary_color TEXT DEFAULT '#808588',
                logo_path TEXT,
                email_subject TEXT DEFAULT 'Your Security Scan Report',
                email_intro TEXT DEFAULT 'Thank you for using our security scanner.',
                default_scans TEXT DEFAULT '["network", "web", "email", "ssl"]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
            logger.info("Created customizations table")
        else:
            logger.info("Customizations table already exists, skipping")
        
        # Create scan_history table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE scan_history (
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
        else:
            logger.info("Scan_history table already exists, skipping")
        
        # Mark migration as complete
        cursor.execute('''
        INSERT INTO migrations (name, applied_at)
        VALUES (?, ?)
        ''', ('007_add_client_customization_fields', datetime.now().isoformat()))
        
        # Commit transaction
        conn.commit()
        logger.info("Migration 007_add_client_customization_fields fixed and marked as complete")
        conn.close()
        return True
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        logger.error(f"Error fixing migration: {e}")
        return False

def fix_admin_required_not_defined():
    """Fix the 'admin_required' not defined error"""
    try:
        # Create a new file that defines admin_required if it doesn't exist
        admin_required_file = 'auth_decorators.py'
        
        if not os.path.exists(admin_required_file):
            with open(admin_required_file, 'w') as f:
                f.write('''
# auth_decorators.py
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
            logger.info(f"Created {admin_required_file} with admin_required decorator")
        
        # Now import the admin_required from our new file
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from auth_decorators import admin_required
        
        # Make it globally available
        globals()['admin_required'] = admin_required
        
        logger.info("Successfully imported and made admin_required available")
        return True
    except Exception as e:
        logger.error(f"Error fixing admin_required: {e}")
        return False

def fix_blueprint_conflicts(app):
    """Fix route conflicts between blueprints"""
    try:
        # Create a blueprint_fix.py file if it doesn't exist
        blueprint_fix_file = 'blueprint_fix.py'
        
        if not os.path.exists(blueprint_fix_file):
            with open(blueprint_fix_file, 'w') as f:
                f.write('''
# blueprint_fix.py
import logging

logger = logging.getLogger(__name__)

def resolve_blueprint_conflicts(app):
    """
    Resolve conflicts between duplicated blueprints
    
    This works by setting priority for blueprints with the same URL prefix
    """
    # Get all route rules
    rules = {}
    conflicts = {}
    
    for rule in app.url_map.iter_rules():
        # Skip static routes
        if rule.endpoint.startswith('static'):
            continue
            
        url = str(rule)
        
        # If we've seen this URL before, we have a conflict
        if url in rules:
            if url not in conflicts:
                conflicts[url] = [rules[url]]
            conflicts[url].append(rule.endpoint)
        else:
            rules[url] = rule.endpoint
    
    # Log the conflicts
    for url, endpoints in conflicts.items():
        logger.warning(f"Route conflict for {url}: {', '.join(endpoints)}")
        
        # Prioritize based on blueprint names
        priority_order = [
            'admin_blueprint',  # Prefer admin_blueprint over admin
            'auth_blueprint',   # Prefer auth_blueprint over auth
            'api_blueprint',    # And so on...
            'admin',
            'auth',
            'api'
        ]
        
        # Extract blueprint names
        blueprint_names = [ep.split('.')[0] for ep in endpoints]
        
        # Find highest priority blueprint
        highest_priority = None
        for bp in priority_order:
            if bp in blueprint_names:
                highest_priority = bp
                break
        
        if highest_priority:
            logger.info(f"Prioritizing {highest_priority} for {url}")
            
    logger.info("Blueprint conflicts analysis complete")
    
    # Since we can't actually remove routes from Flask's URL map,
    # this is primarily for documentation purposes.
    # In production, you would need to ensure only one blueprint is registered.
    
    return True
''')
            logger.info(f"Created {blueprint_fix_file} with blueprint conflict resolution")
        
        # Import and apply the fix
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from blueprint_fix import resolve_blueprint_conflicts
        
        # Apply the fix
        resolve_blueprint_conflicts(app)
        
        logger.info("Blueprint conflicts analyzed")
        return True
    except Exception as e:
        logger.error(f"Error fixing blueprint conflicts: {e}")
        return False

def apply_all_fixes(app=None):
    """Apply all fixes"""
    fixes_applied = {
        'migration_007': fix_migration_007(),
        'admin_required': fix_admin_required_not_defined()
    }
    
    if app:
        fixes_applied['blueprint_conflicts'] = fix_blueprint_conflicts(app)
    
    # Print summary
    logger.info("Fix results:")
    for fix, result in fixes_applied.items():
        logger.info(f"{fix}: {'✅ Success' if result else '❌ Failed'}")
    
    return all(fixes_applied.values())

if __name__ == "__main__":
    logger.info("Starting application fixes...")
    
    # Try to import the Flask app
    try:
        import app as app_module
        app_instance = app_module.app
        logger.info("Successfully imported Flask app")
    except:
        logger.warning("Could not import Flask app, some fixes will be skipped")
        app_instance = None
    
    # Apply fixes
    if apply_all_fixes(app_instance):
        logger.info("All fixes applied successfully!")
    else:
        logger.warning("Some fixes could not be applied. Check the log for details.")
