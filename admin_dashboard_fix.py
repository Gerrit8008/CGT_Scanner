# admin_dashboard_fix.py
import os
import sys
import re
import logging
import sqlite3
from datetime import datetime
import importlib.util

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def get_db_connection():
    """Get a connection to the client database"""
    CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')
    
    if os.path.exists(CLIENT_DB_PATH):
        return sqlite3.connect(CLIENT_DB_PATH)
    
    # Try to find the database in the current directory
    local_db = 'client_scanner.db'
    if os.path.exists(local_db):
        return sqlite3.connect(local_db)
    
    # Create database if it doesn't exist
    logger.warning(f"Database not found at {CLIENT_DB_PATH}, creating a new one")
    conn = sqlite3.connect(CLIENT_DB_PATH)
    return conn

def apply_dashboard_fix(admin_py_path='admin.py'):
    """Fix issues with the dashboard route in admin.py"""
    
    if not os.path.exists(admin_py_path):
        logger.error(f"admin.py not found at {admin_py_path}")
        return False
    
    try:
        # Read the admin.py file
        with open(admin_py_path, 'r') as f:
            content = f.read()
        
        # Create a backup of the original file
        backup_path = f"{admin_py_path}.bak"
        with open(backup_path, 'w') as f:
            f.write(content)
        logger.info(f"Created backup at {backup_path}")
        
        # Create fixed dashboard function
        fixed_dashboard = """@admin_bp.route('/dashboard')
@admin_required
def dashboard(user):
    """Admin dashboard with summary statistics"""
    try:
        # Connect to the database
        from client_db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get dashboard summary data with the cursor parameter
        from client_db import get_dashboard_summary
        summary = get_dashboard_summary(cursor)
        
        # Get recent clients with proper parameters
        from client_db import list_clients
        recent_clients_result = list_clients(cursor, page=1, per_page=5)
        if recent_clients_result and 'clients' in recent_clients_result:
            recent_clients = recent_clients_result['clients']
        else:
            # Handle the case where 'clients' key is missing
            recent_clients = []
        
        # Close the connection
        conn.close()
        
        # Render dashboard template
        return render_template(
            'admin/admin-dashboard.html',
            user=user,
            dashboard_stats=summary,
            recent_clients=recent_clients
        )
    except Exception as e:
        import traceback
        print(f"Error in dashboard: {e}")
        print(traceback.format_exc())
        # Return a simple error page
        return render_template(
            'admin/error.html',
            error=f"Error loading dashboard: {str(e)}"
        )"""
        
        # Replace the original dashboard function if it exists
        dashboard_pattern = r'@admin_bp\.route\([\'"]\/dashboard[\'"]\)[\s\S]*?def dashboard\([^)]*\):[\s\S]*?(?=@|\Z)'
        if re.search(dashboard_pattern, content):
            new_content = re.sub(dashboard_pattern, fixed_dashboard, content)
            with open(admin_py_path, 'w') as f:
                f.write(new_content)
            logger.info("Replaced existing dashboard function with fixed version")
        else:
            # Add the function if it doesn't exist
            with open(admin_py_path, 'a') as f:
                f.write("\n\n" + fixed_dashboard)
            logger.info("Added dashboard function since it wasn't found")
        
        return True
    except Exception as e:
        logger.error(f"Error applying dashboard fix: {e}")
        return False

def add_get_dashboard_summary(client_db_path='client_db.py'):
    """Add or update the get_dashboard_summary function in client_db.py"""
    
    if not os.path.exists(client_db_path):
        logger.error(f"client_db.py not found at {client_db_path}")
        return False
    
    try:
        # Read the client_db.py file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Create a backup of the original file
        backup_path = f"{client_db_path}.bak"
        with open(backup_path, 'w') as f:
            f.write(content)
        logger.info(f"Created backup at {backup_path}")
        
        # Define the new function
        dashboard_summary_func = """
def get_dashboard_summary(cursor=None):
    """Get summary statistics for the admin dashboard."""
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active scanners count (try/except in case table doesn't exist)
        try:
            cursor.execute("SELECT COUNT(*) FROM deployed_scanners WHERE deploy_status = 'deployed'")
            deployed_scanners = cursor.fetchone()[0]
        except:
            deployed_scanners = 0
        
        # Count scan history (active scans)
        try:
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            active_scans = cursor.fetchone()[0]
        except:
            active_scans = 0
        
        # Calculate monthly revenue (based on subscriptions)
        try:
            cursor.execute("SELECT COUNT(*), subscription_level FROM clients WHERE active = 1 GROUP BY subscription_level")
            subscription_counts = cursor.fetchall()
            
            # Define subscription prices
            subscription_prices = {'basic': 49, 'pro': 149, 'enterprise': 499}
            monthly_revenue = 0
            
            for count, level in subscription_counts:
                level = level.lower() if level else 'basic'
                price = subscription_prices.get(level, 0)
                monthly_revenue += count * price
        except:
            monthly_revenue = 0
        
        # Close connection if we created it
        if conn:
            conn.close()
        
        # Return the summary
        return {
            'total_clients': total_clients,
            'deployed_scanners': deployed_scanners,
            'active_scans': active_scans,
            'monthly_revenue': monthly_revenue
        }
    except Exception as e:
        import traceback
        print(f"Error in get_dashboard_summary: {e}")
        print(traceback.format_exc())
        
        # Return empty summary on error
        return {
            'total_clients': 0,
            'deployed_scanners': 0,
            'active_scans': 0,
            'monthly_revenue': 0
        }
"""
        
        # Check if the function already exists
        if 'def get_dashboard_summary' in content:
            # Replace the existing function
            dashboard_pattern = r'def get_dashboard_summary[^(]*\([^)]*\):[\s\S]*?(?=def|\Z)'
            new_content = re.sub(dashboard_pattern, dashboard_summary_func, content)
            with open(client_db_path, 'w') as f:
                f.write(new_content)
            logger.info("Replaced existing get_dashboard_summary function")
        else:
            # Add the function if it doesn't exist
            with open(client_db_path, 'a') as f:
                f.write("\n" + dashboard_summary_func)
            logger.info("Added get_dashboard_summary function")
        
        return True
    except Exception as e:
        logger.error(f"Error adding get_dashboard_summary: {e}")
        return False

def fix_list_clients(client_db_path='client_db.py'):
    """Add or update the list_clients function in client_db.py"""
    
    if not os.path.exists(client_db_path):
        logger.error(f"client_db.py not found at {client_db_path}")
        return False
    
    try:
        # Read the client_db.py file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Define the new function
        list_clients_func = """
def list_clients(cursor=None, page=1, per_page=10, filters=None):
    """List clients with pagination and filtering."""
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Default filters
        if filters is None:
            filters = {}
        
        # Build query
        query = "SELECT * FROM clients"
        params = []
        
        # Apply filters
        where_clauses = []
        
        if 'search' in filters and filters['search']:
            where_clauses.append("(business_name LIKE ? OR business_domain LIKE ? OR contact_email LIKE ?)")
            search_term = f"%{filters['search']}%"
            params.extend([search_term, search_term, search_term])
        
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append("subscription_level = ?")
            params.append(filters['subscription'])
        
        if 'active' in filters:
            where_clauses.append("active = ?")
            params.append(1 if filters['active'] else 0)
        
        # Add WHERE clause if needed
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        # Count total matching clients
        count_query = f"SELECT COUNT(*) FROM ({query})"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Add pagination
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        # Execute query
        cursor.execute(query, params)
        
        # Convert to list of dictionaries
        clients = []
        for row in cursor.fetchall():
            client = {}
            for idx, col in enumerate(cursor.description):
                client[col[0]] = row[idx]
            clients.append(client)
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page if per_page > 0 else 1
        
        # Close connection if we created it
        if conn:
            conn.close()
        
        # Return clients and pagination info
        return {
            'clients': clients,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        }
    except Exception as e:
        import traceback
        print(f"Error in list_clients: {e}")
        print(traceback.format_exc())
        
        # Return empty list on error
        return {
            'clients': [],
            'pagination': {
                'page': 1,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 1
            }
        }
"""
        
        # Check if the function already exists
        if 'def list_clients' in content:
            # Replace the existing function
            list_clients_pattern = r'def list_clients[^(]*\([^)]*\):[\s\S]*?(?=def|\Z)'
            new_content = re.sub(list_clients_pattern, list_clients_func, content)
            with open(client_db_path, 'w') as f:
                f.write(new_content)
            logger.info("Replaced existing list_clients function")
        else:
            # Add the function if it doesn't exist
            with open(client_db_path, 'a') as f:
                f.write("\n" + list_clients_func)
            logger.info("Added list_clients function")
        
        return True
    except Exception as e:
        logger.error(f"Error fixing list_clients function: {e}")
        return False

def create_missing_tables():
    """Create missing tables in the database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if clients table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
        if not cursor.fetchone():
            # Create clients table
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
                active INTEGER DEFAULT 1
            )
            ''')
            logger.info("Created clients table")
            
            # Insert example client
            cursor.execute('''
            INSERT INTO clients (
                business_name, business_domain, contact_email, contact_phone, 
                scanner_name, subscription_level, created_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'Example Company', 'example.com', 'admin@example.com',
                '555-123-4567', 'Security Scanner', 'basic',
                datetime.now().isoformat(), 1
            ))
            logger.info("Inserted example client")
        
        # Create deployed_scanners table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='deployed_scanners'")
        if not cursor.fetchone():
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS deployed_scanners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                subdomain TEXT UNIQUE,
                domain TEXT,
                deploy_status TEXT DEFAULT 'pending',
                deploy_date TEXT,
                last_updated TEXT,
                config_path TEXT,
                template_version TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
            logger.info("Created deployed_scanners table")
            
            # Get client id
            cursor.execute("SELECT id FROM clients LIMIT 1")
            client_id = cursor.fetchone()
            if client_id:
                # Insert example deployed scanner
                cursor.execute('''
                INSERT INTO deployed_scanners (
                    client_id, subdomain, domain, deploy_status, deploy_date
                ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    client_id[0], 'example', 'yourscannerdomain.com', 'deployed', 
                    datetime.now().isoformat()
                ))
                logger.info("Inserted example deployed scanner")
        
        # Create scan_history table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
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
            logger.info("Created scan_history table")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        return False

def fix_admin_routes(app):
    """Add missing admin routes"""
    try:
        # Import admin_route_fix.py or route_fix.py
        route_fix_path = 'route_fix.py'
        
        if os.path.exists(route_fix_path):
            # Load the module dynamically
            spec = importlib.util.spec_from_file_location("route_fix", route_fix_path)
            route_fix = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(route_fix)
            
            # Call fix_admin_routes function
            if hasattr(route_fix, 'fix_admin_routes'):
                route_fix.fix_admin_routes(app)
                logger.info("Applied admin routes fix")
                return True
            else:
                logger.error("route_fix.py doesn't contain fix_admin_routes function")
        else:
            # Create the route_fix.py file with the appropriate content
            from route_fix_content import get_route_fix_content
            
            with open(route_fix_path, 'w') as f:
                f.write(get_route_fix_content())
            
            # Load the new module
            spec = importlib.util.spec_from_file_location("route_fix", route_fix_path)
            route_fix = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(route_fix)
            
            # Call fix_admin_routes function
            route_fix.fix_admin_routes(app)
            logger.info("Created and applied admin routes fix")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error fixing admin routes: {e}")
        return False

def apply_all_fixes(app=None):
    """Apply all fixes"""
    results = {
        'dashboard_fix': False,
        'get_dashboard_summary': False,
        'list_clients': False,
        'tables': False,
        'routes': False
    }
    
    # Step 1: Fix dashboard function
    results['dashboard_fix'] = apply_dashboard_fix()
    
    # Step 2: Add/update get_dashboard_summary function
    results['get_dashboard_summary'] = add_get_dashboard_summary()
    
    # Step 3: Fix list_clients function
    results['list_clients'] = fix_list_clients()
    
    # Step 4: Create missing tables
    results['tables'] = create_missing_tables()
    
    # Step 5: Fix admin routes if app is provided
    if app:
        results['routes'] = fix_admin_routes(app)
    
    return results

def main():
    """Main function"""
    print("=" * 60)
    print("Admin Dashboard Fix")
    print("=" * 60)
    
    # Try to import the Flask app
    app = None
    try:
        from app import app
        logger.info("Successfully imported Flask app from app.py")
    except ImportError:
        logger.warning("Could not import app from app.py. Route fixes will not be applied.")
    
    # Apply all fixes
    results = apply_all_fixes(app)
    
    # Print results
    print("\nFix Results:")
    print(f"Dashboard Function: {'✅ Fixed' if results['dashboard_fix'] else '❌ Failed'}")
    print(f"get_dashboard_summary Function: {'✅ Fixed' if results['get_dashboard_summary'] else '❌ Failed'}")
    print(f"list_clients Function: {'✅ Fixed' if results['list_clients'] else '❌ Failed'}")
    print(f"Database Tables: {'✅ Fixed' if results['tables'] else '❌ Failed'}")
    print(f"Admin Routes: {'✅ Fixed' if results['routes'] else '❌ Not Applied'}")
    
    if all(results.values()) or (all(v for k, v in results.items() if k != 'routes')):
        print("\n✅ All fixes applied successfully!")
        return 0
    else:
        print("\n⚠️ Some fixes could not be applied. Check the log for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
