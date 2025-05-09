import os
import sys
import re
import logging
import sqlite3
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ADMIN_PY_PATH = os.path.join(SCRIPT_DIR, 'admin.py')
CLIENT_DB_PATH = os.path.join(SCRIPT_DIR, 'client_scanner.db')

def get_db_connection():
    """Get a connection to the client database"""
    if os.path.exists(CLIENT_DB_PATH):
        return sqlite3.connect(CLIENT_DB_PATH)
    
    # Try to find the database in the current directory
    local_db = 'client_scanner.db'
    if os.path.exists(local_db):
        return sqlite3.connect(local_db)
    
    # Check for database in instance folder
    instance_db = os.path.join('instance', 'client_scanner.db')
    if os.path.exists(instance_db):
        return sqlite3.connect(instance_db)
    
    # Create database if it doesn't exist
    logger.warning(f"Database not found at {CLIENT_DB_PATH}, creating a new one")
    conn = sqlite3.connect(CLIENT_DB_PATH)
    return conn

def create_missing_tables():
    """Create missing tables in the database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
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
            active INTEGER DEFAULT 1
        )
        ''')
        
        # Create deployed_scanners table if not exists
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
        
        # Create scan_history table if not exists
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
        
        # Insert some example data if the tables are empty
        cursor.execute("SELECT COUNT(*) FROM clients")
        if cursor.fetchone()[0] == 0:
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
            client_id = cursor.lastrowid
            
            # Insert example deployed scanner
            cursor.execute('''
            INSERT INTO deployed_scanners (
                client_id, subdomain, domain, deploy_status, deploy_date
            ) VALUES (?, ?, ?, ?, ?)
            ''', (
                client_id, 'example', 'yourscannerdomain.com', 'deployed', 
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
        logger.info("Tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        return False

def apply_dashboard_fix(admin_py_path=None):
    """Fix issues with the dashboard route in admin.py"""
    if admin_py_path is None:
        admin_py_path = ADMIN_PY_PATH
    
    if not os.path.exists(admin_py_path):
        logger.error(f"admin.py not found at {admin_py_path}")
        return False
    
    try:
        # Read the admin.py file
        with open(admin_py_path, 'r') as f:
            content = f.read()
        
        # Check if dashboard route is present
        if '@admin_bp.route(\'/dashboard\')' not in content:
            logger.error("Dashboard route not found in admin.py")
            return False
        
        # Find the dashboard function
        dashboard_match = re.search(r'@admin_bp\.route\([\'"]/dashboard[\'"].*?\)\s+@admin_required\s+def dashboard\([^)]*\):', content, re.DOTALL)
        if not dashboard_match:
            logger.error("Dashboard function not found in admin.py")
            return False
        
        # Get the dashboard function code
        dashboard_start = dashboard_match.start()
        
        # Find end of function (indentation level returns to original level)
        lines = content[dashboard_start:].split('\n')
        
        # Determine the indentation of the function definition
        function_line = 0
        for i, line in enumerate(lines):
            if 'def dashboard' in line:
                function_line = i
                break
        
        # Find the indentation level
        function_indent = len(lines[function_line]) - len(lines[function_line].lstrip())
        
        # Find where the function ends
        function_end = 0
        for i in range(function_line + 1, len(lines)):
            # Skip empty lines
            if not lines[i].strip():
                continue
            
            line_indent = len(lines[i]) - len(lines[i].lstrip())
            if line_indent <= function_indent:
                function_end = i
                break
        
        # If we didn't find the end, assume it's the end of the file
        if function_end == 0:
            function_end = len(lines)
        
        # Get the full function code
        dashboard_func = '\n'.join(lines[:function_end])
        
        # Check if the function has issues
        issues_found = False
        
        # Common issues to check for
        if "render_template('admin/admin-dashboard.html'" not in dashboard_func:
            issues_found = True
            logger.warning("Dashboard doesn't render admin-dashboard.html template")
        
        if "get_dashboard_summary" not in dashboard_func:
            issues_found = True
            logger.warning("Dashboard doesn't call get_dashboard_summary()")
        
        if "cursor" not in dashboard_func and "conn.cursor()" not in dashboard_func:
            issues_found = True
            logger.warning("Dashboard doesn't create a database cursor")
        
        # If issues were found, replace the function with a fixed version
        if issues_found:
            logger.info("Fixing dashboard function...")
            
            # Create a backup of the original file
            backup_path = f"{admin_py_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
            logger.info(f"Created backup at {backup_path}")
            
            # Create fixed dashboard function
            fixed_dashboard = """@admin_bp.route('/dashboard')
@admin_required
def dashboard(user):
    \"\"\"Admin dashboard with summary statistics\"\"\"
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
            
            # Replace the original dashboard function with the fixed version
            new_content = content[:dashboard_start] + fixed_dashboard + content[dashboard_start + len(dashboard_func):]
            
            # Write the fixed content to the file
            with open(admin_py_path, 'w') as f:
                f.write(new_content)
                
            logger.info("Dashboard function fixed successfully")
            return True
        else:
            logger.info("Dashboard function appears to be working correctly")
            return True
    except Exception as e:
        logger.error(f"Error applying dashboard fix: {e}")
        return False

def add_get_dashboard_summary(client_db_path=None):
    """Add or update the get_dashboard_summary function in client_db.py"""
    if client_db_path is None:
        # Try to find client_db.py in the current directory
        client_db_path = os.path.join(SCRIPT_DIR, 'client_db.py')
        if not os.path.exists(client_db_path):
            client_db_path = 'client_db.py'  # Try just the filename
    
    if not os.path.exists(client_db_path):
        logger.error(f"client_db.py not found at {client_db_path}")
        return False
    
    try:
        # Read the client_db.py file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Check if get_dashboard_summary function exists
        if 'def get_dashboard_summary' in content:
            logger.info("get_dashboard_summary function already exists")
            
            # Create a backup in case we need to modify it
            backup_path = f"{client_db_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
                
            # Check if function has issues
            if 'cursor is None' not in content:
                # Function doesn't handle cursor parameter properly
                logger.warning("get_dashboard_summary function doesn't handle cursor parameter properly")
                
                # Create a fixed version
                fixed_func = """
def get_dashboard_summary(cursor=None):
    \"\"\"Get summary statistics for the admin dashboard.\"\"\"
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active scanners count
        cursor.execute("SELECT COUNT(*) FROM deployed_scanners WHERE deploy_status = 'deployed'")
        deployed_scanners = cursor.fetchone()[0]
        
        # Count scan history (active scans)
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        try:
            active_scans = cursor.fetchone()[0]
        except:
            active_scans = 0
        
        # Calculate monthly revenue (based on subscriptions)
        cursor.execute("SELECT COUNT(*), subscription_level FROM clients WHERE active = 1 GROUP BY subscription_level")
        subscription_counts = cursor.fetchall()
        
        # Define subscription prices
        subscription_prices = {'basic': 49, 'pro': 149, 'enterprise': 499}
        monthly_revenue = 0
        
        for count, level in subscription_counts:
            level = level.lower() if level else 'basic'
            price = subscription_prices.get(level, 0)
            monthly_revenue += count * price
        
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
                # Replace or append the function
                if 'def get_dashboard_summary' in content:
                    # Find the existing function
                    pattern = r'def get_dashboard_summary.*?(?=def|\Z)'
                    replacement = fixed_func
                    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
                else:
                    # Append the function
                    new_content = content + fixed_func
                
                # Write the fixed content
                with open(client_db_path, 'w') as f:
                    f.write(new_content)
                
                logger.info("get_dashboard_summary function updated")
                return True
            else:
                logger.info("get_dashboard_summary function appears to be working correctly")
                return True
        else:
            # Function doesn't exist, add it
            logger.info("Adding get_dashboard_summary function...")
            
            # Create a backup
            backup_path = f"{client_db_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
            
            # Add the function
            dashboard_summary_func = """
def get_dashboard_summary(cursor=None):
    \"\"\"Get summary statistics for the admin dashboard.\"\"\"
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active scanners count
        cursor.execute("SELECT COUNT(*) FROM deployed_scanners WHERE deploy_status = 'deployed'")
        deployed_scanners = cursor.fetchone()[0]
        
        # Count scan history (active scans)
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        try:
            active_scans = cursor.fetchone()[0]
        except:
            active_scans = 0
        
        # Calculate monthly revenue (based on subscriptions)
        cursor.execute("SELECT COUNT(*), subscription_level FROM clients WHERE active = 1 GROUP BY subscription_level")
        subscription_counts = cursor.fetchall()
        
        # Define subscription prices
        subscription_prices = {'basic': 49, 'pro': 149, 'enterprise': 499}
        monthly_revenue = 0
        
        for count, level in subscription_counts:
            level = level.lower() if level else 'basic'
            price = subscription_prices.get(level, 0)
            monthly_revenue += count * price
        
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
            # Append the function to the file
            with open(client_db_path, 'a') as f:
                f.write(dashboard_summary_func)
            
            logger.info("get_dashboard_summary function added successfully")
            return True
    except Exception as e:
        logger.error(f"Error adding/updating get_dashboard_summary: {e}")
        return False

def fix_list_clients(client_db_path=None):
    """Fix issues with the list_clients function in client_db.py"""
    if client_db_path is None:
        # Try to find client_db.py in the current directory
        client_db_path = os.path.join(SCRIPT_DIR, 'client_db.py')
        if not os.path.exists(client_db_path):
            client_db_path = 'client_db.py'  # Try just the filename
    
    if not os.path.exists(client_db_path):
        logger.error(f"client_db.py not found at {client_db_path}")
        return False
    
    try:
        # Read the client_db.py file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Check if list_clients function exists
        if 'def list_clients' in content:
            logger.info("list_clients function already exists")
            
            # Create a backup in case we need to modify it
            backup_path = f"{client_db_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
                
            # Check if function has issues
            issues_found = False
            
            if 'cursor=None' not in content and 'cursor = None' not in content:
                issues_found = True
                logger.warning("list_clients function doesn't handle cursor parameter properly")
            
            if issues_found:
                # Create a fixed version
                fixed_func = """
def list_clients(cursor=None, page=1, per_page=10, filters=None):
    \"\"\"List clients with pagination and filtering.\"\"\"
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
                # Replace or append the function
                if 'def list_clients' in content:
                    # Find the existing function
                    pattern = r'def list_clients.*?(?=def|\Z)'
                    replacement = fixed_func
                    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
                else:
                    # Append the function
                    new_content = content + fixed_func
                
                # Write the fixed content
                with open(client_db_path, 'w') as f:
                    f.write(new_content)
                
                logger.info("list_clients function updated")
                return True
            else:
                logger.info("list_clients function appears to be working correctly")
                return True
        else:
            # Function doesn't exist, add it
            logger.info("Adding list_clients function...")
            
            # Create a backup
            backup_path = f"{client_db_path}.bak"
            with open(backup_path, 'w') as f:
                f.write(content)
            
            # Add the function
            list_clients_func = """
def list_clients(cursor=None, page=1, per_page=10, filters=None):
    \"\"\"List clients with pagination and filtering.\"\"\"
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
            # Append the function to the file
            with open(client_db_path, 'a') as f:
                f.write(list_clients_func)
            
            logger.info("list_clients function added successfully")
            return True
    except Exception as e:
        logger.error(f"Error adding/updating list_clients: {e}")
        return False

def main():
    """Main function"""
    print("=" * 60)
    print("Dashboard Fix Script")
    print("=" * 60)
    
    # Step 1: Create missing tables
    print("\nChecking database tables...")
    if create_missing_tables():
        print("✅ Database tables verified/created successfully")
    else:
        print("❌ Error checking/creating database tables")
    
    # Step 2: Add/update get_dashboard_summary function
    print("\nAdding/updating get_dashboard_summary function...")
    if add_get_dashboard_summary():
        print("✅ get_dashboard_summary function added/updated successfully")
    else:
        print("❌ Error adding/updating get_dashboard_summary function")
    
    # Step 3: Fix list_clients function
    print("\nFixing list_clients function...")
    if fix_list_clients():
        print("✅ list_clients function fixed successfully")
    else:
        print("❌ Error fixing list_clients function")
    
    # Step 4: Fix dashboard function in admin.py
    print("\nFixing dashboard function...")
    if apply_dashboard_fix():
        print("✅ Dashboard function fixed successfully")
    else:
        print("❌ Error fixing dashboard function")
    
    print("\nFix script completed!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
