import os
import sys
import sqlite3
import logging
from datetime import datetime, timedelta

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
CLIENT_DB_PATH = os.path.join(SCRIPT_DIR, 'client_scanner.db')

def get_client_db_path():
    """Get the path to the client DB, searching in different locations if needed"""
    # Try the default path first
    if os.path.exists(CLIENT_DB_PATH):
        return CLIENT_DB_PATH
    
    # Check for client_scanner.db in the current directory
    if os.path.exists('client_scanner.db'):
        return 'client_scanner.db'
    
    # Check for database in instance folder
    instance_db = os.path.join('instance', 'client_scanner.db')
    if os.path.exists(instance_db):
        return instance_db
    
    # Try searching for any .db files
    db_files = [f for f in os.listdir('.') if f.endswith('.db')]
    if db_files:
        logger.info(f"Found potential database files: {db_files}")
        return db_files[0]
    
    logger.warning("Could not find client database file")
    return CLIENT_DB_PATH  # Return default path even if it doesn't exist

def check_required_tables():
    """Check if required tables exist, create them if needed"""
    try:
        db_path = get_client_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if clients table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
        if not cursor.fetchone():
            logger.info("Creating clients table...")
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
        
        # Check if deployed_scanners table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='deployed_scanners'")
        if not cursor.fetchone():
            logger.info("Creating deployed_scanners table...")
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
        
        # Check if scan_history table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            logger.info("Creating scan_history table...")
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
        
        conn.commit()
        conn.close()
        
        logger.info("Required tables verified/created")
        return True
    except Exception as e:
        logger.error(f"Error checking/creating tables: {e}")
        return False

def add_dashboard_functions():
    """Add functions to client_db.py for dashboard functionality"""
    try:
        # Try to find client_db.py in the current directory
        client_db_path = os.path.join(SCRIPT_DIR, 'client_db.py')
        if not os.path.exists(client_db_path):
            client_db_path = 'client_db.py'  # Try just the filename
            
        if not os.path.exists(client_db_path):
            logger.error("Could not find client_db.py")
            return False
        
        logger.info(f"Found client_db.py at: {client_db_path}")
        
        # Read existing content
        with open(client_db_path, 'r') as file:
            content = file.read()
        
        # Add get_dashboard_summary function if it doesn't exist
        if 'def get_dashboard_summary' not in content:
            logger.info("Adding get_dashboard_summary function...")
            with open(client_db_path, 'a') as file:
                file.write("""
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
""")
        
        # Add fix for list_clients function if it has issues
        if 'def list_clients' not in content:
            logger.info("Adding list_clients function...")
            with open(client_db_path, 'a') as file:
                file.write("""
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
""")
        
        # Add function for deployed scanners if needed
        if 'def list_deployed_scanners' not in content:
            logger.info("Adding list_deployed_scanners function...")
            with open(client_db_path, 'a') as file:
                file.write("""
def list_deployed_scanners(conn, page=1, per_page=10, filters=None):
    """List deployed scanners with pagination and filtering."""
    try:
        cursor = conn.cursor()
        
        # Default filters
        if filters is None:
            filters = {}
        
        # Build query
        query = """
        SELECT ds.*, c.business_name, c.business_domain, c.contact_email, c.scanner_name
        FROM deployed_scanners ds
        JOIN clients c ON ds.client_id = c.id
        """
        params = []
        
        # Apply filters
        where_clauses = []
        
        if 'search' in filters and filters['search']:
            where_clauses.append("(c.business_name LIKE ? OR c.business_domain LIKE ? OR ds.subdomain LIKE ?)")
            search_term = f"%{filters['search']}%"
            params.extend([search_term, search_term, search_term])
        
        if 'status' in filters and filters['status']:
            where_clauses.append("ds.deploy_status = ?")
            params.append(filters['status'])
        
        # Add WHERE clause if needed
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        # Count total matching scanners
        count_query = f"SELECT COUNT(*) FROM ({query})"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Add pagination
        query += " ORDER BY ds.id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        # Execute query
        cursor.execute(query, params)
        
        # Convert to list of dictionaries
        scanners = []
        for row in cursor.fetchall():
            scanner = {}
            for idx, col in enumerate(cursor.description):
                scanner[col[0]] = row[idx]
            scanners.append(scanner)
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page if per_page > 0 else 1
        
        # Return scanners and pagination info
        return {
            'scanners': scanners,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        }
    except Exception as e:
        import traceback
        print(f"Error in list_deployed_scanners: {e}")
        print(traceback.format_exc())
        
        # Return empty list on error
        return {
            'scanners': [],
            'pagination': {
                'page': 1,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 1
            }
        }
""")
        
        logger.info("Dashboard functions added successfully")
        return True
    except Exception as e:
        logger.error(f"Error adding dashboard functions: {e}")
        return False

def main():
    """Main function"""
    print("=" * 60)
    print("Client DB Fix Script")
    print("=" * 60)
    
    # Step 1: Check database tables
    print("\nChecking database tables...")
    if check_required_tables():
        print("✅ Database tables verified/created successfully")
    else:
        print("❌ Error checking/creating database tables")
    
    # Step 2: Add/update dashboard functions
    print("\nAdding dashboard functions...")
    if add_dashboard_functions():
        print("✅ Dashboard functions added/updated successfully")
    else:
        print("❌ Error adding dashboard functions")
    
    print("\nFix script completed!")
    print(f"Database path: {get_client_db_path()}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
