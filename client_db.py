# Enhanced client_db.py with better structure and relations

import os
import sqlite3
import json
import logging
import traceback
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
import functools
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner_platform.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Create the schema string for initialization
SCHEMA_SQL = """
-- Users table for authentication and access control
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'client',
    created_at TEXT,
    last_login TEXT,
    active BOOLEAN DEFAULT 1
);

-- Clients table to store basic client information
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    active BOOLEAN DEFAULT 1,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Customizations table for branding and visual options
CREATE TABLE IF NOT EXISTS customizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    primary_color TEXT,
    secondary_color TEXT,
    logo_path TEXT,
    favicon_path TEXT,
    email_subject TEXT,
    email_intro TEXT,
    email_footer TEXT,
    default_scans TEXT,  -- JSON array of default scan types
    css_override TEXT,
    html_override TEXT,
    last_updated TEXT,
    updated_by INTEGER,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Deployed scanners table to track scanner instances
CREATE TABLE IF NOT EXISTS deployed_scanners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    subdomain TEXT UNIQUE,
    domain TEXT,
    deploy_status TEXT,
    deploy_date TEXT,
    last_updated TEXT,
    config_path TEXT,
    template_version TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Scan history table to track scanning activity
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
);

-- Sessions table for user login sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at TEXT,
    expires_at TEXT,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit log table for tracking changes
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    changes TEXT,
    timestamp TEXT NOT NULL,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reset_token TEXT UNIQUE NOT NULL,
    created_at TEXT,
    expires_at TEXT,
    used BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Client billing table for subscriptions
CREATE TABLE IF NOT EXISTS client_billing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    plan_id TEXT,
    billing_cycle TEXT,
    amount REAL,
    currency TEXT DEFAULT 'USD',
    start_date TEXT,
    next_billing_date TEXT,
    payment_method TEXT,
    status TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Billing transactions table for payment history
CREATE TABLE IF NOT EXISTS billing_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    transaction_id TEXT UNIQUE,
    amount REAL,
    currency TEXT DEFAULT 'USD',
    payment_method TEXT,
    status TEXT,
    timestamp TEXT,
    notes TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- Create indices for better performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_clients_business_name ON clients(business_name);
CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
"""

SCHEMA_SQL = """
-- Your schema creation SQL here
-- This can be empty if you're creating tables explicitly in init_client_db
"""



def with_transaction(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            result = func(conn, *args, **kwargs)
            conn.commit()
            return result
        except Exception as e:
            conn.rollback()
            logging.error(f"Transaction error in {func.__name__}: {e}")
            return {'status': 'error', 'message': str(e)}
        finally:
            conn.close()
    return wrapper

def get_client_by_user_id(user_id):
    """Get client data for a specific user"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                id,
                business_name,
                business_domain,
                contact_email,
                contact_phone,
                scanner_name,
                subscription_level,
                primary_color,
                secondary_color,
                email_subject,
                email_intro
            FROM clients 
            WHERE user_id = ? AND active = 1
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (user_id,))
        
        result = cursor.fetchone()
        
        if result:
            return {
                'id': result[0],
                'business_name': result[1],
                'business_domain': result[2],
                'contact_email': result[3],
                'contact_phone': result[4],
                'scanner_name': result[5],
                'subscription_level': result[6],
                'primary_color': result[7] if len(result) > 7 else '#FF6900',
                'secondary_color': result[8] if len(result) > 8 else '#808588',
                'email_subject': result[9] if len(result) > 9 else 'Your Security Scan Report',
                'email_intro': result[10] if len(result) > 10 else ''
            }
        return None
        
    except Exception as e:
        import logging
        logging.error(f"Error getting client by user_id: {str(e)}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()

def track_activity(client_id, activity_type, details):
    """Track client activities"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO activity_logs 
            (client_id, activity_type, details, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            client_id,
            activity_type,
            json.dumps(details),
            datetime.now().isoformat()
        ))
        conn.commit()
    finally:
        conn.close()

def _get_client_by_user_id_legacy(user_id):
    """Legacy version of get_client_by_user_id for backward compatibility"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.*, cu.primary_color, cu.secondary_color, cu.logo_path,
                   cu.default_scans, ds.subdomain, ds.deploy_status
            FROM clients c
            LEFT JOIN customizations cu ON c.id = cu.client_id
            LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
            WHERE c.user_id = ? AND c.active = 1
        ''', (user_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        # Convert row to dict
        client_data = dict(row)
        
        # Convert default_scans JSON to list if present
        if client_data.get('default_scans'):
            try:
                client_data['default_scans'] = json.loads(client_data['default_scans'])
            except json.JSONDecodeError:
                client_data['default_scans'] = []
        else:
            client_data['default_scans'] = []
            
        return client_data
    except Exception as e:
        logging.error(f"Error in legacy get_client_by_user_id: {e}")
        return None

# Add this function to client_db.py for audit logging with better error handling
def add_audit_log(conn, user_id, action, entity_type, entity_id, changes=None, ip_address=None):
    """
    Add an entry to the audit log with enhanced error handling
    """
    try:
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if audit_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
        if not cursor.fetchone():
            logging.warning("Audit log table doesn't exist. Creating it now.")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER NOT NULL,
                changes TEXT,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            ''')
            conn.commit()
        
        # Insert the audit log entry
        cursor.execute('''
        INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, action, entity_type, entity_id, json.dumps(changes) if changes else None, timestamp, ip_address))
        
        conn.commit()
        return True
    except Exception as e:
        logging.warning(f"Could not add audit log: {e}")
        return False

def get_deployed_scanners_by_client_id(client_id, page=1, per_page=10, filters=None):
    """Get list of deployed scanners for a client with pagination and filtering"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculate offset for pagination
        offset = (page - 1) * per_page
        
        # Base query - CHANGE 'scanners' to 'deployed_scanners'
        query = "SELECT * FROM deployed_scanners WHERE client_id = ?"
        params = [client_id]
        
        # Apply filters if provided
        if filters:
            if 'status' in filters and filters['status']:
                query += " AND deploy_status = ?"  # Changed 'status' to 'deploy_status'
                params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                query += " AND (domain LIKE ? OR subdomain LIKE ?)"  # Changed field names
                search_term = f"%{filters['search']}%"
                params.append(search_term)
                params.append(search_term)
        
        # Add sorting and pagination
        query += " ORDER BY last_updated DESC LIMIT ? OFFSET ?"  # Changed 'created_at' to 'last_updated'
        params.append(per_page)
        params.append(offset)
        
        # Execute query for scanners
        cursor.execute(query, params)
        scanners = [dict(row) for row in cursor.fetchall()]
        
        # Get total count for pagination
        count_query = "SELECT COUNT(*) FROM deployed_scanners WHERE client_id = ?"  # Changed table name
        count_params = [client_id]
        
        # Apply the same filters to count query
        if filters:
            if 'status' in filters and filters['status']:
                count_query += " AND deploy_status = ?"  # Changed field name
                count_params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                count_query += " AND (domain LIKE ? OR subdomain LIKE ?)"  # Changed field names
                search_term = f"%{filters['search']}%"
                count_params.append(search_term)
                count_params.append(search_term)
        
        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()[0]
        
        conn.close()
        
        # Calculate pagination metadata
        total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
        
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
        logging.error(f"Error retrieving scanners for client: {e}")
        return {
            'scanners': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 0
            }
        }

@with_transaction
def get_client_statistics(conn, cursor, client_id):
    """Get comprehensive statistics for a client"""
    try:
        stats = {}
        
        # Get scanner count
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM deployed_scanners
            WHERE client_id = ? AND deploy_status = 'deployed'
        """, (client_id,))
        stats['scanners_count'] = cursor.fetchone()['count']
        
        # Get total scans
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM scan_history
            WHERE client_id = ?
        """, (client_id,))
        stats['total_scans'] = cursor.fetchone()['count']
        
        # Get average security score (this would need to be implemented based on your scan storage)
        # For now, return a placeholder
        stats['avg_security_score'] = None
        
        # Get reports count (same as total scans for now)
        stats['reports_count'] = stats['total_scans']
        
        # Get recent scans
        cursor.execute("""
            SELECT s.*, ds.subdomain as scanner_name
            FROM scan_history s
            LEFT JOIN deployed_scanners ds ON s.client_id = ds.client_id
            WHERE s.client_id = ?
            ORDER BY s.timestamp DESC
            LIMIT 5
        """, (client_id,))
        stats['recent_scans'] = [dict(row) for row in cursor.fetchall()]
        
        return stats
    except Exception as e:
        logging.error(f"Error getting client statistics: {e}")
        return {
            'scanners_count': 0,
            'total_scans': 0,
            'avg_security_score': None,
            'reports_count': 0,
            'recent_scans': []
        }

@with_transaction
def get_recent_activities(conn, cursor, client_id, limit=10):
    """Get recent activities for a client"""
    try:
        activities = []
        
        # Get recent scans
        cursor.execute("""
            SELECT timestamp, target, scan_type
            FROM scan_history
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (client_id, limit))
        
        for row in cursor.fetchall():
            activities.append({
                'timestamp': row['timestamp'],
                'description': f"Scanned {row['target']}",
                'icon': 'bi-search',
                'type': 'scan'
            })
        
        # Get recent client updates from audit log
        cursor.execute("""
            SELECT timestamp, action, changes
            FROM audit_log
            WHERE entity_type = 'client' AND entity_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (client_id, limit))
        
        for row in cursor.fetchall():
            activities.append({
                'timestamp': row['timestamp'],
                'description': f"Client {row['action']}",
                'icon': 'bi-gear',
                'type': 'update'
            })
        
        # Sort all activities by timestamp
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return activities[:limit]
    except Exception as e:
        logging.error(f"Error getting recent activities: {e}")
        return []

@with_transaction
def get_available_scanners_for_client(conn, cursor, client_id):
    """Get all available scanners for a client"""
    try:
        cursor.execute("""
            SELECT ds.*, c.business_name, c.scanner_name
            FROM deployed_scanners ds
            JOIN clients c ON ds.client_id = c.id
            WHERE ds.client_id = ?
            ORDER BY ds.id DESC
        """, (client_id,))
        
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Error getting available scanners: {e}")
        return []

def get_client_dashboard_data(client_id):
    """Get comprehensive dashboard data for a client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get client info
        cursor.execute('''
            SELECT c.*, cu.primary_color, cu.secondary_color, cu.logo_path,
                   cu.default_scans, ds.subdomain, ds.deploy_status
            FROM clients c
            LEFT JOIN customizations cu ON c.id = cu.client_id
            LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
            WHERE c.id = ? AND c.active = 1
        ''', (client_id,))
        
        client_row = cursor.fetchone()
        if not client_row:
            conn.close()
            return None
        
        client = dict(client_row)
        
        # Convert default_scans JSON to list if present
        if client.get('default_scans'):
            try:
                client['default_scans'] = json.loads(client['default_scans'])
            except json.JSONDecodeError:
                client['default_scans'] = []
        else:
            client['default_scans'] = []
        
        # Get statistics
        stats = {}
        
        # Get scanner count
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM deployed_scanners
            WHERE client_id = ? AND deploy_status = 'deployed'
        """, (client_id,))
        stats['scanners_count'] = cursor.fetchone()['count']
        
        # Get total scans
        stats['total_scans'] = 0  # Default value
        
        # Check if scan_history table exists
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(scan_history)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'client_id' in columns:
                    cursor.execute("SELECT COUNT(*) as count FROM scan_history WHERE client_id = ?", (client_id,))
                    stats['total_scans'] = cursor.fetchone()['count']
        except Exception as e:
            logging.warning(f"Error getting scan count: {e}")
        
        # Set default numeric values
        stats['avg_security_score'] = 75  # Default numeric value
        stats['reports_count'] = stats['total_scans']
        stats['critical_issues'] = 0
        stats['high_issues'] = 0
        stats['medium_issues'] = 0
        
        # Get scanners
        scanners_result = get_deployed_scanners_by_client_id(client_id)
        scanners = scanners_result.get('scanners', [])
        
        # Get scan history
        scan_history = get_scan_history_by_client_id(client_id, limit=5)
        
        # Get recent activities (simplified)
        recent_activities = []  # TODO: Implement actual activity tracking
        
        conn.close()
        
        return {
            'client': client,
            'stats': stats,
            'scanners': scanners,
            'scan_history': scan_history,
            'recent_activities': recent_activities
        }
    except Exception as e:
        logging.error(f"Error getting client dashboard data: {e}")
        import traceback
        logging.error(traceback.format_exc())
        if 'conn' in locals():
            conn.close()
        return None
@with_transaction
def format_scan_results_for_client(conn, cursor, scan_data):
    """Format scan results for client-friendly display"""
    try:
        if not scan_data:
            return None
        
        # Add client-friendly formatting
        formatted_scan = scan_data.copy()
        
        # Format risk levels
        if 'risk_assessment' in formatted_scan:
            risk_level = formatted_scan['risk_assessment'].get('risk_level', 'Unknown')
            if risk_level.lower() == 'critical':
                formatted_scan['risk_color'] = 'danger'
            elif risk_level.lower() == 'high':
                formatted_scan['risk_color'] = 'warning'
            elif risk_level.lower() == 'medium':
                formatted_scan['risk_color'] = 'info'
            else:
                formatted_scan['risk_color'] = 'success'
        
        # Format dates for display
        if 'timestamp' in formatted_scan:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(formatted_scan['timestamp'])
                formatted_scan['formatted_date'] = dt.strftime('%B %d, %Y at %I:%M %p')
            except:
                pass
        
        # Add summary statistics
        if 'risk_assessment' in formatted_scan:
            risk_assessment = formatted_scan['risk_assessment']
            formatted_scan['total_issues'] = (
                risk_assessment.get('critical_issues', 0) +
                risk_assessment.get('high_issues', 0) +
                risk_assessment.get('medium_issues', 0) +
                risk_assessment.get('low_issues', 0)
            )
        
        return formatted_scan
    except Exception as e:
        logging.error(f"Error formatting scan results: {e}")
        return scan_data

# Also add these missing functions with proper error handling

@with_transaction
def get_scan_history_by_client_id(conn, cursor, client_id, limit=None):
    """Get scan history for a client with proper error handling"""
    try:
        query = """
        SELECT sh.*, ds.subdomain as scanner_name
        FROM scan_history sh
        LEFT JOIN deployed_scanners ds ON sh.client_id = ds.client_id
        WHERE sh.client_id = ?
        ORDER BY sh.timestamp DESC
        """
        
        params = [client_id]
        
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Error getting scan history: {e}")
        return []

@with_transaction
def update_scanner_config(conn, cursor, scanner_id, scanner_data, user_id):
    """Update scanner configuration with proper validation"""
    try:
        # Get scanner details
        cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
        row = cursor.fetchone()
        
        if not row:
            return {"status": "error", "message": "Scanner not found"}
        
        client_id = row['client_id']
        
        # Update deployed_scanners table
        scanner_fields = []
        scanner_values = []
        
        if 'subdomain' in scanner_data:
            # Check if subdomain is unique
            cursor.execute("""
                SELECT id FROM deployed_scanners 
                WHERE subdomain = ? AND id != ?
            """, (scanner_data['subdomain'], scanner_id))
            
            if cursor.fetchone():
                return {"status": "error", "message": "Subdomain already in use"}
            
            scanner_fields.append("subdomain = ?")
            scanner_values.append(scanner_data['subdomain'])
        
        # Update last_updated
        scanner_fields.append("last_updated = ?")
        scanner_values.append(datetime.now().isoformat())
        
        # Execute scanner update
        if scanner_fields:
            query = f"UPDATE deployed_scanners SET {', '.join(scanner_fields)} WHERE id = ?"
            scanner_values.append(scanner_id)
            cursor.execute(query, scanner_values)
        
        # Update client table
        client_fields = []
        client_values = []
        
        if 'scanner_name' in scanner_data:
            client_fields.append("scanner_name = ?")
            client_values.append(scanner_data['scanner_name'])
        
        if 'business_domain' in scanner_data:
            client_fields.append("business_domain = ?")
            client_values.append(scanner_data['business_domain'])
        
        if 'contact_email' in scanner_data:
            client_fields.append("contact_email = ?")
            client_values.append(scanner_data['contact_email'])
        
        if 'contact_phone' in scanner_data:
            client_fields.append("contact_phone = ?")
            client_values.append(scanner_data['contact_phone'])
        
        # Update client table
        if client_fields:
            client_fields.append("updated_at = ?")
            client_values.append(datetime.now().isoformat())
            client_fields.append("updated_by = ?")
            client_values.append(user_id)
            
            query = f"UPDATE clients SET {', '.join(client_fields)} WHERE id = ?"
            client_values.append(client_id)
            cursor.execute(query, client_values)
        
        # Update customizations table
        custom_fields = []
        custom_values = []
        
        custom_mapping = {
            'primary_color': 'primary_color',
            'secondary_color': 'secondary_color',
            'logo_path': 'logo_path',
            'favicon_path': 'favicon_path',
            'email_subject': 'email_subject',
            'email_intro': 'email_intro'
        }
        
        for key, db_field in custom_mapping.items():
            if key in scanner_data:
                custom_fields.append(f"{db_field} = ?")
                custom_values.append(scanner_data[key])
        
        # Handle default_scans
        if 'default_scans' in scanner_data:
            custom_fields.append("default_scans = ?")
            custom_values.append(json.dumps(scanner_data['default_scans']))
        
        # Update customizations
        if custom_fields:
            custom_fields.append("last_updated = ?")
            custom_values.append(datetime.now().isoformat())
            custom_fields.append("updated_by = ?")
            custom_values.append(user_id)
            
            # Check if customization exists
            cursor.execute('SELECT id FROM customizations WHERE client_id = ?', (client_id,))
            if cursor.fetchone():
                # Update existing
                query = f"UPDATE customizations SET {', '.join(custom_fields)} WHERE client_id = ?"
                custom_values.append(client_id)
                cursor.execute(query, custom_values)
            else:
                # Insert new
                fields = ['client_id'] + [field.split(' = ')[0] for field in custom_fields]
                values = [client_id] + custom_values
                placeholders = ', '.join(['?'] * len(fields))
                query = f"INSERT INTO customizations ({', '.join(fields)}) VALUES ({placeholders})"
                cursor.execute(query, values)
        
        # Log the update
        log_action(conn, cursor, user_id, 'update', 'scanner', scanner_id, scanner_data)
        
        return {"status": "success", "scanner_id": scanner_id}
    except Exception as e:
        logging.error(f"Error updating scanner config: {e}")
        return {"status": "error", "message": str(e)}

@with_transaction
def get_dashboard_summary(conn, cursor=None):
    """
    Get dashboard summary statistics
    
    Args:
        conn: Database connection (provided by with_transaction)
        cursor: Database cursor (provided by with_transaction)
        
    Returns:
        dict: Dashboard summary statistics
    """
    try:
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 1")
        active_clients = cursor.fetchone()[0]
        
        # Get inactive clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 0")
        inactive_clients = cursor.fetchone()[0]
        
        # Get total scan count
        try:
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
        except:
            # Table might not exist
            total_scans = 0
        
        # Get today's scan count
        import datetime
        today = datetime.date.today().isoformat()
        try:
            cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(timestamp) = ?", (today,))
            scans_today = cursor.fetchone()[0]
        except:
            scans_today = 0
        
        # Get total users count
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Get subscription distribution
        try:
            cursor.execute("""
                SELECT subscription_level as subscription, COUNT(*) as count
                FROM clients
                GROUP BY subscription_level
            """)
            subscription_distribution = {}
            for row in cursor.fetchall():
                subscription_distribution[row[0]] = row[1]
        except:
            subscription_distribution = {"basic": 0, "pro": 0, "enterprise": 0}
        
        # Return summary data
        return {
            'total_clients': total_clients,
            'active_clients': active_clients,
            'inactive_clients': inactive_clients,
            'total_scans': total_scans,
            'scans_today': scans_today,
            'total_users': total_users,
            'subscription_distribution': subscription_distribution,
            'deployed_scanners': active_clients  # Use active_clients as a proxy
        }
    except Exception as e:
        logging.error(f"Error in get_dashboard_summary: {e}")
        # Return default data on error
        return {
            'total_clients': 0,
            'active_clients': 0,
            'inactive_clients': 0,
            'total_scans': 0,
            'scans_today': 0,
            'total_users': 0,
            'subscription_distribution': {"basic": 0, "pro": 0, "enterprise": 0},
            'deployed_scanners': 0
        }

@with_transaction
def deactivate_client(conn, cursor, client_id, user_id=None):
    """
    Deactivate a client (soft delete)
    
    Args:
        conn: Database connection
        cursor: Database cursor
        client_id (int): ID of the client to deactivate
        user_id (int, optional): ID of the user performing the action
        
    Returns:
        dict: Status result
    """
    try:
        # Check if client exists
        cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
        if not cursor.fetchone():
            return {"status": "error", "message": "Client not found"}
        
        # Set client as inactive
        cursor.execute('''
        UPDATE clients 
        SET active = 0, 
            updated_at = ?, 
            updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user_id, client_id))
        
        # Also deactivate any deployed scanners
        cursor.execute('''
        UPDATE deployed_scanners
        SET deploy_status = 'inactive',
            last_updated = ?
        WHERE client_id = ?
        ''', (datetime.now().isoformat(), client_id))
        
        # Log the deactivation
        if user_id:
            try:
                cursor.execute('''
                INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    'deactivate',
                    'client',
                    client_id,
                    json.dumps({"active": 0}),
                    datetime.now().isoformat()
                ))
            except Exception as log_error:
                logging.warning(f"Could not add audit log: {str(log_error)}")
        
        logging.info(f"Client {client_id} deactivated by user {user_id}")
        
        return {"status": "success", "message": "Client deactivated successfully"}
        
    except Exception as e:
        logging.error(f"Error deactivating client: {e}")
        raise  # Re-raise to let transaction wrapper handle it

@with_transaction
def get_dashboard_summary(cursor=None):
    """
    Get dashboard summary statistics
    
    Args:
        cursor (sqlite3.Cursor, optional): Database cursor. If None, a new connection is created.
        
    Returns:
        dict: Dashboard summary statistics
    """
    # Create connection and cursor if not provided
    conn = None
    close_conn = False
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()
        close_conn = True
    
    try:
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 1")
        active_clients = cursor.fetchone()[0]
        
        # Get inactive clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 0")
        inactive_clients = cursor.fetchone()[0]
        
        # Get total scan count
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        # Get today's scan count
        import datetime
        today = datetime.date.today().isoformat()
        cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(scan_date) = ?", (today,))
        scans_today = cursor.fetchone()[0]
        
        # Get total users count
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Get client distribution by subscription
        cursor.execute("""
            SELECT subscription, COUNT(*) as count
            FROM clients
            GROUP BY subscription
        """)
        subscription_distribution = {}
        for row in cursor.fetchall():
            subscription_distribution[row[0]] = row[1]
        
        # Return summary data
        return {
            'total_clients': total_clients,
            'active_clients': active_clients,
            'inactive_clients': inactive_clients,
            'total_scans': total_scans,
            'scans_today': scans_today,
            'total_users': total_users,
            'subscription_distribution': subscription_distribution
        }
    finally:
        # Close connection if we opened it
        if close_conn and conn:
            conn.close()
            
@with_transaction
def list_clients(page=1, per_page=10, filters=None, sort_by=None, sort_dir='asc'):
    """
    List clients with pagination and filtering
    
    Args:
        page (int): Page number
        per_page (int): Items per page
        filters (dict, optional): Filter conditions
        sort_by (str, optional): Column to sort by
        sort_dir (str, optional): Sort direction ('asc' or 'desc')
        
    Returns:
        dict: Dictionary with clients and pagination info
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Base query
    query = "SELECT * FROM clients"
    count_query = "SELECT COUNT(*) FROM clients"
    
    # Add filter conditions if provided
    params = []
    where_clauses = []
    
    if filters:
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append("subscription = ?")
            params.append(filters['subscription'])
        
        if 'status' in filters and filters['status']:
            active = 1 if filters['status'].lower() == 'active' else 0
            where_clauses.append("active = ?")
            params.append(active)
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append("(business_name LIKE ? OR business_domain LIKE ? OR contact_email LIKE ?)")
            params.extend([search_term, search_term, search_term])
    
    # Add WHERE clause if there are filter conditions
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
        count_query += " WHERE " + " AND ".join(where_clauses)
    
    # Add sorting
    if sort_by:
        valid_columns = ['id', 'business_name', 'business_domain', 'created_at', 'subscription']
        if sort_by in valid_columns:
            sort_direction = "DESC" if sort_dir.lower() == 'desc' else "ASC"
            query += f" ORDER BY {sort_by} {sort_direction}"
        else:
            # Default sorting
            query += " ORDER BY id DESC"
    else:
        # Default sorting
        query += " ORDER BY id DESC"
    
    # Get total count for pagination
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]
    
    # Add pagination
    offset = (page - 1) * per_page
    query += " LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    # Execute final query
    cursor.execute(query, params)
    clients = [dict(row) for row in cursor.fetchall()]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    # Build pagination object
    pagination = {
        'page': page,
        'per_page': per_page,
        'total_count': total_count,
        'total_pages': total_pages
    }
    
    conn.close()
    
    return {
        'clients': clients,
        'pagination': pagination
    }
    
@with_transaction
def get_client_by_id(conn, client_id):
    """Get client details by ID"""
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT c.*, u.username as created_by_name
        FROM clients c
        LEFT JOIN users u ON c.created_by = u.id
        WHERE c.id = ?
    """, (client_id,))
    
    client = cursor.fetchone()
    
    if client:
        # Get customizations if available
        cursor.execute("SELECT * FROM customizations WHERE client_id = ?", (client_id,))
        customizations = cursor.fetchone()
        
        client_dict = dict(client)
        
        if customizations:
            client_dict.update(dict(customizations))
        
        return client_dict
    else:
        return None

@with_transaction
def update_client(conn, client_id, client_data):
    """Update client details"""
    cursor = conn.cursor()
    
    # Extract fields for the clients table
    client_fields = [
        'business_name', 'business_domain', 'contact_email', 'contact_phone',
        'scanner_name', 'subscription_level', 'subscription_status',
        'active', 'updated_at', 'updated_by'
    ]
    
    # Filter client_data to keep only relevant fields
    client_updates = {k: v for k, v in client_data.items() if k in client_fields}
    
    if not client_updates:
        return {'status': 'error', 'message': 'No valid fields to update'}
    
    # Build the UPDATE query
    query = "UPDATE clients SET " + ", ".join([f"{k} = ?" for k in client_updates.keys()])
    query += " WHERE id = ?"
    
    values = list(client_updates.values()) + [client_id]
    
    cursor.execute(query, values)
    
    # Check if there are customization fields to update
    customization_fields = [
        'primary_color', 'secondary_color', 'logo_path', 'favicon_path',
        'email_subject', 'email_intro', 'email_footer', 'default_scans',
        'css_override', 'html_override'
    ]
    
    customization_updates = {k: v for k, v in client_data.items() if k in customization_fields}
    
    if customization_updates:
        # Check if a customization record exists
        cursor.execute("SELECT id FROM customizations WHERE client_id = ?", (client_id,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing record
            customization_query = "UPDATE customizations SET " + ", ".join([f"{k} = ?" for k in customization_updates.keys()])
            customization_query += ", last_updated = ?"
            
            if 'updated_by' in client_data:
                customization_query += ", updated_by = ?"
                customization_values = list(customization_updates.values()) + [datetime.now().isoformat(), client_data['updated_by'], client_id]
            else:
                customization_values = list(customization_updates.values()) + [datetime.now().isoformat(), client_id]
            
            customization_query += " WHERE client_id = ?"
            
            cursor.execute(customization_query, customization_values)
        else:
            # Create new record
            customization_updates['client_id'] = client_id
            customization_updates['last_updated'] = datetime.now().isoformat()
            
            if 'updated_by' in client_data:
                customization_updates['updated_by'] = client_data['updated_by']
            
            columns = ', '.join(customization_updates.keys())
            placeholders = ', '.join(['?'] * len(customization_updates))
            
            cursor.execute(f"INSERT INTO customizations ({columns}) VALUES ({placeholders})", 
                           list(customization_updates.values()))
    
    # Log the change
    try:
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            client_data.get('updated_by'), 
            'update', 
            'client', 
            client_id, 
            json.dumps(client_data), 
            datetime.now().isoformat(),
            client_data.get('ip_address', 'unknown')
        ))
    except Exception as log_error:
        logging.warning(f"Could not create audit log: {log_error}")
    
    return {'status': 'success'}

@with_transaction
def create_client(conn, client_data, user_id):
    """Create a new client record"""
    cursor = conn.cursor()
    
    # Generate API key
    api_key = str(uuid.uuid4())
    
    # Prepare client data
    now = datetime.now().isoformat()
    
    # Extract/validate required fields
    business_name = client_data.get('business_name')
    business_domain = client_data.get('business_domain')
    contact_email = client_data.get('contact_email')
    
    if not business_name or not business_domain or not contact_email:
        return {'status': 'error', 'message': 'Missing required fields'}
    
    # Insert the client
    cursor.execute("""
        INSERT INTO clients (
            business_name, business_domain, contact_email, contact_phone,
            scanner_name, subscription_level, subscription_status,
            api_key, created_at, created_by, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        business_name,
        business_domain,
        contact_email,
        client_data.get('contact_phone', ''),
        client_data.get('scanner_name', ''),
        client_data.get('subscription', 'basic'),
        'active',
        api_key,
        now,
        user_id
    ))
    
    # Get the new client ID
    client_id = cursor.lastrowid
    
    # Insert customization data if provided
    customization_data = {
        'client_id': client_id,
        'primary_color': client_data.get('primary_color', '#FF6900'),
        'secondary_color': client_data.get('secondary_color', '#808588'),
        'last_updated': now,
        'updated_by': user_id
    }
    
    # Add optional customization fields if provided
    for field in ['logo_path', 'favicon_path', 'email_subject', 'email_intro', 'email_footer']:
        if field in client_data and client_data[field]:
            customization_data[field] = client_data[field]
    
    # Store default_scans as JSON string if provided
    if 'default_scans' in client_data and client_data['default_scans']:
        if isinstance(client_data['default_scans'], list):
            customization_data['default_scans'] = json.dumps(client_data['default_scans'])
        else:
            customization_data['default_scans'] = client_data['default_scans']
    
    # Insert customizations
    columns = ', '.join(customization_data.keys())
    placeholders = ', '.join(['?'] * len(customization_data))
    cursor.execute(f"INSERT INTO customizations ({columns}) VALUES ({placeholders})",
                  list(customization_data.values()))
    
    # Generate subdomain for scanner
    subdomain = business_name.lower().replace(' ', '-')
    subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
    
    # Check if subdomain exists, add random suffix if needed
    cursor.execute("SELECT id FROM deployed_scanners WHERE subdomain = ?", (subdomain,))
    if cursor.fetchone():
        import random
        subdomain = f"{subdomain}-{random.randint(100, 999)}"
    
    # Create a deployed scanner record
    cursor.execute("""
        INSERT INTO deployed_scanners (
            client_id, subdomain, deploy_status, deploy_date, 
            last_updated, template_version
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        client_id,
        subdomain,
        'pending',  # New scanners start as pending
        now,
        now,
        '1.0'
    ))
    
    scanner_id = cursor.lastrowid
    
    return {
        'status': 'success', 
        'client_id': client_id,
        'scanner_id': scanner_id,
        'api_key': api_key
    }

@with_transaction
def list_users(conn, page=1, per_page=10, filters=None):
    """
    List users with pagination and filtering
    
    Args:
        conn: Database connection
        page (int): Page number (1-indexed)
        per_page (int): Number of items per page
        filters (dict): Optional filters like {'role': 'admin', 'search': 'query', etc.}
    
    Returns:
        dict: Dictionary with users and pagination info
    """
    # Validate and sanitize parameters
    page = max(1, page)  # Ensure page is at least 1
    per_page = min(100, max(1, per_page))  # Between 1 and 100
    offset = (page - 1) * per_page
    
    # Default filters
    if filters is None:
        filters = {}
    
    # Build query
    query = """
        SELECT u.*, 
            (SELECT COUNT(*) FROM sessions WHERE user_id = u.id) as login_count
        FROM users u
    """
    count_query = "SELECT COUNT(*) as total FROM users"
    
    # Apply filters
    conditions = []
    params = []
    
    if 'search' in filters and filters['search']:
        search_term = f"%{filters['search']}%"
        conditions.append("(username LIKE ? OR email LIKE ? OR full_name LIKE ?)")
        params.extend([search_term, search_term, search_term])
    
    if 'role' in filters and filters['role']:
        conditions.append("role = ?")
        params.append(filters['role'])
    
    if 'active' in filters:
        conditions.append("active = ?")
        params.append(1 if filters['active'] else 0)
    
    # Add WHERE clause if conditions exist
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        count_query += " WHERE " + " AND ".join(conditions)
    
    # Add ORDER BY clause
    query += " ORDER BY id DESC"
    
    # Add LIMIT and OFFSET
    query += f" LIMIT {per_page} OFFSET {offset}"
    
    cursor = conn.cursor()
    
    # Get total count
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()['total']
    
    # Get current page data
    cursor.execute(query, params)
    users = [dict(row) for row in cursor.fetchall()]
    
    # Calculate pagination details
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    return {
        'users': users,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': total_pages
        }
    }

@with_transaction
def create_user(conn, username, email, password, role='client', full_name=''):
    """Create a new user"""
    cursor = conn.cursor()
    
    # Check if username or email already exists
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone():
        return {'status': 'error', 'message': 'Username or email already exists'}
    
    # Generate password hash
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000
    ).hex()
    
    # Insert the user
    cursor.execute("""
        INSERT INTO users (
            username, email, password_hash, salt, role, full_name, created_at, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        username,
        email,
        password_hash,
        salt,
        role,
        full_name,
        datetime.now().isoformat()
    ))
    
    user_id = cursor.lastrowid
    
    return {'status': 'success', 'user_id': user_id}

@with_transaction
def update_user(conn, user_id, user_data):
    """Update user details"""
    cursor = conn.cursor()
    
    # Check if username or email is being changed and if it conflicts
    if 'username' in user_data or 'email' in user_data:
        # Use a direct function call with the database connection
        current_data = get_user_by_id(conn, user_id)
        if not current_data:
            return {'status': 'error', 'message': 'User not found'}
            
        if 'username' in user_data and user_data['username'] != current_data['username']:
            cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", 
                          (user_data['username'], user_id))
            if cursor.fetchone():
                return {'status': 'error', 'message': 'Username already taken'}
                
        if 'email' in user_data and user_data['email'] != current_data['email']:
            cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", 
                          (user_data['email'], user_id))
            if cursor.fetchone():
                return {'status': 'error', 'message': 'Email already in use'}
    
    # Handle password update separately
    if 'password' in user_data and user_data['password']:
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            user_data['password'].encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        cursor.execute("""
            UPDATE users SET password_hash = ?, salt = ? WHERE id = ?
        """, (password_hash, salt, user_id))
        
        # Remove password from user_data after handling
        del user_data['password']
    
    # Update other fields
    update_fields = [k for k in user_data.keys() if k not in ['password']]
    
    if update_fields:
        query = "UPDATE users SET " + ", ".join([f"{field} = ?" for field in update_fields])
        query += " WHERE id = ?"
        
        values = [user_data[field] for field in update_fields] + [user_id]
        
        cursor.execute(query, values)
    
    return {'status': 'success'}

@with_transaction
def deactivate_user(conn, user_id):
    """Deactivate a user account"""
    cursor = conn.cursor()
    
    # Set user as inactive
    cursor.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
    
    # Terminate all active sessions
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    
    return {'status': 'success'}

@with_transaction
def list_deployed_scanners(conn, page=1, per_page=10, filters=None):
    """
    List deployed scanners with pagination and filtering
    
    Args:
        conn: Database connection
        page (int): Page number (1-indexed)
        per_page (int): Number of items per page
        filters (dict): Optional filters like {'status': 'deployed', 'search': 'query', etc.}
    
    Returns:
        dict: Dictionary with scanners and pagination info
    """
    # Validate and sanitize parameters
    page = max(1, page)  # Ensure page is at least 1
    per_page = min(100, max(1, per_page))  # Between 1 and 100
    offset = (page - 1) * per_page
    
    # Default filters
    if filters is None:
        filters = {}
    
    # Build query
    query = """
        SELECT ds.*, c.business_name, c.business_domain, c.scanner_name,
            (SELECT COUNT(*) FROM scan_history WHERE client_id = ds.client_id) as scan_count,
            (SELECT MAX(timestamp) FROM scan_history WHERE client_id = ds.client_id) as last_scan
        FROM deployed_scanners ds
        JOIN clients c ON ds.client_id = c.id
    """
    count_query = """
        SELECT COUNT(*) as total 
        FROM deployed_scanners ds
        JOIN clients c ON ds.client_id = c.id
    """
    
    # Apply filters
    conditions = []
    params = []
    
    if 'search' in filters and filters['search']:
        search_term = f"%{filters['search']}%"
        conditions.append("(c.business_name LIKE ? OR c.business_domain LIKE ? OR ds.subdomain LIKE ?)")
        params.extend([search_term, search_term, search_term])
    
    if 'status' in filters and filters['status']:
        conditions.append("ds.deploy_status = ?")
        params.append(filters['status'])
    
    if 'client_id' in filters and filters['client_id']:
        conditions.append("ds.client_id = ?")
        params.append(filters['client_id'])
    
    # Add WHERE clause if conditions exist
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        count_query += " WHERE " + " AND ".join(conditions)
    
    # Add ORDER BY clause
    query += " ORDER BY ds.id DESC"
    
    # Add LIMIT and OFFSET
    query += f" LIMIT {per_page} OFFSET {offset}"
    
    cursor = conn.cursor()
    
    # Get total count
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()['total']
    
    # Get current page data
    cursor.execute(query, params)
    scanners = [dict(row) for row in cursor.fetchall()]
    
    # Calculate pagination details
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    return {
        'scanners': scanners,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': total_pages
        }
    }

@with_transaction
def get_scanner_by_id(conn, scanner_id):
    """Get scanner details by ID"""
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ds.*, c.business_name, c.business_domain, c.scanner_name, c.subscription_level,
            (SELECT COUNT(*) FROM scan_history WHERE client_id = ds.client_id) as scan_count,
            (SELECT MAX(timestamp) FROM scan_history WHERE client_id = ds.client_id) as last_scan
        FROM deployed_scanners ds
        JOIN clients c ON ds.client_id = c.id
        WHERE ds.id = ?
    """, (scanner_id,))
    
    scanner = cursor.fetchone()
    
    if scanner:
        # Get customizations
        cursor.execute("""
            SELECT * FROM customizations
            WHERE client_id = ?
        """, (scanner['client_id'],))
        
        customizations = cursor.fetchone()
        
        scanner_dict = dict(scanner)
        
        if customizations:
            # Add customization data to scanner dict
            for key, value in dict(customizations).items():
                if key not in scanner_dict and key != 'id' and key != 'client_id':
                    scanner_dict[key] = value
        
        return scanner_dict
    else:
        return None

@with_transaction
def update_scanner(conn, scanner_id, scanner_data):
    """Update scanner configuration"""
    cursor = conn.cursor()
    
    # Check if scanner exists
    cursor.execute("SELECT id, client_id FROM deployed_scanners WHERE id = ?", (scanner_id,))
    scanner = cursor.fetchone()
    
    if not scanner:
        return {'status': 'error', 'message': 'Scanner not found'}
    
    # If updating subdomain, check if it's unique
    if 'subdomain' in scanner_data:
        cursor.execute("""
            SELECT id FROM deployed_scanners 
            WHERE subdomain = ? AND id != ?
        """, (scanner_data['subdomain'], scanner_id))
        
        if cursor.fetchone():
            return {'status': 'error', 'message': 'Subdomain already in use'}
    
    # Update scanner fields
    update_fields = scanner_data.keys()
    
    if update_fields:
        query = "UPDATE deployed_scanners SET " + ", ".join([f"{field} = ?" for field in update_fields])
        query += " WHERE id = ?"
        
        values = [scanner_data[field] for field in update_fields] + [scanner_id]
        
        cursor.execute(query, values)
    
    return {'status': 'success'}

@with_transaction
def regenerate_scanner_api_key(conn, scanner_id):
    """Regenerate API key for a scanner"""
    cursor = conn.cursor()
    
    # Get client ID for scanner
    cursor.execute("SELECT client_id FROM deployed_scanners WHERE id = ?", (scanner_id,))
    result = cursor.fetchone()
    
    if not result:
        return {'status': 'error', 'message': 'Scanner not found'}
    
    client_id = result[0]
    
    # Generate new API key
    new_api_key = str(uuid.uuid4())
    
    # Update client record with new API key
    cursor.execute("""
        UPDATE clients SET api_key = ? WHERE id = ?
    """, (new_api_key, client_id))
    
    return {'status': 'success', 'api_key': new_api_key}

def get_scan_history_by_client_id(client_id, limit=None):
    """Get scan history for a client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # First check if scan_history table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            # Fall back to scans table instead
            base_query = "SELECT * FROM scans WHERE target LIKE ? ORDER BY timestamp DESC"
            
            # Get client domain
            cursor.execute("SELECT business_domain FROM clients WHERE id = ?", (client_id,))
            client = cursor.fetchone()
            
            if client and client['business_domain']:
                domain = f"%{client['business_domain']}%"
                params = [domain]
            else:
                # If no domain found, return empty list
                conn.close()
                return []
        else:
            # Check if client_id column exists in scan_history
            cursor.execute("PRAGMA table_info(scan_history)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'client_id' in columns:
                base_query = "SELECT * FROM scan_history WHERE client_id = ? ORDER BY timestamp DESC"
                params = [client_id]
            else:
                # Fall back to scans table
                base_query = "SELECT * FROM scans WHERE target LIKE ? ORDER BY timestamp DESC"
                
                # Get client domain
                cursor.execute("SELECT business_domain FROM clients WHERE id = ?", (client_id,))
                client = cursor.fetchone()
                
                if client and client['business_domain']:
                    domain = f"%{client['business_domain']}%"
                    params = [domain]
                else:
                    # If no domain found, return empty list
                    conn.close()
                    return []
        
        # Add limit if provided
        if limit:
            base_query += " LIMIT ?"
            params.append(limit)
        
        cursor.execute(base_query, params)
        scan_history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return scan_history
    except Exception as e:
        logging.error(f"Error retrieving scan history for client: {e}")
        return []

@with_transaction
def toggle_scanner_status(conn, scanner_id):
    """Toggle scanner between deployed and inactive states"""
    cursor = conn.cursor()
    
    # Get current status
    cursor.execute("SELECT deploy_status FROM deployed_scanners WHERE id = ?", (scanner_id,))
    result = cursor.fetchone()
    
    if not result:
        return {'status': 'error', 'message': 'Scanner not found'}
    
    current_status = result[0]
    
    # Toggle status
    new_status = 'deployed' if current_status != 'deployed' else 'inactive'
    
    # Update status
    cursor.execute("""
        UPDATE deployed_scanners SET 
            deploy_status = ?,
            last_updated = ?
        WHERE id = ?
    """, (
        new_status,
        datetime.now().isoformat(),
        scanner_id
    ))
    
    return {'status': 'success', 'current_status': new_status}

@with_transaction
def get_scanner_stats(conn, scanner_id):
    """Get statistics for a scanner"""
    cursor = conn.cursor()
    
    # Get scanner info
    cursor.execute("SELECT client_id, deploy_date FROM deployed_scanners WHERE id = ?", (scanner_id,))
    scanner = cursor.fetchone()
    
    if not scanner:
        return {'status': 'error', 'message': 'Scanner not found'}
    
    client_id = scanner['client_id']
    
    # Get total scan count
    cursor.execute("SELECT COUNT(*) as total FROM scan_history WHERE client_id = ?", (client_id,))
    total_scans = cursor.fetchone()['total']
    
    # Get scans in last 24 hours
    twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).isoformat()
    cursor.execute("SELECT COUNT(*) as total FROM scan_history WHERE client_id = ? AND timestamp > ?", 
                  (client_id, twenty_four_hours_ago))
    scans_today = cursor.fetchone()['total']
    
    # Get scans in last 7 days
    seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
    cursor.execute("SELECT COUNT(*) as total FROM scan_history WHERE client_id = ? AND timestamp > ?", 
                  (client_id, seven_days_ago))
    scans_week = cursor.fetchone()['total']
    
    # Get scans in last 30 days
    thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
    cursor.execute("SELECT COUNT(*) as total FROM scan_history WHERE client_id = ? AND timestamp > ?", 
                  (client_id, thirty_days_ago))
    scans_month = cursor.fetchone()['total']
    
    # Get monthly scan trends (past 6 months)
    monthly_trend = []
    for i in range(5, -1, -1):
        month_start = (datetime.now() - timedelta(days=i*30+30)).isoformat()[0:7] + '-01'
        next_month_start = (datetime.now() - timedelta(days=(i-1)*30+30)).isoformat()[0:7] + '-01'
        if i == 0:
            next_month_start = (datetime.now() + timedelta(days=30)).isoformat()[0:7] + '-01'
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM scan_history 
            WHERE client_id = ? AND timestamp >= ? AND timestamp < ?
        """, (client_id, month_start, next_month_start))
        
        month_name = datetime.fromisoformat(month_start).strftime('%b')
        count = cursor.fetchone()['count']
        monthly_trend.append({'month': month_name, 'count': count})
    
    # Get last scan details
    cursor.execute("""
        SELECT * FROM scan_history 
        WHERE client_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 1
    """, (client_id,))
    last_scan = cursor.fetchone()
    last_scan_details = dict(last_scan) if last_scan else None
    
    return {
        'total_scans': total_scans,
        'scans_today': scans_today,
        'scans_week': scans_week,
        'scans_month': scans_month,
        'monthly_trend': monthly_trend,
        'last_scan': last_scan_details,
        'status': 'success'
    }

@with_transaction
def get_scan_history(conn, scanner_id, page=1, per_page=10):
    """Get scan history for a scanner"""
    cursor = conn.cursor()
    
    # Get client ID for scanner
    cursor.execute("SELECT client_id FROM deployed_scanners WHERE id = ?", (scanner_id,))
    result = cursor.fetchone()
    
    if not result:
        return {'status': 'error', 'message': 'Scanner not found'}
    
    client_id = result[0]
    
    # Paginate scan history
    offset = (page - 1) * per_page
    
    cursor.execute("""
        SELECT * FROM scan_history 
        WHERE client_id = ? 
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """, (client_id, per_page, offset))
    
    scans = [dict(row) for row in cursor.fetchall()]
    
    # Get total count
    cursor.execute("SELECT COUNT(*) as total FROM scan_history WHERE client_id = ?", (client_id,))
    total_count = cursor.fetchone()['total']
    
    # Calculate total pages
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        'scans': scans,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': total_pages
        },
        'status': 'success'
    }

@with_transaction
def list_subscriptions(conn, page=1, per_page=10, filters=None):
    """
    List subscription details with pagination and filtering
    
    Args:
        conn: Database connection
        page (int): Page number (1-indexed)
        per_page (int): Number of items per page
        filters (dict): Optional filters
    
    Returns:
        dict: Dictionary with subscriptions and pagination info
    """
    # Validate and sanitize parameters
    page = max(1, page)  # Ensure page is at least 1
    per_page = min(100, max(1, per_page))  # Between 1 and 100
    offset = (page - 1) * per_page
    
    # Default filters
    if filters is None:
        filters = {}
    
    # Build query to get subscription information from clients table
    query = """
        SELECT c.id, c.business_name, c.business_domain, c.contact_email,
            c.subscription_level, c.subscription_status, c.subscription_start, c.subscription_end,
            c.created_at, cb.billing_cycle, cb.amount, cb.next_billing_date
        FROM clients c
        LEFT JOIN client_billing cb ON c.id = cb.client_id
        WHERE c.active = 1
    """
    count_query = "SELECT COUNT(*) as total FROM clients WHERE active = 1"
    
    # Apply filters
    conditions = []
    params = []
    
    if 'search' in filters and filters['search']:
        search_term = f"%{filters['search']}%"
        # Add WHERE clause to the main query
        query += " AND (c.business_name LIKE ? OR c.business_domain LIKE ? OR c.contact_email LIKE ?)"
        params.extend([search_term, search_term, search_term])
        # Add WHERE clause to the count query
        count_query += " AND (business_name LIKE ? OR business_domain LIKE ? OR contact_email LIKE ?)"
        params.extend([search_term, search_term, search_term])
    
    if 'level' in filters and filters['level']:
        # Add to main query
        query += " AND c.subscription_level = ?"
        params.append(filters['level'])
        # Add to count query
        count_query += " AND subscription_level = ?"
        params.append(filters['level'])
    
    if 'status' in filters and filters['status']:
        # Add to main query
        query += " AND c.subscription_status = ?"
        params.append(filters['status'])
        # Add to count query
        count_query += " AND subscription_status = ?"
        params.append(filters['status'])
    
    # Add ORDER BY clause
    query += " ORDER BY c.id DESC"
    
    # Add LIMIT and OFFSET
    query += f" LIMIT {per_page} OFFSET {offset}"
    
    cursor = conn.cursor()
    
    # Get total count
    cursor.execute(count_query, params[:len(params)//2] if 'search' in filters else params)
    total_count = cursor.fetchone()['total']
    
    # Get current page data
    cursor.execute(query, params)
    subscriptions = [dict(row) for row in cursor.fetchall()]
    
    # Get recent transactions for each subscription
    for sub in subscriptions:
        cursor.execute("""
            SELECT * FROM billing_transactions
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT 3
        """, (sub['id'],))
        sub['recent_transactions'] = [dict(row) for row in cursor.fetchall()]
        
        # Calculate subscription metrics
        # For example, days until next billing
        if sub.get('next_billing_date'):
            try:
                next_date = datetime.fromisoformat(sub['next_billing_date'])
                today = datetime.now()
                days_remaining = (next_date - today).days
                sub['days_until_billing'] = max(0, days_remaining)
            except (ValueError, TypeError):
                sub['days_until_billing'] = None
    
    # Calculate pagination details
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    return {
        'subscriptions': subscriptions,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': total_pages
        }
    }

@with_transaction
def get_client_stats(conn, client_id):
    """Get detailed statistics for a client"""
    cursor = conn.cursor()
    
    # Get scanner count
    cursor.execute("""
        SELECT COUNT(*) as scanner_count
        FROM deployed_scanners
        WHERE client_id = ?
    """, (client_id,))
    scanner_count = cursor.fetchone()['scanner_count']
    
    # Get total scan count
    cursor.execute("""
        SELECT COUNT(*) as scan_count
        FROM scan_history
        WHERE client_id = ?
    """, (client_id,))
    scan_count = cursor.fetchone()['scan_count']
    
    # Get scan count for different periods
    today = datetime.now().date().isoformat()
    cursor.execute("""
        SELECT COUNT(*) as today_count
        FROM scan_history
        WHERE client_id = ? AND date(timestamp) = ?
    """, (client_id, today))
    scans_today = cursor.fetchone()['today_count']
    
    # Last 7 days
    seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as week_count
        FROM scan_history
        WHERE client_id = ? AND timestamp > ?
    """, (client_id, seven_days_ago))
    scans_week = cursor.fetchone()['week_count']
    
    # Last 30 days
    thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as month_count
        FROM scan_history
        WHERE client_id = ? AND timestamp > ?
    """, (client_id, thirty_days_ago))
    scans_month = cursor.fetchone()['month_count']
    
    # Get daily scan activity for last 30 days
    cursor.execute("""
        SELECT date(timestamp) as scan_date, COUNT(*) as count
        FROM scan_history
        WHERE client_id = ? AND timestamp > ?
        GROUP BY date(timestamp)
        ORDER BY scan_date
    """, (client_id, thirty_days_ago))
    daily_activity = [dict(row) for row in cursor.fetchall()]
    
    # Get most recent scans
    cursor.execute("""
        SELECT *
        FROM scan_history
        WHERE client_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
    """, (client_id,))
    recent_scans = [dict(row) for row in cursor.fetchall()]
    
    # Get subscription information
    cursor.execute("""
        SELECT subscription_level, subscription_status, subscription_start, subscription_end
        FROM clients
        WHERE id = ?
    """, (client_id,))
    subscription = dict(cursor.fetchone())
    
    # Get billing information
    cursor.execute("""
        SELECT *
        FROM client_billing
        WHERE client_id = ?
    """, (client_id,))
    billing = cursor.fetchone()
    billing_info = dict(billing) if billing else {}
    
    # Get recent transactions
    cursor.execute("""
        SELECT *
        FROM billing_transactions
        WHERE client_id = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (client_id,))
    recent_transactions = [dict(row) for row in cursor.fetchall()]
    
    return {
        'scanner_count': scanner_count,
        'scan_count': scan_count,
        'scans_today': scans_today,
        'scans_week': scans_week,
        'scans_month': scans_month,
        'daily_activity': daily_activity,
        'recent_scans': recent_scans,
        'subscription': subscription,
        'billing': billing_info,
        'recent_transactions': recent_transactions
    }

@with_transaction
def log_scan(conn, client_id, scan_id, target):
    """Log a scan in the scan history table"""
    cursor = conn.cursor()
    
    # Insert scan record
    cursor.execute("""
        INSERT INTO scan_history (
            client_id, scan_id, timestamp, target, scan_type, status
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        client_id,
        scan_id,
        datetime.now().isoformat(),
        target,
        'security_scan',  # Default scan type
        'completed'  # Assuming scan completed successfully
    ))
    
    return {'status': 'success'}

@with_transaction
def check_username_availability(conn, username):
    """Check if a username is available"""
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    return {'available': result is None}

@with_transaction
def check_email_availability(conn, email):
    """Check if an email is available"""
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    
    return {'available': result is None}

@with_transaction
def verify_session(conn, session_token):
    """Verify a session token and return user info"""
    if not session_token:
        return {'status': 'error', 'message': 'No session token provided'}
    
    cursor = conn.cursor()
    
    # Get session with user info
    cursor.execute("""
        SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND s.expires_at > ?
          AND u.active = 1
    """, (session_token, datetime.now().isoformat()))
    
    session = cursor.fetchone()
    
    if not session:
        return {'status': 'error', 'message': 'Invalid or expired session'}
    
    # Convert to dict but exclude sensitive fields
    user_data = {
        'id': session['user_id'],
        'username': session['username'],
        'email': session['email'],
        'role': session['role'],
        'full_name': session['full_name']
    }
    
    return {'status': 'success', 'user': user_data}

@with_transaction
def get_login_stats(conn):
    """Get login statistics for admin dashboard"""
    cursor = conn.cursor()
    
    # Get active users count
    cursor.execute("SELECT COUNT(*) as count FROM users WHERE active = 1")
    active_users = cursor.fetchone()['count']
    
    # Get logins today
    today = datetime.now().date().isoformat()
    cursor.execute("""
        SELECT COUNT(*) as count FROM sessions
        WHERE date(created_at) = ?
    """, (today,))
    logins_today = cursor.fetchone()['count']
    
    # Get logins this week
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as count FROM sessions
        WHERE created_at > ?
    """, (week_ago,))
    logins_week = cursor.fetchone()['count']
    
    # Get logins this month
    month_ago = (datetime.now() - timedelta(days=30)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) as count FROM sessions
        WHERE created_at > ?
    """, (month_ago,))
    logins_month = cursor.fetchone()['count']
    
    # Get new users this week
    cursor.execute("""
        SELECT COUNT(*) as count FROM users
        WHERE created_at > ? AND active = 1
    """, (week_ago,))
    new_users_week = cursor.fetchone()['count']
    
    # Get new users this month
    cursor.execute("""
        SELECT COUNT(*) as count FROM users
        WHERE created_at > ? AND active = 1
    """, (month_ago,))
    new_users_month = cursor.fetchone()['count']
    
    # Get user roles distribution
    cursor.execute("""
        SELECT role, COUNT(*) as count FROM users
        WHERE active = 1
        GROUP BY role
    """)
    roles = cursor.fetchall()
    user_roles = {row['role']: row['count'] for row in roles}
    
    # Get recent logins
    cursor.execute("""
        SELECT s.created_at, s.ip_address, u.id, u.username, u.email, u.role
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 10
    """)
    recent_logins = [dict(row) for row in cursor.fetchall()]
    
    return {
        'status': 'success',
        'data': {
            'active_users': active_users,
            'logins_today': logins_today,
            'logins_week': logins_week,
            'logins_month': logins_month,
            'new_users_week': new_users_week,
            'new_users_month': new_users_month,
            'user_roles': user_roles,
            'recent_logins': recent_logins
        }
    }
    
def get_client_by_user_id(user_id):
    """Get client data for a specific user"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                id,
                business_name,
                business_domain,
                contact_email,
                contact_phone,
                scanner_name,
                subscription_level,
                primary_color,
                secondary_color,
                email_subject,
                email_intro
            FROM clients 
            WHERE user_id = ? AND active = 1
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (user_id,))
        
        result = cursor.fetchone()
        
        if result:
            return {
                'id': result[0],
                'business_name': result[1],
                'business_domain': result[2],
                'contact_email': result[3],
                'contact_phone': result[4],
                'scanner_name': result[5],
                'subscription_level': result[6],
                'primary_color': result[7] if len(result) > 7 else '#FF6900',
                'secondary_color': result[8] if len(result) > 8 else '#808588',
                'email_subject': result[9] if len(result) > 9 else 'Your Security Scan Report',
                'email_intro': result[10] if len(result) > 10 else ''
            }
        return None
        
    except Exception as e:
        import logging
        logging.error(f"Error getting client by user_id: {str(e)}")
        return None
    finally:
        if 'conn' in locals():
            conn.close()
def get_db_connection():
    """Get a new database connection
    
    Returns:
        sqlite3.Connection: Database connection with row factory enabled
    """
    conn = sqlite3.connect(CLIENT_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_deployed_scanners_by_client_id(client_id, page=1, per_page=10, filters=None):
    """Get list of deployed scanners for a client with pagination and filtering"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculate offset for pagination
        offset = (page - 1) * per_page
        
        # Base query - Use deployed_scanners table
        query = "SELECT * FROM deployed_scanners WHERE client_id = ?"
        params = [client_id]
        
        # Apply filters if provided
        if filters:
            if 'status' in filters and filters['status']:
                query += " AND deploy_status = ?"
                params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                query += " AND (domain LIKE ? OR subdomain LIKE ?)"
                search_term = f"%{filters['search']}%"
                params.append(search_term)
                params.append(search_term)
        
        # Add sorting and pagination
        query += " ORDER BY last_updated DESC LIMIT ? OFFSET ?"
        params.append(per_page)
        params.append(offset)
        
        # Execute query for scanners
        cursor.execute(query, params)
        scanners = [dict(row) for row in cursor.fetchall()]
        
        # Get total count for pagination
        count_query = "SELECT COUNT(*) FROM deployed_scanners WHERE client_id = ?"
        count_params = [client_id]
        
        # Apply the same filters to count query
        if filters:
            if 'status' in filters and filters['status']:
                count_query += " AND deploy_status = ?"
                count_params.append(filters['status'])
            
            if 'search' in filters and filters['search']:
                count_query += " AND (domain LIKE ? OR subdomain LIKE ?)"
                search_term = f"%{filters['search']}%"
                count_params.append(search_term)
                count_params.append(search_term)
        
        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()[0]
        
        conn.close()
        
        # Calculate pagination metadata
        total_pages = (total_count + per_page - 1) // per_page
        
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
        logging.error(f"Error retrieving scanners for client: {e}")
        return {
            'scanners': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 0
            }
        }

def get_scan_history_by_client_id(client_id, limit=None):
    """Get scan history for a client"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if scan_history table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            # Fall back to scans table if scan_history doesn't exist
            base_query = "SELECT * FROM scans WHERE target LIKE ? ORDER BY timestamp DESC"
            
            # Get client domain
            cursor.execute("SELECT business_domain FROM clients WHERE id = ?", (client_id,))
            client = cursor.fetchone()
            
            if client and client['business_domain']:
                domain = f"%{client['business_domain']}%"
                params = [domain]
            else:
                conn.close()
                return []
        else:
            # Check what columns exist in scan_history
            cursor.execute("PRAGMA table_info(scan_history)")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'client_id' in columns:
                base_query = "SELECT * FROM scan_history WHERE client_id = ? ORDER BY timestamp DESC"
                params = [client_id]
            else:
                # Try to join with clients table
                base_query = """
                SELECT sh.* FROM scan_history sh
                JOIN clients c ON sh.target LIKE '%' || c.business_domain || '%'
                WHERE c.id = ? ORDER BY sh.timestamp DESC
                """
                params = [client_id]
        
        # Add limit if provided
        if limit:
            base_query += " LIMIT ?"
            params.append(limit)
        
        cursor.execute(base_query, params)
        scan_history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return scan_history
    except Exception as e:
        logging.error(f"Error retrieving scan history for client: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return []

@with_transaction
def get_client_statistics(conn, cursor, client_id):
    """Get comprehensive statistics for a client"""
    try:
        stats = {}
        
        # Get scanner count
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM deployed_scanners
            WHERE client_id = ? AND deploy_status = 'deployed'
        """, (client_id,))
        stats['scanners_count'] = cursor.fetchone()['count']
        
        # Get total scans - handle both scan_history and scans tables
        try:
            # Check if scan_history table exists and has client_id column
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(scan_history)")
                columns = [column[1] for column in cursor.fetchall()]
                if 'client_id' in columns:
                    cursor.execute("""
                        SELECT COUNT(*) as count
                        FROM scan_history
                        WHERE client_id = ?
                    """, (client_id,))
                    stats['total_scans'] = cursor.fetchone()['count']
                else:
                    stats['total_scans'] = 0
            else:
                stats['total_scans'] = 0
        except Exception as e:
            logging.warning(f"Error getting scan count: {e}")
            stats['total_scans'] = 0
        
        # Get average security score (placeholder for now)
        stats['avg_security_score'] = 75  # Default numeric value
        
        # Get reports count (same as total scans for now)
        stats['reports_count'] = stats['total_scans']
        
        # Get recent scans (if applicable)
        stats['recent_scans'] = []
        
        return stats
    except Exception as e:
        logging.error(f"Error getting client statistics: {e}")
        return {
            'scanners_count': 0,
            'total_scans': 0,
            'avg_security_score': 0,  # Numeric value
            'reports_count': 0,
            'recent_scans': []
        }
def log_scan(client_id, scan_id=None, target=None, scan_type='standard'):
    """Log a scan to the database"""
    try:
        if not scan_id:
            scan_id = str(uuid.uuid4())
            
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Get current timestamp
        timestamp = datetime.datetime.now().isoformat()
        
        # Insert scan record
        cursor.execute('''
            INSERT INTO scans (
                scan_id, client_id, timestamp, target, scan_type
            ) VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, client_id, timestamp, target, scan_type))
        
        conn.commit()
        conn.close()
        
        return {
            'status': 'success',
            'scan_id': scan_id
        }
    except Exception as e:
        logging.error(f"Error logging scan: {e}")
        return {
            'status': 'error',
            'message': f"Failed to log scan: {str(e)}"
        }

def regenerate_api_key(client_id):
    """Regenerate API key for a client"""
    try:
        # Generate a new API key
        new_api_key = str(uuid.uuid4())
        
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Update client record with new API key
        cursor.execute('''
            UPDATE clients
            SET api_key = ?
            WHERE id = ?
        ''', (new_api_key, client_id))
        
        # Check if update was successful
        if cursor.rowcount == 0:
            conn.close()
            return {
                'status': 'error',
                'message': 'Client not found'
            }
        
        conn.commit()
        conn.close()
        
        return {
            'status': 'success',
            'message': 'API key regenerated successfully',
            'api_key': new_api_key
        }
    except Exception as e:
        logging.error(f"Error regenerating API key: {e}")
        return {
            'status': 'error',
            'message': f"Failed to regenerate API key: {str(e)}"
        }



def register_client(*args):
    """
    Register a client for a user - wrapper function to handle both calling conventions
    
    This function can be called either with:
    - (conn, cursor, user_id, business_data) when used with @with_transaction
    - (user_id, business_data) when called directly
    
    Returns:
        dict: Client registration result
    """
    # Handle different argument counts
    if len(args) == 4:
        # Called with (conn, cursor, user_id, business_data)
        conn, cursor, user_id, business_data = args
        # Call the internal implementation
        return _register_client_impl(conn, cursor, user_id, business_data)
    elif len(args) == 2:
        # Called with (user_id, business_data)
        user_id, business_data = args
        # Create connection and call the implementation
        try:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            result = _register_client_impl(conn, cursor, user_id, business_data)
            
            if result["status"] == "success":
                conn.commit()
            else:
                conn.rollback()
                
            conn.close()
            return result
        except Exception as e:
            logging.error(f"Database error in register_client: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return {"status": "error", "message": str(e)}
    else:
        # Invalid number of arguments
        return {"status": "error", "message": f"register_client() takes 2 or 4 arguments but {len(args)} were given"}

def _register_client_impl(conn, cursor, user_id, business_data):
    """
    Internal implementation of client registration
    
    Args:
        conn: Database connection
        cursor: Database cursor
        user_id (int): User ID
        business_data (dict): Business information
        
    Returns:
        dict: Client registration result
    """
    try:
        # Check for required fields
        if not business_data.get('business_name') or not business_data.get('business_domain') or not business_data.get('contact_email'):
            return {"status": "error", "message": "Business name, domain, and contact email are required"}
        
        # Check if user exists
        cursor.execute('SELECT id, role FROM users WHERE id = ? AND active = 1', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return {"status": "error", "message": "User not found or inactive"}
        
        # Check if client already exists for this user
        cursor.execute('SELECT id FROM clients WHERE user_id = ?', (user_id,))
        existing_client = cursor.fetchone()
        
        if existing_client:
            return {"status": "error", "message": "Client already registered for this user"}
        
        # Generate API key
        api_key = secrets.token_hex(16)
        
        # Insert client record
        now = datetime.now().isoformat()
        cursor.execute('''
        INSERT INTO clients (
            user_id, business_name, business_domain, contact_email, contact_phone,
            scanner_name, subscription_level, subscription_status, subscription_start,
            api_key, created_at, created_by, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            user_id,
            business_data.get('business_name'),
            business_data.get('business_domain'),
            business_data.get('contact_email'),
            business_data.get('contact_phone', ''),
            business_data.get('scanner_name', business_data.get('business_name') + ' Scanner'),
            business_data.get('subscription_level', 'basic'),
            'active',
            now,
            api_key,
            now,
            user_id
        ))
        
        client_id = cursor.lastrowid
        
        # Insert customization record
        cursor.execute('''
        INSERT INTO customizations (
            client_id, primary_color, secondary_color, email_subject, email_intro, 
            default_scans, last_updated, updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            business_data.get('primary_color', '#FF6900'),
            business_data.get('secondary_color', '#808588'),
            business_data.get('email_subject', 'Your Security Scan Report'),
            business_data.get('email_intro', 'Thank you for using our security scanner.'),
            json.dumps(business_data.get('default_scans', ['network', 'web', 'email', 'system'])),
            now,
            user_id
        ))
        
        # Create a deployed scanner record with sanitized subdomain
        subdomain = business_data.get('business_name', '').lower()
        # Clean up subdomain to be URL-friendly
        subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
        # Remove consecutive dashes and ensure it doesn't start/end with a dash
        subdomain = '-'.join(filter(None, subdomain.split('-')))
        
        # Handle duplicates by appending client_id if needed
        cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
        if cursor.fetchone():
            subdomain = f"{subdomain}-{client_id}"
        
        cursor.execute('''
        INSERT INTO deployed_scanners 
        (client_id, subdomain, deploy_status, deploy_date, last_updated, template_version)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            subdomain,
            'pending',
            now,
            now,
            '1.0'
        ))
        
        # Log the action
        try:
            cursor.execute('''
            INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                'create_client',
                'client',
                client_id,
                json.dumps(business_data),
                now
            ))
        except Exception as log_error:
            logging.warning(f"Could not add audit log: {str(log_error)}")
        
        # Log successful registration
        logging.info(f"Registered client for user_id {user_id}: {business_data.get('business_name')}")
        
        return {
            "status": "success", 
            "client_id": client_id, 
            "message": "Client registered successfully",
            "api_key": api_key
        }
        
    except Exception as e:
        logging.error(f"Client registration error: {str(e)}")
        return {"status": "error", "message": str(e)}
        
# Run database initialization
def init_db():
    """Initialize the database with schema and ensure columns exist"""
    try:
        # Check if the schema.sql file exists
        if os.path.exists('schema.sql'):
            logging.info("Initializing database from schema.sql...")
            
            # Initialize from schema file
            with open('schema.sql', 'r') as f:
                schema = f.read()
            
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.executescript(schema)
            conn.commit()
            logging.info("Schema executed successfully")
        else:
            # If schema file doesn't exist, try to run the init_client_db function
            logging.info("No schema.sql found, initializing from client_db code...")
            result = init_client_db()
            if result and isinstance(result, dict) and result.get("status") == "success":
                logging.info("Database initialized successfully from client_db")
            else:
                logging.info("Database initialization completed from client_db")
        
        # Now check if the users table exists before trying to add columns
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        users_table_exists = cursor.fetchone() is not None
        
        if users_table_exists:
            # Check if the full_name column exists
            cursor.execute("PRAGMA table_info(users)")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            
            if 'full_name' not in column_names:
                logging.info("Adding 'full_name' column to users table...")
                cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
                conn.commit()
                logging.info("'full_name' column added successfully")
        else:
            logging.info("Users table doesn't exist yet - skipping column check")
        
        # Check if clients table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clients'")
        clients_table_exists = cursor.fetchone() is not None
        
        if clients_table_exists:
            # Check if the user_id column exists in clients table
            cursor.execute("PRAGMA table_info(clients)")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            
            if 'user_id' not in column_names:
                logging.info("Adding 'user_id' column to clients table...")
                cursor.execute("ALTER TABLE clients ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
                conn.commit()
                logging.info("'user_id' column added successfully")
        else:
            logging.info("Clients table doesn't exist yet - skipping column check")
        
        conn.close()
        logging.info("Database initialization completed")
        return True
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
        logging.debug(traceback.format_exc())
        return False

# This version is designed to work with the @with_transaction decorator

@with_transaction
# Modify the init_client_db function in client_db.py to make cursor optional:

def init_client_db(cursor=None):
    """Initialize the client database with required tables
    
    Args:
        cursor: Optional database cursor. If not provided, a new connection will be created.
        
    Returns:
        Dict with status and message
    """
    close_conn = False
    conn = None
    
    try:
        # If cursor wasn't provided, create a new connection and cursor
        if cursor is None:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            close_conn = True
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'client',
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            active INTEGER DEFAULT 1
        )
        ''')
        
        # Create other tables...
        # (your existing table creation code)
        
        # Commit changes if we created our own connection
        if close_conn and conn:
            conn.commit()
            
        return {'status': 'success', 'message': 'Client database initialized successfully'}
        
    except Exception as e:
        if close_conn and conn:
            conn.rollback()
        logging.error(f"Error initializing client database: {e}")
        return {'status': 'error', 'message': str(e)}
    finally:
        # Close connection if we created it
        if close_conn and conn:
            conn.close()
        
def ensure_full_name_column():
    """Ensure the full_name column exists in the users table"""
    try:
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if the full_name column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        if 'full_name' not in column_names:
            logging.info("Adding 'full_name' column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            conn.commit()
            logging.info("'full_name' column added successfully")
        else:
            logging.info("'full_name' column already exists in users table")
        
        conn.close()
        return True
    except Exception as e:
        logging.error(f"Error ensuring full_name column: {e}")
        logging.debug(traceback.format_exc())
        return False
        
# Enhanced user management functions
@with_transaction
def create_user(conn, cursor, username, email, password, role='client', created_by=None):
    """Create a new user with enhanced validation and security"""
    # Validate input
    if not username or not email or not password:
        return {"status": "error", "message": "All fields are required"}
    
    if len(password) < 8:
        return {"status": "error", "message": "Password must be at least 8 characters"}
    
    # Check if username or email already exists
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
    existing_user = cursor.fetchone()
    
    if existing_user:
        return {"status": "error", "message": "Username or email already exists"}
    
    # Create salt and hash password (improved security)
    salt = secrets.token_hex(16)
    # Use stronger hashing with iterations
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000  # More iterations for better security
    ).hex()
    
    # Insert the user
    cursor.execute('''
    INSERT INTO users (username, email, password_hash, salt, role, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, email, password_hash, salt, role, datetime.now().isoformat()))
    
    user_id = cursor.lastrowid
    
    # Log the action if created_by is provided
    if created_by:
        log_action(conn, cursor, created_by, 'create', 'user', user_id, 
                  {'username': username, 'email': email, 'role': role})
    
    return {"status": "success", "user_id": user_id}

@with_transaction
def get_deployed_scanners(conn, cursor, page=1, per_page=10, filters=None):
    """Get list of deployed scanners with pagination and filtering"""
    offset = (page - 1) * per_page
    
    # Start with base query
    query = '''
    SELECT ds.*, c.business_name, c.business_domain, c.scanner_name, c.created_at, c.active
    FROM deployed_scanners ds
    JOIN clients c ON ds.client_id = c.id
    '''
    
    # Add filter conditions if provided
    params = []
    where_clauses = []
    
    if filters:
        if 'status' in filters and filters['status']:
            where_clauses.append('ds.deploy_status = ?')
            params.append(filters['status'])
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append('(c.business_name LIKE ? OR c.business_domain LIKE ? OR ds.subdomain LIKE ?)')
            params.extend([search_term, search_term, search_term])
    
    # Construct WHERE clause if needed
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Add order by and pagination
    query += ' ORDER BY ds.id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Execute query
    cursor.execute(query, params)
    scanners = [dict(row) for row in cursor.fetchall()]
    
    # Count total records for pagination
    count_query = 'SELECT COUNT(*) FROM deployed_scanners ds JOIN clients c ON ds.client_id = c.id'
    if where_clauses:
        count_query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Remove pagination params and execute count query
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    
    return {
        "status": "success",
        "scanners": scanners,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def update_scanner_config(conn, cursor, scanner_id, scanner_data, user_id):
    """Update scanner configuration"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Update client table if scanner_name is provided
    if 'scanner_name' in scanner_data and scanner_data['scanner_name']:
        cursor.execute('''
        UPDATE clients
        SET scanner_name = ?, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (scanner_data['scanner_name'], datetime.now().isoformat(), user_id, client_id))
    
    # Update customizations table
    custom_fields = []
    custom_values = []
    
    # Map fields to database columns for customizations table
    custom_mapping = {
        'primary_color': 'primary_color',
        'secondary_color': 'secondary_color',
        'logo_path': 'logo_path',
        'favicon_path': 'favicon_path',
        'email_subject': 'email_subject',
        'email_intro': 'email_intro'
    }
    
    for key, db_field in custom_mapping.items():
        if key in scanner_data:
            custom_fields.append(f"{db_field} = ?")
            custom_values.append(scanner_data[key])
    
    # Handle default_scans separately as it needs to be JSON
    if 'default_scans' in scanner_data:
        custom_fields.append("default_scans = ?")
        custom_values.append(json.dumps(scanner_data['default_scans']))
    
    # Always update last_updated and updated_by
    custom_fields.append("last_updated = ?")
    custom_values.append(datetime.now().isoformat())
    custom_fields.append("updated_by = ?")
    custom_values.append(user_id)
    
    # Check if customization record exists
    cursor.execute('SELECT id FROM customizations WHERE client_id = ?', (client_id,))
    customization = cursor.fetchone()
    
    if customization and custom_fields:
        # Update existing record
        query = f'''
        UPDATE customizations 
        SET {', '.join(custom_fields)}
        WHERE client_id = ?
        '''
        custom_values.append(client_id)
        cursor.execute(query, custom_values)
    elif custom_fields:
        # Insert new record
        fields = [db_field for key, db_field in custom_mapping.items() if key in scanner_data]
        if 'default_scans' in scanner_data:
            fields.append('default_scans')
        fields.extend(['client_id', 'last_updated', 'updated_by'])
        
        values = custom_values
        values.append(client_id)
        values.append(datetime.now().isoformat())
        values.append(user_id)
        
        query = f'''
        INSERT INTO customizations 
        ({', '.join(fields)})
        VALUES ({', '.join(['?'] * len(fields))})
        '''
        cursor.execute(query, values)
    
    # Update deployed_scanners table
    cursor.execute('''
    UPDATE deployed_scanners
    SET last_updated = ?
    WHERE id = ?
    ''', (datetime.now().isoformat(), scanner_id))
    
    # Update scanner files
    from scanner_template import update_scanner
    update_scanner(client_id, scanner_data)
    
    # Log the update
    log_action(conn, cursor, user_id, 'update', 'scanner', scanner_id, scanner_data)
    
    return {"status": "success", "scanner_id": scanner_id}

@with_transaction
def update_scanner_status(conn, cursor, scanner_id, status, user_id):
    """Update scanner status"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Update status
    cursor.execute('''
    UPDATE deployed_scanners
    SET deploy_status = ?, last_updated = ?
    WHERE id = ?
    ''', (status, datetime.now().isoformat(), scanner_id))
    
    # Also update client active status if needed
    if status == 'inactive':
        cursor.execute('''
        UPDATE clients
        SET active = 0, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user_id, client_id))
    elif status == 'deployed':
        cursor.execute('''
        UPDATE clients
        SET active = 1, updated_at = ?, updated_by = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), user_id, client_id))
    
    # Log the action
    log_action(conn, cursor, user_id, 'update_status', 'scanner', scanner_id, {'status': status})
    
    return {"status": "success"}

@with_transaction
def regenerate_scanner_api_key(conn, cursor, scanner_id, user_id):
    """Regenerate API key for a scanner"""
    # Get scanner details
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return {"status": "error", "message": "Scanner not found"}
    
    client_id = row['client_id']
    
    # Use existing regenerate_api_key function
    result = regenerate_api_key(client_id)
    
    if result['status'] == 'success':
        # Log the action
        log_action(conn, cursor, user_id, 'regenerate_api_key', 'scanner', scanner_id, None)
    
    return result

@with_transaction
def get_scanner_scan_history(conn, cursor, scanner_id, limit=100):
    """Get scan history for a specific scanner"""
    # Get client_id from scanner_id
    cursor.execute('SELECT client_id FROM deployed_scanners WHERE id = ?', (scanner_id,))
    row = cursor.fetchone()
    
    if not row:
        return []
    
    client_id = row['client_id']
    
    # Get scan history for this client
    cursor.execute('''
    SELECT * FROM scan_history
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT ?
    ''', (client_id, limit))
    
    scans = [dict(row) for row in cursor.fetchall()]
    
    return scans

# Improved authentication with better security
@with_transaction
def authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
    """Authenticate a user with enhanced security and debug logging"""
    try:
        logging.debug(f"Authentication attempt for: {username_or_email} from IP: {ip_address}")
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find user by username or email
        cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ?) AND active = 1
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if not user:
            logging.warning(f"Authentication failed: User not found: {username_or_email}")
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Verify password
        try:
            # Use pbkdf2_hmac if salt exists (new format)
            salt = user['salt']
            stored_hash = user['password_hash']
            
            # Log for debugging (don't log this in production)
            logging.debug(f"Authenticating {user['username']} (ID: {user['id']}) with salt: {salt[:5]}...")
            
            # Compute hash with pbkdf2
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000  # Same iterations as used for storing
            ).hex()
            
            password_correct = (password_hash == stored_hash)
            logging.debug(f"Password verification result: {password_correct}")
        except Exception as pw_error:
            # Fallback to simple hash if pbkdf2 fails
            logging.warning(f"Error in password verification with pbkdf2: {pw_error}, falling back to simple hash")
            try:
                password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                password_correct = (password_hash == user['password_hash'])
                logging.debug(f"Fallback password verification result: {password_correct}")
            except Exception as fallback_error:
                logging.error(f"Error in fallback password verification: {fallback_error}")
                password_correct = False
        
        if not password_correct:
            logging.warning(f"Authentication failed: Invalid password for user: {user['username']}")
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        logging.debug(f"Creating session for user {user['username']} (ID: {user['id']})")
        
        # Store session in database
        cursor.execute('''
        INSERT INTO sessions (
            user_id, 
            session_token, 
            created_at, 
            expires_at, 
            ip_address
        ) VALUES (?, ?, ?, ?, ?)
        ''', (user['id'], session_token, created_at, expires_at, ip_address))
        
        # Update last login timestamp
        cursor.execute('''
        UPDATE users 
        SET last_login = ? 
        WHERE id = ?
        ''', (created_at, user['id']))
        
        conn.commit()
        
        logging.info(f"Authentication successful for user: {user['username']} (ID: {user['id']}) from IP: {ip_address}")
        
        conn.close()
        
        return {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "session_token": session_token
        }
    
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        logging.debug(traceback.format_exc())
        return {"status": "error", "message": "Authentication failed due to a system error"}

def verify_session(session_token):
    """Verify a session token with enhanced debug logging"""
    try:
        if not session_token:
            logging.debug("verify_session called with empty token")
            return {"status": "error", "message": "No session token provided"}
        
        # Create a new connection for each verification
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find the session and join with user data
        cursor.execute('''
        SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND u.active = 1
        ''', (session_token,))
        
        session = cursor.fetchone()
        
        if not session:
            logging.debug(f"No valid session found for token (partial): {session_token[:10]}...")
            conn.close()
            return {"status": "error", "message": "Invalid or expired session"}
        
        # Check if session is expired
        import datetime
        if 'expires_at' in session and session['expires_at']:
            try:
                expires_at = datetime.datetime.fromisoformat(session['expires_at'])
                now = datetime.datetime.now()
                if now > expires_at:
                    logging.debug(f"Session expired: {expires_at} (now: {now})")
                    conn.close()
                    return {"status": "error", "message": "Session expired"}
            except Exception as date_err:
                logging.warning(f"Error parsing session expiry: {date_err}")
        
        # Return success with user info
        result = {
            "status": "success",
            "user": {
                "user_id": session['user_id'],
                "username": session['username'],
                "email": session['email'],
                "role": session['role'],
                "full_name": session.get('full_name', '')
            }
        }
        
        logging.debug(f"Session verified successfully for {session['username']} (role: {session['role']})")
        conn.close()
        return result
    
    except Exception as e:
        logging.error(f"Session verification error: {str(e)}")
        return {"status": "error", "message": f"Session verification failed: {str(e)}"}
        
@with_transaction
def logout_user(session_token):
    """Logout a user by invalidating their session"""
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Delete the session
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        
        conn.commit()
        conn.close()
        
        return {"status": "success"}
    
    except Exception as e:
        print(f"Logout error: {e}")
        return {"status": "error", "message": "Logout failed due to a system error"}

# Enhanced client management functions
@with_transaction
def create_client(conn, cursor, client_data, user_id):
    """Create a new client with enhanced validation and audit logging"""
    # Validate required fields
    required_fields = ['business_name', 'business_domain', 'contact_email']
    for field in required_fields:
        if not client_data.get(field):
            return {"status": "error", "message": f"Missing required field: {field}"}
    
    # Generate API key
    api_key = str(uuid.uuid4())
    current_time = datetime.now().isoformat()
    
    # Insert client record
    cursor.execute('''
    INSERT INTO clients 
    (business_name, business_domain, contact_email, contact_phone, 
     scanner_name, subscription_level, subscription_status, subscription_start,
     api_key, created_at, created_by, updated_at, updated_by, active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_data.get('business_name', ''),
        client_data.get('business_domain', ''),
        client_data.get('contact_email', ''),
        client_data.get('contact_phone', ''),
        client_data.get('scanner_name', ''),
        client_data.get('subscription', 'basic'),
        'active',
        current_time,
        api_key,
        current_time,
        user_id,
        current_time,
        user_id,
        1
    ))
    
    # Get the client ID
    client_id = cursor.lastrowid
    
    # Save customization data
    default_scans = json.dumps(client_data.get('default_scans', []))
    
    cursor.execute('''
    INSERT INTO customizations 
    (client_id, primary_color, secondary_color, logo_path, 
     favicon_path, email_subject, email_intro, default_scans, last_updated, updated_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        client_data.get('primary_color', '#FF6900'),
        client_data.get('secondary_color', '#808588'),
        client_data.get('logo_path', ''),
        client_data.get('favicon_path', ''),
        client_data.get('email_subject', 'Your Security Scan Report'),
        client_data.get('email_intro', 'Thank you for using our security scanner.'),
        default_scans,
        current_time,
        user_id
    ))
    
    # Create deployed scanner record with sanitized subdomain
    subdomain = client_data.get('business_name', '').lower()
    # Clean up subdomain to be URL-friendly
    subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
    # Remove consecutive dashes and ensure it doesn't start/end with a dash
    subdomain = '-'.join(filter(None, subdomain.split('-')))
    
    # Handle duplicates by appending client_id if needed
    cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
    if cursor.fetchone():
        subdomain = f"{subdomain}-{client_id}"
    
    cursor.execute('''
    INSERT INTO deployed_scanners 
    (client_id, subdomain, deploy_status, deploy_date, last_updated, template_version)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        subdomain,
        'pending',
        current_time,
        current_time,
        '1.0'
    ))
    
    # Log the client creation
    log_action(conn, cursor, user_id, 'create', 'client', client_id, 
              {'business_name': client_data.get('business_name'), 
               'subscription': client_data.get('subscription', 'basic')})
    
    return {
        "status": "success",
        "client_id": client_id,
        "api_key": api_key,
        "subdomain": subdomain
    }

# Enhanced function to log actions for audit trail
@with_transaction
def log_action(conn, cursor, user_id, action, entity_type, entity_id, changes=None, ip_address=None):
    """Log an action for the audit trail"""
    changes_json = json.dumps(changes) if changes else None
    
    cursor.execute('''
    INSERT INTO audit_log (user_id, action, entity_type, entity_id, changes, timestamp, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id, 
        action, 
        entity_type, 
        entity_id, 
        changes_json, 
        datetime.now().isoformat(),
        ip_address
    ))
    
    return cursor.lastrowid

@with_transaction
def create_password_reset_token(conn, cursor, email):
    """Create a password reset token for the specified email"""
    # Find the user
    cursor.execute('SELECT id FROM users WHERE email = ? AND active = 1', (email,))
    user = cursor.fetchone()
    
    if not user:
        # Don't reveal whether the email exists or not (security)
        return {"status": "success", "message": "If the email exists, a reset link has been sent"}
    
    # Generate a secure token
    reset_token = secrets.token_urlsafe(32)
    user_id = user['id']
    
    # Set expiration to 24 hours from now
    expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
    
    # Clear any existing tokens for this user
    cursor.execute('UPDATE password_resets SET used = 1 WHERE user_id = ?', (user_id,))
    
    # Insert the new token
    cursor.execute('''
    INSERT INTO password_resets (user_id, reset_token, created_at, expires_at)
    VALUES (?, ?, ?, ?)
    ''', (user_id, reset_token, datetime.now().isoformat(), expires_at))
    
    # Log the action
    log_action(conn, cursor, user_id, 'request_password_reset', 'user', user_id, 
              {'reset_token_id': cursor.lastrowid})
    
    return {"status": "success", "user_id": user_id, "reset_token": reset_token}

@with_transaction
def verify_password_reset_token(conn, cursor, token):
    """Verify a password reset token"""
    # Find the token
    cursor.execute('''
    SELECT pr.*, u.username, u.email
    FROM password_resets pr
    JOIN users u ON pr.user_id = u.id
    WHERE pr.reset_token = ? AND pr.used = 0 AND pr.expires_at > ?
    ''', (token, datetime.now().isoformat()))
    
    reset = cursor.fetchone()
    
    if not reset:
        return {"status": "error", "message": "Invalid or expired token"}
    
    return {
        "status": "success", 
        "user_id": reset['user_id'],
        "username": reset['username'],
        "email": reset['email']
    }

@with_transaction
def update_user_password(conn, cursor, user_id, new_password):
    """Update a user's password with enhanced security"""
    # Validate password
    if len(new_password) < 8:
        return {"status": "error", "message": "Password must be at least 8 characters"}
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE id = ? AND active = 1', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        return {"status": "error", "message": "User not found"}
    
    # Create salt and hash password (improved security)
    salt = secrets.token_hex(16)
    # Use stronger hashing with iterations
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        new_password.encode(), 
        salt.encode(), 
        100000  # More iterations for better security
    ).hex()
    
    # Update the user's password
    cursor.execute('''
    UPDATE users SET 
        password_hash = ?,
        salt = ?,
        updated_at = ?
    WHERE id = ?
    ''', (password_hash, salt, datetime.now().isoformat(), user_id))
    
    # Mark all reset tokens for this user as used
    cursor.execute('UPDATE password_resets SET used = 1 WHERE user_id = ?', (user_id,))
    
    # Log the password change
    log_action(conn, cursor, user_id, 'password_change', 'user', user_id, None)
    
    return {"status": "success"}

@with_transaction
def get_user_permissions(conn, cursor, role):
    """Get permissions for a specific role"""
    # Default permissions for all users
    default_permissions = ['view_profile', 'change_password']
    
    # Role-specific permissions
    role_permissions = {
        'admin': [
            'admin_dashboard',
            'manage_clients',
            'manage_users',
            'view_reports',
            'system_settings'
        ],
        'manager': [
            'admin_dashboard',
            'manage_clients',
            'view_reports'
        ],
        'client': [
            'client_dashboard',
            'view_own_reports'
        ]
    }
    
    # Combine default and role-specific permissions
    permissions = default_permissions.copy()
    if role in role_permissions:
        permissions.extend(role_permissions[role])
    
    return permissions

@with_transaction
def get_dashboard_summary(conn, cursor):
    """Get summary statistics for admin dashboard"""
    summary = {
        'clients': {
            'total': 0,
            'active': 0,
            'inactive': 0,
            'pending': 0,
            'new_this_month': 0
        },
        'subscriptions': {
            'basic': 0,
            'pro': 0,
            'enterprise': 0
        },
        'scans': {
            'total': 0,
            'this_month': 0,
            'yesterday': 0,
            'today': 0
        },
        'revenue': {
            'monthly': 0,
            'yearly': 0,
            'total': 0
        }
    }
    
    # Get total client count
    cursor.execute('SELECT COUNT(*) FROM clients')
    summary['clients']['total'] = cursor.fetchone()[0]
    
    # Get active client count
    cursor.execute('SELECT COUNT(*) FROM clients WHERE active = 1')
    summary['clients']['active'] = cursor.fetchone()[0]
    
    # Get inactive client count
    cursor.execute('SELECT COUNT(*) FROM clients WHERE active = 0')
    summary['clients']['inactive'] = cursor.fetchone()[0]
    
    # Get pending client count
    cursor.execute('''
    SELECT COUNT(*) FROM clients c
    JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE ds.deploy_status = 'pending' AND c.active = 1
    ''')
    summary['clients']['pending'] = cursor.fetchone()[0]
    
    # Get new clients this month
    current_month = datetime.now().strftime('%Y-%m')
    cursor.execute('''
    SELECT COUNT(*) FROM clients 
    WHERE created_at LIKE ? AND active = 1
    ''', (f'{current_month}%',))
    summary['clients']['new_this_month'] = cursor.fetchone()[0]
    
    # Get subscription counts
    subscription_levels = ['basic', 'pro', 'enterprise']
    for level in subscription_levels:
        cursor.execute('''
        SELECT COUNT(*) FROM clients 
        WHERE subscription_level = ? AND active = 1
        ''', (level,))
        summary['subscriptions'][level] = cursor.fetchone()[0]
    
    # Get scan counts
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    summary['scans']['total'] = cursor.fetchone()[0]
    
    # Get scans this month
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{current_month}%',))
    summary['scans']['this_month'] = cursor.fetchone()[0]
    
    # Get scans yesterday
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{yesterday}%',))
    summary['scans']['yesterday'] = cursor.fetchone()[0]
    
    # Get scans today
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('''
    SELECT COUNT(*) FROM scan_history 
    WHERE timestamp LIKE ?
    ''', (f'{today}%',))
    summary['scans']['today'] = cursor.fetchone()[0]
    
    # Get revenue info if billing is available
    try:
        # Monthly recurring revenue
        cursor.execute('''
        SELECT SUM(amount) FROM client_billing 
        WHERE status = 'active' AND billing_cycle = 'monthly'
        ''')
        result = cursor.fetchone()
        summary['revenue']['monthly'] = result[0] if result[0] is not None else 0
        
        # Yearly revenue (estimated)
        summary['revenue']['yearly'] = summary['revenue']['monthly'] * 12
        
        # Total revenue (all time)
        cursor.execute('SELECT SUM(amount) FROM billing_transactions WHERE status = "completed"')
        result = cursor.fetchone()
        summary['revenue']['total'] = result[0] if result[0] is not None else 0
    except:
        # Table might not exist yet
        pass
    
    return summary

@with_transaction
def get_client_by_id(conn, cursor, client_id):
    """Get client details by ID"""
    cursor.execute('''
    SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE c.id = ?
    ''', (client_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    client = dict(row)
    
    # Convert default_scans JSON to list
    if client.get('default_scans'):
        try:
            client['default_scans'] = json.loads(client['default_scans'])
        except:
            client['default_scans'] = []
    
    return client

@with_transaction
def get_client_by_api_key(conn, cursor, api_key):
    """Get client details by API key"""
    cursor.execute('''
    SELECT c.*, cu.*, ds.subdomain, ds.deploy_status
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    WHERE c.api_key = ?
    ''', (api_key,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    # Convert row to dict
    client = dict(row)
    
    # Convert default_scans JSON to list
    if client.get('default_scans'):
        try:
            client['default_scans'] = json.loads(client['default_scans'])
        except:
            client['default_scans'] = []
    
    return client

@with_transaction
def get_client_by_subdomain(conn, subdomain):
    """Get client details by subdomain
    
    Args:
        conn: Database connection
        subdomain: Client subdomain to look up
        
    Returns:
        Client details dict or None if not found
    """
    try:
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT c.*, d.* 
        FROM clients c
        JOIN deployed_scanners d ON c.id = d.client_id
        WHERE d.subdomain = ?
        ''', (subdomain,))
        
        result = cursor.fetchone()
        
        if result:
            return dict(result)
        return None
    except Exception as e:
        logging.error(f"Error retrieving client by subdomain: {e}")
        return None

@with_transaction
def list_users(conn, cursor, page=1, per_page=10):
    """List users with pagination"""
    offset = (page - 1) * per_page
    
    # Get users with pagination
    cursor.execute('''
    SELECT id, username, email, role, created_at, last_login, active
    FROM users
    ORDER BY id DESC
    LIMIT ? OFFSET ?
    ''', (per_page, offset))
    
    users = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute('SELECT COUNT(*) FROM users')
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        "status": "success",
        "users": users,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def get_user_by_id(conn, cursor, user_id):
    """Get user by ID"""
    cursor.execute('''
    SELECT id, username, email, role, created_at, last_login, active
    FROM users
    WHERE id = ?
    ''', (user_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    return dict(row)

@with_transaction
def get_scan_history(conn, cursor, client_id, page=1, per_page=10):
    """Get scan history for a client"""
    offset = (page - 1) * per_page
    
    # Get scans with pagination
    cursor.execute('''
    SELECT id, scan_id, timestamp, target, scan_type, status, report_path
    FROM scan_history
    WHERE client_id = ?
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
    ''', (client_id, per_page, offset))
    
    scans = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute('SELECT COUNT(*) FROM scan_history WHERE client_id = ?', (client_id,))
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    
    return {
        "status": "success",
        "scans": scans,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }

@with_transaction
def get_scan_by_id(conn, cursor, scan_id):
    """Get scan details by ID"""
    cursor.execute('''
    SELECT sh.*, c.business_name, c.business_domain
    FROM scan_history sh
    JOIN clients c ON sh.client_id = c.id
    WHERE sh.scan_id = ?
    ''', (scan_id,))
    
    row = cursor.fetchone()
    
    if not row:
        return None
    
    return dict(row)

@with_transaction
def update_scan_status(conn, cursor, scan_id, status, report_path=None):
    """Update the status of a scan"""
    if not scan_id:
        return {"status": "error", "message": "Scan ID is required"}
    
    # Create update query
    query = "UPDATE scan_history SET status = ?"
    params = [status]
    
    if report_path:
        query += ", report_path = ?"
        params.append(report_path)
    
    query += " WHERE scan_id = ?"
    params.append(scan_id)
    
    # Execute update
    cursor.execute(query, params)
    
    if cursor.rowcount == 0:
        return {"status": "error", "message": "Scan not found"}
    
    return {"status": "success"}

@with_transaction
def create_billing_record(conn, cursor, client_id, plan_data):
    """Create a billing record for a client"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Validate required fields
    required_fields = ['plan_id', 'billing_cycle', 'amount']
    for field in required_fields:
        if not field in plan_data:
            return {"status": "error", "message": f"Missing required field: {field}"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Calculate next billing date based on billing cycle
    start_date = datetime.now().isoformat()
    if plan_data['billing_cycle'] == 'monthly':
        next_billing_date = (datetime.now() + timedelta(days=30)).isoformat()
    elif plan_data['billing_cycle'] == 'quarterly':
        next_billing_date = (datetime.now() + timedelta(days=90)).isoformat()
    elif plan_data['billing_cycle'] == 'yearly':
        next_billing_date = (datetime.now() + timedelta(days=365)).isoformat()
    else:
        return {"status": "error", "message": "Invalid billing cycle"}
    
    # Insert billing record
    cursor.execute('''
    INSERT INTO client_billing 
    (client_id, plan_id, billing_cycle, amount, currency, start_date, next_billing_date, payment_method, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        plan_data['plan_id'],
        plan_data['billing_cycle'],
        plan_data['amount'],
        plan_data.get('currency', 'USD'),
        start_date,
        next_billing_date,
        plan_data.get('payment_method', 'credit_card'),
        plan_data.get('status', 'active')
    ))
    
    billing_id = cursor.lastrowid
    
    # Create initial transaction record
    transaction_id = str(uuid.uuid4())
    cursor.execute('''
    INSERT INTO billing_transactions
    (client_id, transaction_id, amount, currency, payment_method, status, timestamp, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        transaction_id,
        plan_data['amount'],
        plan_data.get('currency', 'USD'),
        plan_data.get('payment_method', 'credit_card'),
        'completed',
        datetime.now().isoformat(),
        'Initial subscription payment'
    ))
    
    # Update client subscription level if provided
    if 'subscription_level' in plan_data:
        cursor.execute('''
        UPDATE clients
        SET subscription_level = ?, subscription_status = 'active', subscription_start = ?
        WHERE id = ?
        ''', (plan_data['subscription_level'], start_date, client_id))
    
    return {
        "status": "success",
        "billing_id": billing_id,
        "transaction_id": transaction_id,
        "next_billing_date": next_billing_date
    }

# Initialize the database when this module is imported
init_db()
@with_transaction
def update_client(conn, cursor, client_id, client_data, user_id):
    """Update client information"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Verify client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Start with clients table updates
    client_fields = []
    client_values = []
    
    # Map fields to database columns for clients table
    field_mapping = {
        'business_name': 'business_name',
        'business_domain': 'business_domain',
        'contact_email': 'contact_email',
        'contact_phone': 'contact_phone',
        'scanner_name': 'scanner_name',
        'subscription_level': 'subscription_level',
        'subscription_status': 'subscription_status',
        'active': 'active'
    }
    
    for key, db_field in field_mapping.items():
        if key in client_data:
            client_fields.append(f"{db_field} = ?")
            client_values.append(client_data[key])
    
    # Always update the updated_at and updated_by fields
    client_fields.append("updated_at = ?")
    client_values.append(datetime.now().isoformat())
    client_fields.append("updated_by = ?")
    client_values.append(user_id)
    
    # Update clients table
    if client_fields:
        query = f'''
        UPDATE clients 
        SET {', '.join(client_fields)}
        WHERE id = ?
        '''
        client_values.append(client_id)
        cursor.execute(query, client_values)
    
    # Now handle customizations table
    custom_fields = []
    custom_values = []
    
    # Map fields to database columns for customizations table
    custom_mapping = {
        'primary_color': 'primary_color',
        'secondary_color': 'secondary_color',
        'logo_path': 'logo_path',
        'favicon_path': 'favicon_path',
        'email_subject': 'email_subject',
        'email_intro': 'email_intro',
        'email_footer': 'email_footer',
        'css_override': 'css_override',
        'html_override': 'html_override'
    }
    
    for key, db_field in custom_mapping.items():
        if key in client_data:
            custom_fields.append(f"{db_field} = ?")
            custom_values.append(client_data[key])
    
    # Handle default_scans separately as it needs to be JSON
    if 'default_scans' in client_data:
        custom_fields.append("default_scans = ?")
        custom_values.append(json.dumps(client_data['default_scans']))
    
    # Always update last_updated and updated_by
    custom_fields.append("last_updated = ?")
    custom_values.append(datetime.now().isoformat())
    custom_fields.append("updated_by = ?")
    custom_values.append(user_id)
    
    # Check if customization record exists
    cursor.execute('SELECT id FROM customizations WHERE client_id = ?', (client_id,))
    customization = cursor.fetchone()
    
    if customization and custom_fields:
        # Update existing record
        query = f'''
        UPDATE customizations 
        SET {', '.join(custom_fields)}
        WHERE client_id = ?
        '''
        custom_values.append(client_id)
        cursor.execute(query, custom_values)
    elif custom_fields:
        # Insert new record
        fields = [db_field for key, db_field in custom_mapping.items() if key in client_data]
        if 'default_scans' in client_data:
            fields.append('default_scans')
        fields.extend(['client_id', 'last_updated', 'updated_by'])
        
        values = custom_values
        values.append(client_id)
        values.append(datetime.now().isoformat())
        values.append(user_id)
        
        query = f'''
        INSERT INTO customizations 
        ({', '.join(fields)})
        VALUES ({', '.join(['?'] * len(fields))})
        '''
        cursor.execute(query, values)
    
    # Log the update
    log_action(conn, cursor, user_id, 'update', 'client', client_id, client_data)
    
    return {"status": "success", "client_id": client_id}
    
@with_transaction
def update_deployment_status(conn, cursor, client_id, status, config_path=None):
    """Update the deployment status for a client scanner"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if deployment record exists
    cursor.execute('SELECT id FROM deployed_scanners WHERE client_id = ?', (client_id,))
    deployment = cursor.fetchone()
    
    now = datetime.now().isoformat()
    
    if deployment:
        # Update existing record
        query = "UPDATE deployed_scanners SET deploy_status = ?, last_updated = ?"
        params = [status, now]
        
        if config_path:
            query += ", config_path = ?"
            params.append(config_path)
        
        query += " WHERE client_id = ?"
        params.append(client_id)
        
        cursor.execute(query, params)
    else:
        # Get client name for subdomain
        cursor.execute('SELECT business_name FROM clients WHERE id = ?', (client_id,))
        client = cursor.fetchone()
        
        if not client:
            return {"status": "error", "message": "Client not found"}
        
        # Create a subdomain from business name
        subdomain = client['business_name'].lower()
        subdomain = ''.join(c for c in subdomain if c.isalnum() or c == '-')
        subdomain = '-'.join(filter(None, subdomain.split('-')))
        
        # Handle duplicates by appending client_id if needed
        cursor.execute('SELECT id FROM deployed_scanners WHERE subdomain = ?', (subdomain,))
        if cursor.fetchone():
            subdomain = f"{subdomain}-{client_id}"
        
        # Insert new record
        query = "INSERT INTO deployed_scanners (client_id, subdomain, deploy_status, deploy_date, last_updated, config_path, template_version) VALUES (?, ?, ?, ?, ?, ?, ?)"
        
        cursor.execute(query, (
            client_id,
            subdomain,
            status,
            now,
            now,
            config_path,
            "1.0"
        ))
    
    return {"status": "success"}

@with_transaction
def delete_client(conn, cursor, client_id):
    """Delete a client and all associated data"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Delete client (cascade will handle related records)
    cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    
    return {"status": "success", "message": "Client deleted successfully"}

@with_transaction
def log_scan(conn, cursor, client_id, scan_id, target, scan_type):
    """Log a scan to the database"""
    if not client_id or not scan_id:
        return {"status": "error", "message": "Client ID and Scan ID are required"}
    
    # Insert scan record
    cursor.execute('''
    INSERT INTO scan_history 
    (client_id, scan_id, timestamp, target, scan_type, status)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        client_id,
        scan_id,
        datetime.now().isoformat(),
        target,
        scan_type,
        'pending'
    ))
    
    scan_history_id = cursor.lastrowid
    
    # Log the scan
    log_action(conn, cursor, client_id, 'scan', 'scan_history', scan_history_id, 
              {'scan_id': scan_id, 'target': target, 'scan_type': scan_type})
    
    return {"status": "success", "scan_history_id": scan_history_id}

@with_transaction
def regenerate_api_key(conn, cursor, client_id):
    """Regenerate a client's API key"""
    if not client_id:
        return {"status": "error", "message": "Client ID is required"}
    
    # Check if client exists
    cursor.execute('SELECT id FROM clients WHERE id = ?', (client_id,))
    if not cursor.fetchone():
        return {"status": "error", "message": "Client not found"}
    
    # Generate a new API key
    new_api_key = str(uuid.uuid4())
    
    # Update the client's API key
    cursor.execute('UPDATE clients SET api_key = ? WHERE id = ?', (new_api_key, client_id))
    
    if cursor.rowcount == 0:
        return {"status": "error", "message": "Failed to update API key"}
    
    # Log the regeneration
    log_action(conn, cursor, client_id, 'regenerate_api_key', 'client', client_id, None)
    
    return {"status": "success", "api_key": new_api_key}

@with_transaction
def list_clients(conn, cursor, page=1, per_page=10, filters=None):
    """List clients with pagination and filtering options"""
    offset = (page - 1) * per_page
    
    # Start with base query
    query = '''
    SELECT c.id, c.business_name, c.business_domain, c.contact_email, 
           c.subscription_level, c.subscription_status, c.created_at, c.active,
           ds.subdomain
    FROM clients c
    LEFT JOIN deployed_scanners ds ON c.id = ds.client_id
    '''
    
    # Add filter conditions if provided
    params = []
    where_clauses = []
    
    if filters:
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append('c.subscription_level = ?')
            params.append(filters['subscription'])
        
        if 'status' in filters and filters['status']:
            if filters['status'] == 'active':
                where_clauses.append('c.active = 1')
            elif filters['status'] == 'inactive':
                where_clauses.append('c.active = 0')
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append('(c.business_name LIKE ? OR c.business_domain LIKE ? OR c.contact_email LIKE ?)')
            params.extend([search_term, search_term, search_term])
    
    # Construct WHERE clause if needed
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Add order by and pagination
    query += ' ORDER BY c.id DESC LIMIT ? OFFSET ?'
    params.extend([per_page, offset])
    
    # Execute query
    cursor.execute(query, params)
    clients = [dict(row) for row in cursor.fetchall()]
    
    # Count total records for pagination
    count_query = 'SELECT COUNT(*) FROM clients c'
    if where_clauses:
        count_query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Remove pagination params and execute count query
    cursor.execute(count_query, params[:-2] if params else [])
    total_count = cursor.fetchone()[0]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    
    return {
        "status": "success",
        "clients": clients,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "total_count": total_count
        }
    }
