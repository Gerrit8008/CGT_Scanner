import os
import sqlite3
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def debug_database():
    """Debug database state and repair any issues"""
    logger.info(f"Debugging database at {CLIENT_DB_PATH}")
    
    # Check if database file exists
    if not os.path.exists(CLIENT_DB_PATH):
        logger.error(f"Database file does not exist at {CLIENT_DB_PATH}")
        create_database()
        return
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Check which tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = [row[0] for row in cursor.fetchall()]
    logger.info(f"Existing tables: {existing_tables}")
    
    # Expected tables
    expected_tables = [
        'users', 'clients', 'customizations', 'deployed_scanners', 
        'scan_history', 'audit_log', 'sessions', 'scans'
    ]
    
    # Check for missing tables
    missing_tables = [table for table in expected_tables if table not in existing_tables]
    if missing_tables:
        logger.warning(f"Missing tables: {missing_tables}")
        
        # Create missing tables
        create_missing_tables(conn, missing_tables)
    else:
        logger.info("All expected tables exist")
    
    # Check for rows in clients table
    cursor.execute("SELECT COUNT(*) FROM clients")
    client_count = cursor.fetchone()[0]
    logger.info(f"Number of clients in database: {client_count}")
    
    # Check for user records
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    logger.info(f"Users in database: {users}")
    
    # Check for client-user relationships
    cursor.execute("""
    SELECT u.id as user_id, u.username, c.id as client_id, c.business_name
    FROM users u
    LEFT JOIN clients c ON u.id = c.user_id
    """)
    user_clients = cursor.fetchall()
    logger.info(f"User-client relationships: {user_clients}")
    
    # Close connection
    conn.close()
    logger.info("Database debugging completed")

def create_database():
    """Create the database and all tables"""
    logger.info(f"Creating new database at {CLIENT_DB_PATH}")
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    create_missing_tables(conn, [
        'users', 'clients', 'customizations', 'deployed_scanners', 
        'scan_history', 'audit_log', 'sessions', 'scans'
    ])
    conn.close()

def create_missing_tables(conn, missing_tables):
    """Create missing tables in the database"""
    cursor = conn.cursor()
    
    for table in missing_tables:
        logger.info(f"Creating missing table: {table}")
        
        if table == 'users':
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
        
        elif table == 'clients':
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
                active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
            ''')
        
        elif table == 'customizations':
            cursor.execute('''
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
                default_scans TEXT,
                css_override TEXT,
                html_override TEXT,
                last_updated TEXT,
                updated_by INTEGER,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
            ''')
        
        elif table == 'deployed_scanners':
            cursor.execute('''
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
            )
            ''')
        
        elif table == 'scan_history':
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
        
        elif table == 'audit_log':
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
        
        elif table == 'sessions':
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TEXT,
                expires_at TEXT,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')
        
        elif table == 'scans':
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                client_id INTEGER,
                timestamp TEXT,
                target TEXT,
                scan_type TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
    
    # Create necessary indices
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
    
    conn.commit()
    logger.info(f"Created {len(missing_tables)} missing tables")

def fix_client_records():
    """Fix client records in the database"""
    logger.info("Fixing client records...")
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Find user IDs without corresponding client entries
    cursor.execute("""
    SELECT u.id, u.username, u.email
    FROM users u
    LEFT JOIN clients c ON u.id = c.user_id
    WHERE c.id IS NULL AND u.role = 'client'
    """)
    users_without_clients = cursor.fetchall()
    
    for user_id, username, email in users_without_clients:
        logger.info(f"Creating missing client record for user {username} (ID: {user_id})")
        
        # Create default client entry
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
        INSERT INTO clients (
            user_id, business_name, business_domain, contact_email, 
            subscription_level, subscription_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            f"{username}'s Business", 
            "example.com", 
            email,
            "basic",
            "active",
            timestamp
        ))
    
    # Create missing customization entries
    cursor.execute("""
    SELECT c.id 
    FROM clients c
    LEFT JOIN customizations cu ON c.id = cu.client_id
    WHERE cu.id IS NULL
    """)
    clients_without_customizations = cursor.fetchall()
    
    for (client_id,) in clients_without_customizations:
        logger.info(f"Creating missing customization record for client ID: {client_id}")
        
        cursor.execute('''
        INSERT INTO customizations (
            client_id, primary_color, secondary_color, 
            email_subject, email_intro, email_footer, default_scans
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            client_id,
            "#336699",
            "#6699cc",
            "Security Scan Results",
            "Please find your security scan results attached.",
            "Thank you for using our service.",
            "basic,ssl,headers"
        ))
    
    conn.commit()
    conn.close()
    logger.info("Client record fixing completed")

if __name__ == "__main__":
    debug_database()
    fix_client_records()
