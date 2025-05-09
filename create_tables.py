import os
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def create_tables():
    """Manually create all required database tables"""
    logger.info(f"Creating database tables in {CLIENT_DB_PATH}")
    
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Create users table if not exists
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
        active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (updated_by) REFERENCES users(id)
    )
    ''')
    
    # Create customizations table
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
    
    # Create deployed_scanners table
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
    
    # Create scan_history table
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
    
    # Create audit_log table
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
    
    # Create sessions table
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
    
    # Create scans table for compatibility
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
    
    # Create indices for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
    
    conn.commit()
    
    # Verify tables were created
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    logger.info(f"Created tables: {[table[0] for table in tables]}")
    
    conn.close()
    logger.info("Database tables created successfully")

if __name__ == "__main__":
    create_tables()
