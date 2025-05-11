from pathlib import Path
import sqlite3
import logging
import json
from datetime import datetime

class DatabaseManager:
    def __init__(self, base_path='./databases'):
        self.base_path = Path(base_path)
        self.admin_db_path = self.base_path / 'admin.db'
        self.base_path.mkdir(exist_ok=True)
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize databases
        self._init_admin_database()

    def _init_admin_database(self):
        """Initialize the main admin database"""
        try:
            conn = sqlite3.connect(self.admin_db_path)
            cursor = conn.cursor()
            
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
            )''')
            
            # Create clients table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                business_name TEXT NOT NULL,
                business_domain TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                contact_phone TEXT,
                subscription_level TEXT DEFAULT 'basic',
                database_name TEXT UNIQUE,
                api_key TEXT UNIQUE,
                created_at TEXT,
                updated_at TEXT,
                active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
            
            # Create deployed_scanners table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS deployed_scanners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                scanner_name TEXT NOT NULL,
                api_key TEXT UNIQUE,
                status TEXT DEFAULT 'active',
                created_at TEXT,
                last_active TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )''')
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error initializing admin database: {e}")
            raise
        finally:
            conn.close()

    def create_client_database(self, client_id: int, business_name: str) -> str:
        """Create a new database for a client"""
        try:
            # Create sanitized database name
            db_name = f"client_{client_id}_{business_name.lower().replace(' ', '_')}.db"
            db_path = self.base_path / db_name
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner_id TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT,
                report_path TEXT,
                created_at TEXT
            )''')
            
            # Create leads table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanner_id TEXT NOT NULL,
                name TEXT,
                email TEXT NOT NULL,
                company TEXT,
                phone TEXT,
                source TEXT,
                status TEXT DEFAULT 'new',
                created_at TEXT,
                notes TEXT
            )''')
            
            conn.commit()
            conn.close()
            
            # Update main database with the client's database name
            admin_conn = sqlite3.connect(self.admin_db_path)
            cursor = admin_conn.cursor()
            cursor.execute("""
                UPDATE clients 
                SET database_name = ? 
                WHERE id = ?
            """, (db_name, client_id))
            admin_conn.commit()
            admin_conn.close()
            
            return db_name
            
        except Exception as e:
            self.logger.error(f"Error creating client database: {e}")
            raise

    def get_client_connection(self, client_id: int) -> sqlite3.Connection:
        """Get a connection to a client's database"""
        try:
            admin_conn = sqlite3.connect(self.admin_db_path)
            cursor = admin_conn.cursor()
            cursor.execute("SELECT database_name FROM clients WHERE id = ?", (client_id,))
            result = cursor.fetchone()
            admin_conn.close()
            
            if result and result[0]:
                db_path = self.base_path / result[0]
                if db_path.exists():
                    return sqlite3.connect(db_path)
            
            raise ValueError(f"No database found for client {client_id}")
            
        except Exception as e:
            self.logger.error(f"Error getting client connection: {e}")
            raise
