import os
import sqlite3
import time
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

@contextmanager
def get_db_connection(max_retries=5, retry_delay=0.5):
    """
    Context manager for database connections with retry logic for locked database
    
    Args:
        max_retries: Maximum number of retries if database is locked
        retry_delay: Delay between retries in seconds
        
    Yields:
        sqlite3.Connection: Database connection
    """
    conn = None
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(CLIENT_DB_PATH, timeout=10.0)  # Increase timeout
            conn.row_factory = sqlite3.Row
            yield conn
            return
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                logger.warning(f"Database locked, retrying in {retry_delay} seconds (attempt {attempt+1}/{max_retries})")
                time.sleep(retry_delay)
                # Increase delay for next attempt
                retry_delay *= 1.5
            else:
                raise
        finally:
            if conn:
                conn.close()

def initialize_database():
    """Initialize database with all required tables"""
    with get_db_connection() as conn:
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
            active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        ''')
        
        # Create other tables...
        # (add code from schema.sql for other tables)
        
        conn.commit()
        logger.info("Database initialized successfully")
