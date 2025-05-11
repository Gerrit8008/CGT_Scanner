#project directory

import os
import sqlite3
import logging
from client_db import CLIENT_DB_PATH, init_client_db

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def initialize_database():
    """Initialize all database tables if they don't exist"""
    try:
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(CLIENT_DB_PATH), exist_ok=True)
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Create tables with proper foreign key constraints
        cursor.execute('PRAGMA foreign_keys = ON')
        
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
                created_at TEXT NOT NULL,
                last_login TEXT,
                active INTEGER DEFAULT 1
            )
        ''')
        
        # Create sessions table with proper expiration
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        
        conn.commit()
        
        # Initialize default admin user if not exists
        cursor.execute('SELECT * FROM users WHERE role = ? LIMIT 1', ('admin',))
        if not cursor.fetchone():
            create_admin_user(cursor)
            conn.commit()
            
        return True
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        return False
        
    finally:
        if 'conn' in locals():
            conn.close()
