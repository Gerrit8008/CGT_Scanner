#!/usr/bin/env python3
# reset_db.py - Reset the database and create admin user

import os
import sqlite3
import secrets
import hashlib
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def reset_database():
    """Reset the database and create an admin user"""
    try:
        # Backup the existing database if it exists
        if os.path.exists(CLIENT_DB_PATH):
            backup_path = f"{CLIENT_DB_PATH}.bak.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            try:
                os.rename(CLIENT_DB_PATH, backup_path)
                logger.info(f"Backed up existing database to {backup_path}")
            except Exception as e:
                logger.warning(f"Could not backup database: {str(e)}")
                # Try to delete it instead
                try:
                    os.remove(CLIENT_DB_PATH)
                    logger.info("Deleted database file")
                except:
                    logger.error("Could not delete database file")
                    return False
        
        # Create a new database
        conn = sqlite3.connect(CLIENT_DB_PATH)
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
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (updated_by) REFERENCES users(id)
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
            default_scans TEXT,  -- JSON array of default scan types
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
        
        # Create admin user
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        current_time = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT INTO users (
            username, 
            email, 
            password_hash, 
            salt, 
            role, 
            full_name, 
            created_at, 
            active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'Administrator', current_time))
        
        # Get admin user ID
        admin_id = cursor.lastrowid
        
        # Create client record for admin user
        api_key = secrets.token_hex(16)
        
        cursor.execute('''
        INSERT INTO clients (
            user_id,
            business_name,
            business_domain,
            contact_email,
            scanner_name,
            subscription_level,
            subscription_status,
            subscription_start,
            api_key,
            created_at,
            created_by,
            active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            admin_id,
            'Admin Organization',
            'example.com',
            'admin@example.com',
            'Admin Scanner',
            'enterprise',
            'active',
            current_time,
            api_key,
            current_time,
            admin_id
        ))
        
        # Commit changes
        conn.commit()
        conn.close()
        
        logger.info("Database reset successful!")
        logger.info("Admin user created with username 'admin' and password 'admin123'")
        
        return True
    except Exception as e:
        logger.error(f"Error resetting database: {str(e)}")
        return False

if __name__ == "__main__":
    reset_database()
