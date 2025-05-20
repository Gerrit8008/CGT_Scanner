#!/usr/bin/env python3
# fix_migrations.py - Fix the specific migration error with full_name column

import os
import sqlite3
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_migration_006():
    """
    Fix the migration 006_add_full_name_to_users that's failing due to duplicate column
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # 1. Check if migrations table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='migrations'")
        if not cursor.fetchone():
            # Create migrations table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                applied_at TEXT NOT NULL
            )
            ''')
            conn.commit()
            logger.info("Created migrations table")
        
        # 2. Check if migration 006 is already applied
        cursor.execute("SELECT name FROM migrations WHERE name = '006_add_full_name_to_users'")
        if cursor.fetchone():
            logger.info("Migration 006_add_full_name_to_users is already marked as applied")
            conn.close()
            return True
        
        # 3. Check if full_name column already exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'full_name' in column_names:
            logger.info("Column 'full_name' already exists in users table")
            # Just mark the migration as applied
            cursor.execute(
                "INSERT INTO migrations (name, applied_at) VALUES (?, ?)",
                ('006_add_full_name_to_users', datetime.now().isoformat())
            )
            conn.commit()
            logger.info("Marked migration 006_add_full_name_to_users as applied")
            conn.close()
            return True
        
        # 4. Column doesn't exist, need to add it
        logger.info("Adding 'full_name' column to users table")
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
        
        # 5. Mark migration as applied
        cursor.execute(
            "INSERT INTO migrations (name, applied_at) VALUES (?, ?)",
            ('006_add_full_name_to_users', datetime.now().isoformat())
        )
        
        conn.commit()
        logger.info("Migration 006_add_full_name_to_users successfully applied")
        
        conn.close()
        return True
    
    except Exception as e:
        logger.error(f"Error fixing migration 006: {e}")
        if 'conn' in locals():
            conn.close()
        return False

def fix_migration_007():
    """
    Fix the migration 007_add_client_customization_fields that's failing due to duplicate scanner_name column
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # 1. Check if migration 007 is already applied
        cursor.execute("SELECT name FROM migrations WHERE name = '007_add_client_customization_fields'")
        if cursor.fetchone():
            logger.info("Migration 007_add_client_customization_fields is already marked as applied")
            conn.close()
            return True
        
        # 2. Check which columns already exist in the clients table
        cursor.execute("PRAGMA table_info(clients)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        # 3. Begin transaction
        conn.execute('BEGIN TRANSACTION')
        
        # 4. Add only columns that don't already exist
        columns_to_add = [
            ('primary_color', "TEXT", "'#FF6900'"),
            ('secondary_color', "TEXT", "'#808588'"),
            ('business_name', "TEXT", "NULL"),
            ('business_domain', "TEXT", "NULL")
        ]
        
        for col_name, col_type, default in columns_to_add:
            if col_name not in column_names:
                logger.info(f"Adding '{col_name}' column to clients table")
                cursor.execute(f"ALTER TABLE clients ADD COLUMN {col_name} {col_type} DEFAULT {default}")
            else:
                logger.info(f"Column '{col_name}' already exists in clients table")
        
        # Skip scanner_name as it already exists
        logger.info("Skipping scanner_name column (already exists)")
        
        # 5. Create customizations table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='customizations'")
        if not cursor.fetchone():
            logger.info("Creating customizations table")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS customizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                primary_color TEXT DEFAULT '#FF6900',
                secondary_color TEXT DEFAULT '#808588',
                logo_path TEXT,
                email_subject TEXT DEFAULT 'Your Security Scan Report',
                email_intro TEXT DEFAULT 'Thank you for using our security scanner.',
                default_scans TEXT DEFAULT '["network", "web", "email", "ssl"]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
        else:
            logger.info("Customizations table already exists")
        
        # 6. Create scan_history table if it doesn't exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'")
        if not cursor.fetchone():
            logger.info("Creating scan_history table")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                report_path TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
            ''')
        else:
            logger.info("Scan_history table already exists")
        
        # 7. Mark migration as applied
        cursor.execute(
            "INSERT INTO migrations (name, applied_at) VALUES (?, ?)",
            ('007_add_client_customization_fields', datetime.now().isoformat())
        )
        
        conn.commit()
        logger.info("Migration 007_add_client_customization_fields successfully applied")
        
        conn.close()
        return True
    
    except Exception as e:
        logger.error(f"Error fixing migration 007: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

# Update your existing fix_all_migrations() function to include the new fix:

def fix_all_migrations():
    """
    Fix all migrations by checking each one
    """
    # Fix migration 006
    result_006 = fix_migration_006()
    logger.info(f"Migration 006 fix result: {'Success' if result_006 else 'Failed'}")
    
    # Fix migration 007
    result_007 = fix_migration_007()
    logger.info(f"Migration 007 fix result: {'Success' if result_007 else 'Failed'}")
    
    return result_006 and result_007

# Update your main block to include both migration fixes:

if __name__ == "__main__":
    print("Running migration fixes...")
    
    if fix_all_migrations():
        print("✅ All migrations fixed successfully!")
    else:
        print("❌ Some migrations could not be fixed. Check the logs for details.")

def fix_all_migrations():
    """
    Fix all migrations by checking each one
    """
    # For now, we just fix the specific failing migration
    return fix_migration_006()

if __name__ == "__main__":
    print("Running migration fix for users.full_name column...")
    
    if fix_migration_006():
        print("✅ Migration fixed successfully!")
    else:
        print("❌ Failed to fix migration")
