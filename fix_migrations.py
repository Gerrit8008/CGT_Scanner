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
