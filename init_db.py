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
    logger.info("Starting database initialization...")
    
    # Check if database file exists
    if not os.path.exists(CLIENT_DB_PATH):
        logger.info(f"Creating new database file at {CLIENT_DB_PATH}")
    else:
        logger.info(f"Database file already exists at {CLIENT_DB_PATH}")
    
    # Connect to the database
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Check which tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = [row[0] for row in cursor.fetchall()]
    logger.info(f"Existing tables: {existing_tables}")
    
    # Initialize the client database
    try:
        logger.info("Running init_client_db function...")
        result = init_client_db()
        logger.info(f"init_client_db result: {result}")
    except Exception as e:
        logger.error(f"Error initializing client database: {e}")
    
    # Verify tables after initialization
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables_after_init = [row[0] for row in cursor.fetchall()]
    logger.info(f"Tables after initialization: {tables_after_init}")
    
    # Close connection
    conn.close()
    logger.info("Database initialization completed")

if __name__ == "__main__":
    initialize_database()
