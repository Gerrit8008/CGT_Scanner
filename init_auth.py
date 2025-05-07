# init_auth.py
import os
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def initialize_authentication():
    """Initialize the authentication system"""
    # Import auth utilities
    from auth_utils import fix_database_schema, create_admin_user
    
    # Fix database schema
    logger.info("Fixing database schema...")
    fix_database_schema()
    
    # Create admin user if it doesn't exist
    logger.info("Creating admin user if needed...")
    admin_created = create_admin_user()
    
    if admin_created:
        logger.info("Admin user created successfully!")
        logger.info("Admin credentials:")
        logger.info("Username: admin")
        logger.info("Password: admin123")
    else:
        logger.info("Admin user already exists")
    
    logger.info("Authentication system initialized successfully!")
    return True

if __name__ == "__main__":
    initialize_authentication()
