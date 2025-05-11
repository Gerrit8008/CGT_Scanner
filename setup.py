import logging
from database_manager import DatabaseManager
from datetime import datetime
import hashlib
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"setup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def setup_database():
    """Initialize the database and create an admin user"""
    try:
        # Initialize database manager
        db_manager = DatabaseManager()
        
        # Create admin user
        with sqlite3.connect(db_manager.admin_db_path) as conn:
            cursor = conn.cursor()
            
            # Create salt and hash password
            salt = secrets.token_hex(16)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                'SecurePass123'.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
            # Insert admin user
            cursor.execute('''
                INSERT OR IGNORE INTO users (
                    username, email, password_hash, salt, 
                    role, full_name, created_at, active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'admin',
                'admin@example.com',
                password_hash,
                salt,
                'admin',
                'System Administrator',
                datetime.now().isoformat(),
                1
            ))
            
            conn.commit()
            
        logger.info("Database setup completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup database: {e}")
        return False

if __name__ == "__main__":
    setup_database()
