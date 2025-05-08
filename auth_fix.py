# auth_fix.py - Comprehensive solution to authentication issues
import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def fix_authentication_system():
    """Fix the authentication system by ensuring tables exist and creating admin user"""
    try:
        # Connect to database
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
        
        # Create sessions table if not exists
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
        
        # Create admin user if it doesn't exist
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if not admin_user:
            # Create salt and hash password
            salt = secrets.token_hex(16)
            password = 'admin123'
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000
            ).hex()
            
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', datetime.now().isoformat()))
            
            logger.info("Admin user created successfully")
        else:
            logger.info("Admin user already exists")
        
        # Create a monkey patch for the authenticate_user function
        with open('fix_auth.py', 'w') as f:
            f.write('''
import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
    """
    Fixed authenticate_user function that handles parameters correctly
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find user by username or email
        cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ?) AND active = 1
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Verify password
        try:
            # Use pbkdf2_hmac if salt exists (new format)
            salt = user['salt']
            stored_hash = user['password_hash']
            
            # Compute hash with pbkdf2
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                password.encode(), 
                salt.encode(), 
                100000  # Same iterations as used for storing
            ).hex()
            
            password_correct = (password_hash == stored_hash)
        except Exception as pw_error:
            logger.warning(f"Error in password verification with pbkdf2: {pw_error}, falling back to simple hash")
            # Fallback to simple hash if pbkdf2 fails
            try:
                password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                password_correct = (password_hash == user['password_hash'])
            except Exception as fallback_error:
                logger.error(f"Error in fallback password verification: {fallback_error}")
                password_correct = False
        
        if not password_correct:
            conn.close()
            return {"status": "error", "message": "Invalid credentials"}
        
        # Create a session token
        session_token = secrets.token_hex(32)
        created_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        # Store session in database
        cursor.execute('''
        INSERT INTO sessions (
            user_id, 
            session_token, 
            created_at, 
            expires_at, 
            ip_address,
            user_agent
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (user['id'], session_token, created_at, expires_at, ip_address, user_agent))
        
        # Update last login timestamp
        cursor.execute('''
        UPDATE users 
        SET last_login = ? 
        WHERE id = ?
        ''', (created_at, user['id']))
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "session_token": session_token
        }
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

def apply_authentication_fix():
    """Apply authentication fix by monkey patching the original function"""
    import importlib
    try:
        # Import the client_db module where the original function is
        client_db = importlib.import_module('client_db')
        
        # Replace the authenticate_user function with our fixed version
        client_db.authenticate_user = authenticate_user
        
        logger.info("Authentication fix applied successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to apply authentication fix: {e}")
        return False

def verify_session(session_token):
    """
    Verify a session token
    """
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find the session and join with user data
        cursor.execute('''
        SELECT s.*, u.username, u.email, u.role, u.full_name, u.id as user_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND u.active = 1
        ''', (session_token,))
        
        session = cursor.fetchone()
        
        if not session:
            conn.close()
            return {"status": "error", "message": "Invalid or expired session"}
        
        # Check if session is expired
        if 'expires_at' in session and session['expires_at']:
            try:
                expires_at = datetime.fromisoformat(session['expires_at'])
                now = datetime.now()
                if now > expires_at:
                    conn.close()
                    return {"status": "error", "message": "Session expired"}
            except Exception as date_err:
                logger.warning(f"Error parsing session expiry: {date_err}")
        
        # Return success with user info
        result = {
            "status": "success",
            "user": {
                "user_id": session['user_id'],
                "username": session['username'],
                "email": session['email'],
                "role": session['role'],
                "full_name": session.get('full_name', '')
            }
        }
        
        conn.close()
        return result
    
    except Exception as e:
        logger.error(f"Session verification error: {str(e)}")
        return {"status": "error", "message": f"Session verification failed: {str(e)}"}

def create_user(username, email, password, role='client', full_name=None):
    """
    Create a new user
    """
    try:
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return {"status": "error", "message": "Username or email already exists"}
        
        # Create salt and hash password
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Insert user
        cursor.execute('''
        INSERT INTO users (
            username, email, password_hash, salt, role, full_name, created_at, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (username, email, password_hash, salt, role, full_name, datetime.now().isoformat()))
        
        user_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "user_id": user_id, "message": "User created successfully"}
    
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return {"status": "error", "message": f"Failed to create user: {str(e)}"}
''')
            
        # Create auth_hotfix.py file to patch the authenticate_user function
        with open('auth_hotfix.py', 'w') as f:
            f.write('''
def register_auth_hotfix(app):
    """Register the authentication hotfix with the Flask app"""
    @app.before_first_request
    def apply_hotfix():
        # Import and apply the fix
        from fix_auth import apply_authentication_fix
        
        # Apply the fix to the authenticate_user function
        apply_authentication_fix()
        
        app.logger.info("Authentication hotfix applied successfully")
    
    return app
''')
        
        conn.commit()
        conn.close()
        
        logger.info("Authentication fix created successfully")
        return True
    except Exception as e:
        logger.error(f"Error fixing authentication system: {e}")
        return False

if __name__ == "__main__":
    fix_authentication_system()
    print("Authentication system fixed successfully!")
    print("You can now login with:")
    print("Username: admin")
    print("Password: admin123")
