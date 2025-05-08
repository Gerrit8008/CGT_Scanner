# fix_auth.py - Consolidated authentication functions
import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def ensure_db_tables():
    """Ensure all required database tables exist"""
    try:
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
        
        conn.commit()
        conn.close()
        logger.info("Database tables verified")
        return True
    except Exception as e:
        logger.error(f"Error ensuring database tables: {e}")
        return False

def authenticate_user(conn, cursor, username_or_email, password, ip_address=None, user_agent=None):
    """
    Authenticate a user with the database connection provided
    
    Args:
        conn: Database connection
        cursor: Database cursor
        username_or_email: Username or email for login
        password: Password for login
        ip_address: IP address of the request (optional)
        user_agent: User agent string (optional)
        
    Returns:
        dict: Authentication result
    """
    try:
        # Find user by username or email
        cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ?) AND active = 1
        ''', (username_or_email, username_or_email))
        
        user = cursor.fetchone()
        
        if not user:
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
        
        # Return successful authentication result
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

# Add a wrapper function that handles the database connection itself
def authenticate_user_wrapper(username_or_email, password, ip_address=None, user_agent=None):
    """
    Wrapper for authenticate_user that handles database connection
    
    This function has the same signature as the original authenticate_user function
    but takes care of creating and closing the database connection.
    """
    try:
        ensure_db_tables()
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Call the actual authenticate function
        result = authenticate_user(conn, cursor, username_or_email, password, ip_address, user_agent)
        
        # Commit changes if successful
        if result['status'] == 'success':
            conn.commit()
        
        # Close connection
        conn.close()
        
        return result
        
    except Exception as e:
        logger.error(f"Authentication wrapper error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

def verify_session(session_token):
    """Verify if a session token is valid"""
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find session and join with user
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
        
        # Return user info
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

def logout_user(session_token):
    """Log a user out by removing their session"""
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Delete session
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": "Logged out successfully"}
    
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return {"status": "error", "message": f"Logout failed: {str(e)}"}

def create_user(username, email, password, role='client', full_name=None):
    """Create a new user account"""
    try:
        # Ensure tables exist
        ensure_db_tables()
        
        # Basic validation
        if not username or not email or not password:
            return {"status": "error", "message": "All fields are required"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
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
            100000  # 100,000 iterations for security
        ).hex()
        
        # Insert new user
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
        ''', (username, email, password_hash, salt, role, full_name, datetime.now().isoformat()))
        
        user_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created user: {username} with role: {role}")
        return {"status": "success", "user_id": user_id, "message": "User created successfully"}
    
    except Exception as e:
        logger.error(f"User creation error: {str(e)}")
        return {"status": "error", "message": f"Failed to create user: {str(e)}"}

def create_admin_user(password="admin123"):
    """Create or reset the admin user password"""
    try:
        # Ensure tables exist
        ensure_db_tables()
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        # Generate secure password hash
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        current_time = datetime.now().isoformat()
        
        if admin_user:
            # Update existing admin user
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            logger.info("Updated existing admin user")
        else:
            # Create new admin user
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
            ''', ('admin', 'admin@example.com', password_hash, salt, 'admin', 'System Administrator', current_time))
            logger.info("Created new admin user")
        
        conn.commit()
        conn.close()
        
        logger.info("Admin user created/updated successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return False

def apply_authentication_fix():
    """Apply the authentication system fix"""
    try:
        # 1. Ensure database tables
        ensure_db_tables()
        
        # 2. Create admin user if it doesn't exist
        create_admin_user()
        
        # 3. Make sure all functions are properly defined
        # (Already done in this file)
        
        logger.info("Authentication fix applied successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to apply authentication fix: {e}")
        return False

# Run the fix when this module is imported
apply_authentication_fix()
