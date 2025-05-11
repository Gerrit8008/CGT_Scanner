# auth_utils.py
import os
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

def save_uploaded_file(file, directory, allowed_extensions=None):
    """Save uploaded file with security checks"""
    if file and allowed_file(file.filename, allowed_extensions):
        filename = secure_filename(file.filename)
        filepath = os.path.join(directory, filename)
        file.save(filepath)
        return filepath
    return None

def allowed_file(filename, allowed_extensions):
    """Check if file extension is allowed"""
    if allowed_extensions is None:
        return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def hash_password(password, salt=None):
    """
    Hash a password using PBKDF2 with a salt
    
    Args:
        password (str): Password to hash
        salt (str, optional): Salt to use. If None, a new salt is generated
        
    Returns:
        tuple: (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000  # 100,000 iterations for security
    ).hex()
    
    return password_hash, salt

def authenticate_user(username_or_email, password, ip_address=None, user_agent=None):
    """
    Authenticate a user
    
    Args:
        username_or_email (str): Username or email
        password (str): Password
        ip_address (str, optional): Client IP address
        user_agent (str, optional): Client user agent
        
    Returns:
        dict: Authentication result
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
            # Get stored salt and hash
            salt = user['salt']
            stored_hash = user['password_hash']
            
            # Compute hash with same parameters
            password_hash, _ = hash_password(password, salt)
            
            password_correct = (password_hash == stored_hash)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
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
            user_id, session_token, created_at, expires_at, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (user['id'], session_token, created_at, expires_at, ip_address, user_agent))
        
        # Update last login timestamp
        cursor.execute('''
        UPDATE users 
        SET last_login = ? 
        WHERE id = ?
        ''', (created_at, user['id']))
        
        conn.commit()
        
        # Return success with user info
        result = {
            "status": "success",
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "role": user['role'],
            "full_name": user.get('full_name'),
            "session_token": session_token
        }
        
        conn.close()
        return result
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return {"status": "error", "message": f"Authentication failed: {str(e)}"}

def verify_session(session_token):
    """
    Verify a session token
    
    Args:
        session_token (str): Session token
        
    Returns:
        dict: Session verification result
    """
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
        
        # Check if session has expired
        if 'expires_at' in session and session['expires_at']:
            try:
                expires_at = datetime.fromisoformat(session['expires_at'])
                now = datetime.now()
                if now > expires_at:
                    conn.close()
                    return {"status": "error", "message": "Session expired"}
            except Exception as e:
                logger.warning(f"Error parsing expiry date: {e}")
        
        # FIX: Convert SQLite Row to a dictionary or check for the attribute differently
        # Option 1: Get full_name safely
        full_name = ''
        try:
            full_name = session['full_name']
        except (KeyError, IndexError):
            pass
        
        # Return success with user info
        result = {
            "status": "success",
            "user": {
                "user_id": session['user_id'],
                "username": session['username'],
                "email": session['email'],
                "role": session['role'],
                "full_name": full_name  # Use the safely retrieved value
            }
        }
        
        conn.close()
        return result
    
    except Exception as e:
        logger.error(f"Session verification error: {e}")
        return {"status": "error", "message": f"Session verification failed: {str(e)}"}

def get_client_id_from_request():
    """Get client ID from the current request context"""
    # Check for API key in headers
    api_key = request.headers.get('X-API-Key')
    if api_key:
        # Look up client by API key
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM clients WHERE api_key = ?', (api_key,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return result[0]
    
    # If no API key or invalid, check session
    if 'user' in session:
        user_id = session['user'].get('id')
        if user_id:
            conn = sqlite3.connect(CLIENT_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM clients WHERE user_id = ?', (user_id,))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return result[0]
    
    raise ValueError("No valid client ID found in request")

def logout_user(session_token):
    """
    Logout a user by invalidating their session
    
    Args:
        session_token (str): Session token
        
    Returns:
        dict: Logout result
    """
    try:
        if not session_token:
            return {"status": "error", "message": "No session token provided"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        cursor = conn.cursor()
        
        # Delete the session
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": "Logged out successfully"}
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return {"status": "error", "message": f"Logout failed: {str(e)}"}

def create_user(username, email, password, role='client', full_name=None):
    """
    Create a new user
    
    Args:
        username (str): Username
        email (str): Email address
        password (str): Password
        role (str, optional): User role (admin or client)
        full_name (str, optional): User's full name
        
    Returns:
        dict: User creation result
    """
    try:
        # Check for required fields
        if not username or not email or not password:
            return {"status": "error", "message": "Username, email, and password are required"}
        
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
        
        # Hash password
        password_hash, salt = hash_password(password)
        
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
        logger.error(f"User creation error: {e}")
        return {"status": "error", "message": f"Failed to create user: {str(e)}"}

def register_client(user_id, business_data):
    """
    Register a client for a user
    
    Args:
        user_id (int): User ID
        business_data (dict): Business information
        
    Returns:
        dict: Client registration result
    """
    try:
        # Check for required fields
        if not business_data.get('business_name') or not business_data.get('business_domain') or not business_data.get('contact_email'):
            return {"status": "error", "message": "Business name, domain, and contact email are required"}
        
        # Connect to database
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check if client already exists for this user
        cursor.execute('SELECT id FROM clients WHERE user_id = ?', (user_id,))
        existing_client = cursor.fetchone()
        
        if existing_client:
            conn.close()
            return {"status": "error", "message": "Client already registered for this user"}
        
        # Generate API key
        api_key = secrets.token_hex(16)
        
        # Insert client record
        now = datetime.now().isoformat()
        cursor.execute('''
        INSERT INTO clients (
            user_id, business_name, business_domain, contact_email, contact_phone,
            scanner_name, subscription_level, subscription_status, subscription_start,
            api_key, created_at, created_by, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            user_id,
            business_data.get('business_name'),
            business_data.get('business_domain'),
            business_data.get('contact_email'),
            business_data.get('contact_phone', ''),
            business_data.get('scanner_name', business_data.get('business_name') + ' Scanner'),
            business_data.get('subscription_level', 'basic'),
            'active',
            now,
            api_key,
            now,
            user_id
        ))
        
        client_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return {
            "status": "success", 
            "client_id": client_id, 
            "message": "Client registered successfully",
            "api_key": api_key
        }
        
    except Exception as e:
        logger.error(f"Client registration error: {e}")
        return {"status": "error", "message": f"Failed to register client: {str(e)}"}

def create_admin_user(username="admin", email="admin@example.com", password="admin123", full_name="System Administrator"):
    """Create admin user if it doesn't exist"""
    conn = sqlite3.connect(CLIENT_DB_PATH)
    cursor = conn.cursor()
    
    # Check if admin user exists
    cursor.execute("SELECT id FROM users WHERE role = 'admin'")
    admin = cursor.fetchone()
    
    if not admin:
        # Create admin user
        password_hash, salt = hash_password(password)
        
        cursor.execute('''
        INSERT INTO users (
            username, email, password_hash, salt, role, full_name, created_at, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ''', (username, email, password_hash, salt, 'admin', full_name, datetime.now().isoformat()))
        
        user_id = cursor.lastrowid
        
        # Create default admin client
        api_key = secrets.token_hex(16)
        now = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT INTO clients (
            user_id, business_name, business_domain, contact_email,
            scanner_name, subscription_level, subscription_status, subscription_start,
            api_key, created_at, created_by, active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ''', (
            user_id,
            'Admin Organization',
            'example.com',
            email,
            'Admin Scanner',
            'enterprise',
            'active',
            now,
            api_key,
            now,
            user_id
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Admin user created: {username}")
        return True
    
    conn.close()
    return False
