# emergency_access.py - Standalone emergency access module
from flask import Blueprint, request, redirect, url_for, render_template, session, flash
import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
CLIENT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'client_scanner.db')

# Create blueprint for emergency routes
emergency_bp = Blueprint('emergency', __name__)

@emergency_bp.route('/emergency-login', methods=['GET', 'POST'])
def emergency_login():
    """Emergency login in case of auth issues"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('auth/login.html', error="Please provide username and password")
        
        try:
            # Connect directly to database
            conn = sqlite3.connect(CLIENT_DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find user
            cursor.execute('SELECT * FROM users WHERE username = ? AND active = 1', (username,))
            user = cursor.fetchone()
            
            if not user:
                conn.close()
                flash("Invalid credentials", "danger")
                return redirect(url_for('emergency.emergency_login'))
                
            # Try password verification
            try:
                # PBKDF2 method (newer)
                salt = user['salt']
                stored_hash = user['password_hash']
                
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    password.encode(), 
                    salt.encode(), 
                    100000
                ).hex()
                
                pw_matches = (password_hash == stored_hash)
            except Exception as e:
                logger.error(f"Error in password verification: {e}")
                # Simple SHA-256 method (older fallback)
                try:
                    password_hash = hashlib.sha256((password + user['salt']).encode()).hexdigest()
                    pw_matches = (password_hash == user['password_hash'])
                except Exception as e2:
                    logger.error(f"Error in fallback password verification: {e2}")
                    pw_matches = False
            
            if not pw_matches:
                conn.close()
                flash("Invalid credentials", "danger")
                return redirect(url_for('emergency.emergency_login'))
            
            # Password matches - create session directly
            session_token = secrets.token_hex(32)
            created_at = datetime.now().isoformat()
            expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
            
            # Clear existing sessions for this user
            cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user['id'],))
            
            # Insert new session
            cursor.execute('''
            INSERT INTO sessions (
                user_id, session_token, created_at, expires_at, ip_address
            ) VALUES (?, ?, ?, ?, ?)
            ''', (user['id'], session_token, created_at, expires_at, request.remote_addr))
            
            # Commit changes
            conn.commit()
            
            # Store in session
            session.clear()  # Clear any old session data
            session['session_token'] = session_token
            session['username'] = user['username']
            session['role'] = user['role']
            session['user_id'] = user['id']
            
            # Log success
            logger.info(f"Emergency login successful for user: {username}")
            
            # Redirect based on role
            flash("Emergency login successful!", "success")
            if user['role'] == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
                
        except Exception as e:
            import traceback
            logger.error(f"Error in emergency login: {e}")
            logger.error(traceback.format_exc())
            
            return f"""
            <html>
                <head>
                    <title>Emergency Login Error</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; padding: 20px; }}
                        pre {{ background: #f5f5f5; padding: 15px; overflow: auto; }}
                    </style>
                </head>
                <body>
                    <h1>Emergency Login Error</h1>
                    <p>Error: {str(e)}</p>
                    <pre>{traceback.format_exc()}</pre>
                    <form method="post" action="/emergency-login">
                        <label>Username: <input type="text" name="username" value="{username}"></label><br>
                        <label>Password: <input type="password" name="password"></label><br>
                        <button type="submit">Try Again</button>
                    </form>
                    <div>
                        <h2>Debug Information</h2>
                        <p>Database Path: {CLIENT_DB_PATH}</p>
                        <p>Database Exists: {os.path.exists(CLIENT_DB_PATH)}</p>
                    </div>
                </body>
            </html>
            """
    
    # Show login form for GET requests
    return '''
    <html>
        <head>
            <title>Emergency Login</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px; 
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                }
                form { 
                    margin-top: 20px; 
                    width: 300px;
                    border: 1px solid #ddd;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                h1 { color: #333; }
                input { 
                    margin: 5px 0; 
                    padding: 8px; 
                    width: 100%; 
                    box-sizing: border-box;
                }
                button { 
                    padding: 10px 16px; 
                    background: #4CAF50; 
                    color: white; 
                    border: none; 
                    border-radius: 4px;
                    cursor: pointer;
                    width: 100%;
                    margin-top: 15px;
                }
                button:hover {
                    background: #45a049;
                }
                .notice {
                    margin-top: 20px;
                    padding: 10px;
                    background: #fff8e1;
                    border: 1px solid #ffe0b2;
                    border-radius: 4px;
                    width: 300px;
                }
            </style>
        </head>
        <body>
            <h1>Emergency Login</h1>
            <form method="post" action="/emergency-login">
                <div>
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username">
                </div>
                <div>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password">
                </div>
                <button type="submit">Login</button>
            </form>
            <div class="notice">
                <p>This is for emergency access in case of authentication issues.</p>
                <p>Try using <strong>admin</strong> and <strong>admin123</strong> if you're unsure.</p>
            </div>
        </body>
    </html>
    '''

@emergency_bp.route('/db_fix')
def direct_db_fix():
    """Direct database fix route for emergency repair"""
    results = []
    try:
        # Import necessary modules
        import sqlite3
        import secrets
        import hashlib
        from datetime import datetime
        
        # Define database path
        results.append(f"Working with database at: {CLIENT_DB_PATH}")
        results.append(f"Database exists: {os.path.exists(CLIENT_DB_PATH)}")
        
        # Connect to the database or create it if it doesn't exist
        conn = sqlite3.connect(CLIENT_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check database structure
        results.append("Checking database tables...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        results.append(f"Found tables: {[table[0] for table in tables]}")
        
        # Create users table if needed
        if 'users' not in [table[0] for table in tables]:
            results.append("Creating users table...")
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
        
        # Create sessions table if needed
        if 'sessions' not in [table[0] for table in tables]:
            results.append("Creating sessions table...")
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
        
        # Clear all sessions
        cursor.execute("DELETE FROM sessions")
        results.append("Cleared all sessions for a fresh start")
        
        # Create a new admin user with simple password
        results.append("Creating/updating admin user...")
        
        # Generate password hash
        salt = secrets.token_hex(16)
        password = 'admin123'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt.encode(), 
            100000
        ).hex()
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = cursor.fetchone()
        
        if admin_user:
            # Update existing admin
            cursor.execute('''
            UPDATE users SET 
                password_hash = ?, 
                salt = ?,
                role = 'admin',
                active = 1
            WHERE username = 'admin'
            ''', (password_hash, salt))
            results.append("Updated existing admin user")
        else:
            # Create a new admin user
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
            results.append("Created new admin user")
        
        # Commit changes
        conn.commit()
        
        # Verify creation
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = 'admin'")
        user = cursor.fetchone()
        if user:
            results.append(f"Admin user verified: ID={user['id']}, username={user['username']}, email={user['email']}, role={user['role']}")
        
        # Close connection
        conn.close()
        
        results.append("Database fix completed!")
        results.append("You can now login with:")
        results.append("Username: admin")
        results.append("Password: admin123")
        
        return "<br>".join(results)
    except Exception as e:
        import traceback
        results.append(f"Error: {str(e)}")
        results.append(f"<pre>{traceback.format_exc()}</pre>")
        return "<br>".join(results)
