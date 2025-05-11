# settings_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from client_db import get_db_connection
from auth_utils import verify_session, generate_password_hash
import sqlite3
from datetime import datetime
import os
import json

# Define settings blueprint
settings_bp = Blueprint('settings', __name__, url_prefix='/admin')

# Middleware to require admin login
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            flash('You need administrative privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    decorated_function.__doc__ = f.__doc__
    return decorated_function

@settings_bp.route('/settings')
@admin_required
def settings_dashboard(user):
    """Settings dashboard"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get system settings
        cursor.execute("SELECT * FROM system_settings LIMIT 1")
        settings = dict(cursor.fetchone() or {})
        
        # If settings table doesn't exist or is empty, create default settings
        if not settings:
            try:
                # Create settings table if it doesn't exist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS system_settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        company_name TEXT,
                        company_logo TEXT,
                        primary_color TEXT,
                        secondary_color TEXT,
                        email_from TEXT,
                        smtp_host TEXT,
                        smtp_port INTEGER,
                        smtp_username TEXT,
                        smtp_password TEXT,
                        analytics_enabled INTEGER DEFAULT 0,
                        analytics_id TEXT,
                        custom_css TEXT,
                        custom_js TEXT,
                        last_updated TEXT,
                        updated_by INTEGER,
                        FOREIGN KEY (updated_by) REFERENCES users(id)
                    )
                """)
                
                # Insert default settings
                cursor.execute("""
                    INSERT INTO system_settings (
                        company_name, 
                        company_logo, 
                        primary_color, 
                        secondary_color, 
                        email_from,
                        last_updated,
                        updated_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    'Scanner Platform',
                    '/static/img/logo.png',
                    '#FF6900',
                    '#808588',
                    'admin@scannerplatform.com',
                    datetime.now().isoformat(),
                    user['id']
                ))
                
                conn.commit()
                
                # Get the newly created settings
                cursor.execute("SELECT * FROM system_settings LIMIT 1")
                settings = dict(cursor.fetchone() or {})
            except Exception as e:
                flash(f"Error creating default settings: {str(e)}", "danger")
                settings = {}
        
        # Get API settings
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_enabled INTEGER DEFAULT 0,
                    rate_limit_per_minute INTEGER DEFAULT 60,
                    rate_limit_per_day INTEGER DEFAULT 1000,
                    cors_enabled INTEGER DEFAULT 0,
                    allowed_origins TEXT,
                    require_authentication INTEGER DEFAULT 1,
                    last_updated TEXT,
                    updated_by INTEGER,
                    FOREIGN KEY (updated_by) REFERENCES users(id)
                )
            """)
            
            cursor.execute("SELECT * FROM api_settings LIMIT 1")
            api_settings = dict(cursor.fetchone() or {})
            
            if not api_settings:
                # Insert default API settings
                cursor.execute("""
                    INSERT INTO api_settings (
                        api_enabled,
                        rate_limit_per_minute,
                        rate_limit_per_day,
                        cors_enabled,
                        allowed_origins,
                        require_authentication,
                        last_updated,
                        updated_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    1,  # API enabled by default
                    60,  # 60 requests per minute
                    1000,  # 1000 requests per day
                    0,  # CORS disabled by default
                    '*',  # Allow all origins
                    1,  # Require authentication
                    datetime.now().isoformat(),
                    user['id']
                ))
                
                conn.commit()
                
                cursor.execute("SELECT * FROM api_settings LIMIT 1")
                api_settings = dict(cursor.fetchone() or {})
        except Exception as e:
            flash(f"Error retrieving API settings: {str(e)}", "danger")
            api_settings = {}
            
        # Get backup settings
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    auto_backup_enabled INTEGER DEFAULT 0,
                    backup_frequency TEXT DEFAULT 'daily',
                    backup_retention_days INTEGER DEFAULT 7,
                    backup_path TEXT,
                    last_backup TEXT,
                    last_updated TEXT,
                    updated_by INTEGER,
                    FOREIGN KEY (updated_by) REFERENCES users(id)
                )
            """)
            
            cursor.execute("SELECT * FROM backup_settings LIMIT 1")
            backup_settings = dict(cursor.fetchone() or {})
            
            if not backup_settings:
                # Create backup directory if it doesn't exist
                backup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
                os.makedirs(backup_path, exist_ok=True)
                
                # Insert default backup settings
                cursor.execute("""
                    INSERT INTO backup_settings (
                        auto_backup_enabled,
                        backup_frequency,
                        backup_retention_days,
                        backup_path,
                        last_updated,
                        updated_by
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    0,  # Auto backup disabled by default
                    'daily',
                    7,
                    backup_path,
                    datetime.now().isoformat(),
                    user['id']
                ))
                
                conn.commit()
                
                cursor.execute("SELECT * FROM backup_settings LIMIT 1")
                backup_settings = dict(cursor.fetchone() or {})
        except Exception as e:
            flash(f"Error retrieving backup settings: {str(e)}", "danger")
            backup_settings = {}
        
        conn.close()
        
        return render_template(
            'admin/settings-dashboard.html',
            user=user,
            settings=settings,
            api_settings=api_settings,
            backup_settings=backup_settings
        )
        
    except Exception as e:
        conn.close()
        flash(f"Error loading settings: {str(e)}", "danger")
        return render_template(
            'admin/settings-dashboard.html',
            user=user,
            settings={},
            api_settings={},
            backup_settings={}
        )

@settings_bp.route('/settings/general', methods=['POST'])
@admin_required
def update_general_settings(user):
    """Update general system settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        company_name = request.form.get('company_name')
        primary_color = request.form.get('primary_color')
        secondary_color = request.form.get('secondary_color')
        email_from = request.form.get('email_from')
        
        # Handle logo upload
        company_logo = None
        if 'company_logo' in request.files and request.files['company_logo'].filename:
            from werkzeug.utils import secure_filename
            
            logo_file = request.files['company_logo']
            logo_filename = secure_filename(logo_file.filename)
            
            # Create uploads directory if it doesn't exist
            upload_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
            os.makedirs(upload_path, exist_ok=True)
            
            # Save the file
            logo_path = os.path.join(upload_path, logo_filename)
            logo_file.save(logo_path)
            
            # Set logo path relative to static folder
            company_logo = f'/static/uploads/{logo_filename}'
        
        # Update settings
        cursor.execute("""
            UPDATE system_settings SET
                company_name = ?,
                primary_color = ?,
                secondary_color = ?,
                email_from = ?,
                last_updated = ?,
                updated_by = ?
                """ + 
                (", company_logo = ?" if company_logo else "") + 
                """
            WHERE id = 1
        """, 
        (
            company_name,
            primary_color,
            secondary_color,
            email_from,
            datetime.now().isoformat(),
            user['id']
        ) + ((company_logo,) if company_logo else ()))
        
        conn.commit()
        
        flash("General settings updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating general settings: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/settings/email', methods=['POST'])
@admin_required
def update_email_settings(user):
    """Update email settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        smtp_host = request.form.get('smtp_host')
        smtp_port = request.form.get('smtp_port', type=int)
        smtp_username = request.form.get('smtp_username')
        smtp_password = request.form.get('smtp_password')
        
        # Update settings
        cursor.execute("""
            UPDATE system_settings SET
                smtp_host = ?,
                smtp_port = ?,
                smtp_username = ?,
                smtp_password = ?,
                last_updated = ?,
                updated_by = ?
            WHERE id = 1
        """, (
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            datetime.now().isoformat(),
            user['id']
        ))
        
        conn.commit()
        
        flash("Email settings updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating email settings: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/settings/api', methods=['POST'])
@admin_required
def update_api_settings(user):
    """Update API settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        api_enabled = 1 if request.form.get('api_enabled') else 0
        rate_limit_per_minute = request.form.get('rate_limit_per_minute', type=int)
        rate_limit_per_day = request.form.get('rate_limit_per_day', type=int)
        cors_enabled = 1 if request.form.get('cors_enabled') else 0
        allowed_origins = request.form.get('allowed_origins')
        require_authentication = 1 if request.form.get('require_authentication') else 0
        
        # Update settings
        cursor.execute("""
            UPDATE api_settings SET
                api_enabled = ?,
                rate_limit_per_minute = ?,
                rate_limit_per_day = ?,
                cors_enabled = ?,
                allowed_origins = ?,
                require_authentication = ?,
                last_updated = ?,
                updated_by = ?
            WHERE id = 1
        """, (
            api_enabled,
            rate_limit_per_minute,
            rate_limit_per_day,
            cors_enabled,
            allowed_origins,
            require_authentication,
            datetime.now().isoformat(),
            user['id']
        ))
        
        conn.commit()
        
        flash("API settings updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating API settings: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/settings/backup', methods=['POST'])
@admin_required
def update_backup_settings(user):
    """Update backup settings"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        auto_backup_enabled = 1 if request.form.get('auto_backup_enabled') else 0
        backup_frequency = request.form.get('backup_frequency')
        backup_retention_days = request.form.get('backup_retention_days', type=int)
        backup_path = request.form.get('backup_path')
        
        # Create backup directory if it doesn't exist
        if backup_path:
            os.makedirs(backup_path, exist_ok=True)
        
        # Update settings
        cursor.execute("""
            UPDATE backup_settings SET
                auto_backup_enabled = ?,
                backup_frequency = ?,
                backup_retention_days = ?,
                backup_path = ?,
                last_updated = ?,
                updated_by = ?
            WHERE id = 1
        """, (
            auto_backup_enabled,
            backup_frequency,
            backup_retention_days,
            backup_path,
            datetime.now().isoformat(),
            user['id']
        ))
        
        conn.commit()
        
        flash("Backup settings updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating backup settings: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/settings/backup/run', methods=['POST'])
@admin_required
def run_backup(user):
    """Run a manual database backup"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get backup settings
        cursor.execute("SELECT * FROM backup_settings LIMIT 1")
        backup_settings = dict(cursor.fetchone() or {})
        
        if not backup_settings:
            flash("Backup settings not found", "danger")
            return redirect(url_for('settings.settings_dashboard'))
        
        # Ensure backup directory exists
        backup_path = backup_settings.get('backup_path')
        if not backup_path:
            backup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
            os.makedirs(backup_path, exist_ok=True)
        
        # Generate backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"scanner_db_backup_{timestamp}.db"
        backup_file = os.path.join(backup_path, backup_filename)
        
        # Close the current connection to perform backup
        conn.close()
        
        # Get database path
        from client_db import CLIENT_DB_PATH
        
        # Create a backup using SQLite's backup API
        import shutil
        shutil.copy2(CLIENT_DB_PATH, backup_file)
        
        # Reconnect to update backup timestamp
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE backup_settings SET
                last_backup = ?,
                last_updated = ?,
                updated_by = ?
            WHERE id = 1
        """, (
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            user['id']
        ))
        
        conn.commit()
        
        flash(f"Backup created successfully: {backup_filename}", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"Error creating backup: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        if conn:
            conn.close()

@settings_bp.route('/settings/password', methods=['POST'])
@admin_required
def update_password(user):
    """Update admin password"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify passwords match
        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect(url_for('settings.settings_dashboard'))
        
        # Verify current password
        cursor.execute("SELECT password_hash, salt FROM users WHERE id = ?", (user['id'],))
        user_data = cursor.fetchone()
        
        if not user_data:
            flash("User not found", "danger")
            return redirect(url_for('settings.settings_dashboard'))
        
        # Verify current password
        from auth_utils import verify_password
        if not verify_password(current_password, user_data['password_hash'], user_data['salt']):
            flash("Current password is incorrect", "danger")
            return redirect(url_for('settings.settings_dashboard'))
        
        # Generate new password hash
        from auth_utils import hash_password
        password_hash, salt = hash_password(new_password)
        
        # Update password
        cursor.execute("""
            UPDATE users SET
                password_hash = ?,
                salt = ?
            WHERE id = ?
        """, (
            password_hash,
            salt,
            user['id']
        ))
        
        conn.commit()
        
        flash("Password updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating password: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/settings/custom-code', methods=['POST'])
@admin_required
def update_custom_code(user):
    """Update custom CSS and JavaScript"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get form data
        custom_css = request.form.get('custom_css')
        custom_js = request.form.get('custom_js')
        analytics_enabled = 1 if request.form.get('analytics_enabled') else 0
        analytics_id = request.form.get('analytics_id')
        
        # Update settings
        cursor.execute("""
            UPDATE system_settings SET
                custom_css = ?,
                custom_js = ?,
                analytics_enabled = ?,
                analytics_id = ?,
                last_updated = ?,
                updated_by = ?
            WHERE id = 1
        """, (
            custom_css,
            custom_js,
            analytics_enabled,
            analytics_id,
            datetime.now().isoformat(),
            user['id']
        ))
        
        conn.commit()
        
        flash("Custom code settings updated successfully", "success")
        return redirect(url_for('settings.settings_dashboard'))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating custom code: {str(e)}", "danger")
        return redirect(url_for('settings.settings_dashboard'))
    finally:
        conn.close()

@settings_bp.route('/api/settings/system-info')
@admin_required
def api_system_info(user):
    """API endpoint to get system information"""
    try:
        # Get system information
        import platform
        import psutil
        
        # OS info
        os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor()
        }
        
        # Python info
        python_info = {
            'version': platform.python_version(),
            'implementation': platform.python_implementation(),
            'compiler': platform.python_compiler()
        }
        
        # System resources
        resources = {
            'cpu_count': psutil.cpu_count(),
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'memory_percent': psutil.virtual_memory().percent,
            'disk_total': psutil.disk_usage('/').total,
            'disk_used': psutil.disk_usage('/').used,
            'disk_free': psutil.disk_usage('/').free,
            'disk_percent': psutil.disk_usage('/').percent
        }
        
        # Database info
        from client_db import CLIENT_DB_PATH
        import os
        
        db_info = {
            'db_path': CLIENT_DB_PATH,
            'db_size': os.path.getsize(CLIENT_DB_PATH) if os.path.exists(CLIENT_DB_PATH) else 0,
            'db_exists': os.path.exists(CLIENT_DB_PATH)
        }
        
        # Format for human-readable output
        for key in ['memory_total', 'memory_available', 'disk_total', 'disk_used', 'disk_free']:
            resources[f"{key}_human"] = format_bytes(resources[key])
        
        db_info['db_size_human'] = format_bytes(db_info['db_size'])
        
        return jsonify({
            'status': 'success',
            'data': {
                'os': os_info,
                'python': python_info,
                'resources': resources,
                'database': db_info
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def format_bytes(bytes):
    """Format bytes to human-readable format"""
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024 * 1024:
        return f"{bytes / 1024:.2f} KB"
    elif bytes < 1024 * 1024 * 1024:
        return f"{bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes / (1024 * 1024 * 1024):.2f} GB"
