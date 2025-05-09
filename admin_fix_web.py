# admin_fix_web.py
import os
import re
import logging
import sqlite3
from datetime import datetime
import traceback
from flask import Flask, render_template, jsonify

def apply_admin_fixes(app):
    """
    Main function to apply all admin dashboard fixes
    
    Args:
        app: Flask application instance
        
    Returns:
        dict: Results of each fix operation
    """
    results = {
        'dashboard_function': fix_dashboard_function(),
        'dashboard_summary_function': add_dashboard_summary_function(),
        'list_clients_function': fix_list_clients_function(),
        'database_tables': create_required_tables(),
        'admin_routes': fix_admin_routes(app)
    }
    
    return results

def get_db_connection():
    """Get a connection to the client database"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    client_db_path = os.path.join(script_dir, 'client_scanner.db')
    
    if os.path.exists(client_db_path):
        return sqlite3.connect(client_db_path)
    
    # Try in current directory
    if os.path.exists('client_scanner.db'):
        return sqlite3.connect('client_scanner.db')
    
    # Create if not exists
    conn = sqlite3.connect(client_db_path)
    return conn

def fix_dashboard_function():
    """Fix the dashboard function in admin.py"""
    try:
        # Find admin.py
        admin_py_path = 'admin.py'
        if not os.path.exists(admin_py_path):
            return {'status': 'error', 'message': 'admin.py not found'}
        
        # Read the file
        with open(admin_py_path, 'r') as f:
            content = f.read()
        
        # Create backup
        with open(f"{admin_py_path}.bak", 'w') as f:
            f.write(content)
        
        # Fixed dashboard function
        fixed_function = """@admin_bp.route('/dashboard')
@admin_required
def dashboard(user):
    """Admin dashboard with summary statistics"""
    try:
        # Connect to the database
        from client_db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get dashboard summary data
        from client_db import get_dashboard_summary
        summary = get_dashboard_summary(cursor)
        
        # Get recent clients
        from client_db import list_clients
        recent_clients_result = list_clients(cursor, page=1, per_page=5)
        if recent_clients_result and 'clients' in recent_clients_result:
            recent_clients = recent_clients_result['clients']
        else:
            recent_clients = []
        
        # Close the connection
        conn.close()
        
        # Render dashboard template
        return render_template(
            'admin/admin-dashboard.html',
            user=user,
            dashboard_stats=summary,
            recent_clients=recent_clients
        )
    except Exception as e:
        import traceback
        print(f"Error in dashboard: {e}")
        print(traceback.format_exc())
        # Return a simple error page
        return render_template(
            'admin/error.html',
            error=f"Error loading dashboard: {str(e)}"
        )"""
        
        # Check if dashboard function exists
        dashboard_pattern = r'@admin_bp\.route\([\'"]\/dashboard[\'"]\)[\s\S]*?def dashboard\([^)]*\):[\s\S]*?(?=@|\Z)'
        if re.search(dashboard_pattern, content):
            # Replace existing function
            new_content = re.sub(dashboard_pattern, fixed_function, content)
            with open(admin_py_path, 'w') as f:
                f.write(new_content)
            return {'status': 'success', 'message': 'Dashboard function updated'}
        else:
            # Add the function
            with open(admin_py_path, 'a') as f:
                f.write("\n\n" + fixed_function)
            return {'status': 'success', 'message': 'Dashboard function added'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'traceback': traceback.format_exc()}

def add_dashboard_summary_function():
    """Add get_dashboard_summary function to client_db.py"""
    try:
        # Find client_db.py
        client_db_path = 'client_db.py'
        if not os.path.exists(client_db_path):
            return {'status': 'error', 'message': 'client_db.py not found'}
        
        # Read the file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Create backup
        with open(f"{client_db_path}.bak", 'w') as f:
            f.write(content)
        
        # Function to add
        function_content = """
def get_dashboard_summary(cursor=None):
    """Get summary statistics for the admin dashboard."""
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active scanners count
        try:
            cursor.execute("SELECT COUNT(*) FROM deployed_scanners WHERE deploy_status = 'deployed'")
            deployed_scanners = cursor.fetchone()[0]
        except:
            deployed_scanners = 0
        
        # Count scan history
        try:
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            active_scans = cursor.fetchone()[0]
        except:
            active_scans = 0
        
        # Calculate monthly revenue
        try:
            cursor.execute("SELECT COUNT(*), subscription_level FROM clients WHERE active = 1 GROUP BY subscription_level")
            subscription_counts = cursor.fetchall()
            
            # Define subscription prices
            subscription_prices = {'basic': 49, 'pro': 149, 'enterprise': 499}
            monthly_revenue = 0
            
            for count, level in subscription_counts:
                level = level.lower() if level else 'basic'
                price = subscription_prices.get(level, 0)
                monthly_revenue += count * price
        except:
            monthly_revenue = 0
        
        # Close connection if we created it
        if conn:
            conn.close()
        
        # Return the summary
        return {
            'total_clients': total_clients,
            'deployed_scanners': deployed_scanners,
            'active_scans': active_scans,
            'monthly_revenue': monthly_revenue
        }
    except Exception as e:
        import traceback
        print(f"Error in get_dashboard_summary: {e}")
        print(traceback.format_exc())
        
        # Return empty summary on error
        return {
            'total_clients': 0,
            'deployed_scanners': 0,
            'active_scans': 0,
            'monthly_revenue': 0
        }
"""
        
        # Check if function already exists
        if 'def get_dashboard_summary' in content:
            # Replace existing function
            pattern = r'def get_dashboard_summary[^(]*\([^)]*\):[\s\S]*?(?=def|\Z)'
            new_content = re.sub(pattern, function_content, content)
            with open(client_db_path, 'w') as f:
                f.write(new_content)
            return {'status': 'success', 'message': 'get_dashboard_summary function updated'}
        else:
            # Add new function
            with open(client_db_path, 'a') as f:
                f.write("\n" + function_content)
            return {'status': 'success', 'message': 'get_dashboard_summary function added'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'traceback': traceback.format_exc()}

def fix_list_clients_function():
    """Add or fix list_clients function in client_db.py"""
    try:
        # Find client_db.py
        client_db_path = 'client_db.py'
        if not os.path.exists(client_db_path):
            return {'status': 'error', 'message': 'client_db.py not found'}
        
        # Read the file
        with open(client_db_path, 'r') as f:
            content = f.read()
        
        # Function to add
        function_content = """
def list_clients(cursor=None, page=1, per_page=10, filters=None):
    """List clients with pagination and filtering."""
    try:
        # Use provided cursor or create a new connection
        conn = None
        if cursor is None:
            conn = get_db_connection()
            cursor = conn.cursor()
        
        # Default filters
        if filters is None:
            filters = {}
        
        # Build query
        query = "SELECT * FROM clients"
        params = []
        
        # Apply filters
        where_clauses = []
        
        if 'search' in filters and filters['search']:
            where_clauses.append("(business_name LIKE ? OR business_domain LIKE ? OR contact_email LIKE ?)")
            search_term = f"%{filters['search']}%"
            params.extend([search_term, search_term, search_term])
        
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append("subscription_level = ?")
            params.append(filters['subscription'])
        
        if 'active' in filters:
            where_clauses.append("active = ?")
            params.append(1 if filters['active'] else 0)
        
        # Add WHERE clause if needed
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        # Count total matching clients
        count_query = f"SELECT COUNT(*) FROM ({query})"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Add pagination
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page - 1) * per_page])
        
        # Execute query
        cursor.execute(query, params)
        
        # Convert to list of dictionaries
        clients = []
        for row in cursor.fetchall():
            client = {}
            for idx, col in enumerate(cursor.description):
                client[col[0]] = row[idx]
            clients.append(client)
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page if per_page > 0 else 1
        
        # Close connection if we created it
        if conn:
            conn.close()
        
        # Return clients and pagination info
        return {
            'clients': clients,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_count': total_count,
                'total_pages': total_pages
            }
        }
    except Exception as e:
        import traceback
        print(f"Error in list_clients: {e}")
        print(traceback.format_exc())
        
        # Return empty list on error
        return {
            'clients': [],
            'pagination': {
                'page': 1,
                'per_page': per_page,
                'total_count': 0,
                'total_pages': 1
            }
        }
"""
        
        # Check if function already exists
        if 'def list_clients' in content:
            # Replace existing function
            pattern = r'def list_clients[^(]*\([^)]*\):[\s\S]*?(?=def|\Z)'
            new_content = re.sub(pattern, function_content, content)
            with open(client_db_path, 'w') as f:
                f.write(new_content)
            return {'status': 'success', 'message': 'list_clients function updated'}
        else:
            # Add new function
            with open(client_db_path, 'a') as f:
                f.write("\n" + function_content)
            return {'status': 'success', 'message': 'list_clients function added'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'traceback': traceback.format_exc()}

def create_required_tables():
    """Create required database tables if they don't exist"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create clients table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            business_name TEXT NOT NULL,
            business_domain TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            contact_phone TEXT,
            scanner_name TEXT,
            subscription_level TEXT DEFAULT 'basic',
            subscription_status TEXT DEFAULT 'active',
            subscription_start TEXT,
            subscription_end TEXT,
            api_key TEXT UNIQUE,
            created_at TEXT,
            created_by INTEGER,
            updated_at TEXT,
            updated_by INTEGER,
            active INTEGER DEFAULT 1
        )
        ''')
        
        # Create deployed_scanners table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS deployed_scanners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            subdomain TEXT UNIQUE,
            domain TEXT,
            deploy_status TEXT DEFAULT 'pending',
            deploy_date TEXT,
            last_updated TEXT,
            config_path TEXT,
            template_version TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        )
        ''')
        
        # Create scan_history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            scan_id TEXT UNIQUE NOT NULL,
            timestamp TEXT,
            target TEXT,
            scan_type TEXT,
            status TEXT,
            report_path TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        )
        ''')
        
        # Check if clients table is empty
        cursor.execute("SELECT COUNT(*) FROM clients")
        if cursor.fetchone()[0] == 0:
            # Insert example client
            cursor.execute('''
            INSERT INTO clients (
                business_name, business_domain, contact_email, contact_phone, 
                scanner_name, subscription_level, created_at, active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                'Example Company', 'example.com', 'admin@example.com',
                '555-123-4567', 'Security Scanner', 'basic',
                datetime.now().isoformat(), 1
            ))
            
            # Get client ID
            client_id = cursor.lastrowid
            
            # Insert example scanner
            cursor.execute('''
            INSERT INTO deployed_scanners (
                client_id, subdomain, domain, deploy_status, deploy_date
            ) VALUES (?, ?, ?, ?, ?)
            ''', (
                client_id, 'example', 'yourscannerdomain.com', 'deployed', 
                datetime.now().isoformat()
            ))
        
        conn.commit()
        conn.close()
        
        return {'status': 'success', 'message': 'Required tables created successfully'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'traceback': traceback.format_exc()}

def fix_admin_routes(app):
    """Fix admin routes by adding missing routes"""
    try:
        from flask import render_template, request, redirect, url_for, flash, session
        
        # Find the admin blueprint
        admin_bp = None
        for name, blueprint in app.blueprints.items():
            if name == 'admin':
                admin_bp = blueprint
                break
        
        if not admin_bp:
            return {'status': 'error', 'message': 'Admin blueprint not found'}
        
        # Add subscriptions route
        @admin_bp.route('/subscriptions')
        def subscriptions():
            """Subscriptions management page"""
            try:
                # Get user from session for template
                from auth_utils import verify_session
                session_token = session.get('session_token')
                user = None
                if session_token:
                    result = verify_session(session_token)
                    if result['status'] == 'success':
                        user = result['user']
                
                # For now, just render a basic template
                return render_template(
                    'admin/subscription-management.html',
                    user=user
                )
            except Exception as e:
                # Return error page
                return render_template(
                    'admin/error.html',
                    error=f"Error loading subscriptions: {str(e)}"
                )
        
        # Add reports route
        @admin_bp.route('/reports')
        def reports():
            """Reports dashboard page"""
            try:
                # Get user from session for template
                from auth_utils import verify_session
                session_token = session.get('session_token')
                user = None
                if session_token:
                    result = verify_session(session_token)
                    if result['status'] == 'success':
                        user = result['user']
                
                # For now, just render a basic template
                return render_template(
                    'admin/reports-dashboard.html',
                    user=user
                )
            except Exception as e:
                # Return error page
                return render_template(
                    'admin/error.html',
                    error=f"Error loading reports: {str(e)}"
                )
        
        # Add settings route
        @admin_bp.route('/settings')
        def settings():
            """Settings dashboard page"""
            try:
                # Get user from session for template
                from auth_utils import verify_session
                session_token = session.get('session_token')
                user = None
                if session_token:
                    result = verify_session(session_token)
                    if result['status'] == 'success':
                        user = result['user']
                
                # For now, just render a basic template
                return render_template(
                    'admin/settings-dashboard.html',
                    user=user
                )
            except Exception as e:
                # Return error page
                return render_template(
                    'admin/error.html',
                    error=f"Error loading settings: {str(e)}"
                )
        
        # Add scanners route
        @admin_bp.route('/scanners')
        def scanners():
            """Scanner management page"""
            try:
                # Get user from session for template
                from auth_utils import verify_session
                session_token = session.get('session_token')
                user = None
                if session_token:
                    result = verify_session(session_token)
                    if result['status'] == 'success':
                        user = result['user']
                
                # For now, just render a basic template
                return render_template(
                    'admin/scanner-management.html',
                    deployed_scanners={
                        'scanners': [],
                        'pagination': {
                            'page': 1,
                            'per_page': 10,
                            'total_count': 0,
                            'total_pages': 1
                        }
                    },
                    filters={},
                    user=user
                )
            except Exception as e:
                # Return error page
                return render_template(
                    'admin/error.html',
                    error=f"Error loading scanners: {str(e)}"
                )
        
        return {'status': 'success', 'message': 'Admin routes fixed successfully'}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'traceback': traceback.format_exc()}

# Add a route to run the fixes
def add_admin_fix_route(app):
    @app.route('/run_admin_fix')
    def run_admin_fix():
        try:
            results = apply_admin_fixes(app)
            
            # Prepare HTML response
            result_html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Dashboard Fix Results</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; max-width: 800px; margin: 0 auto; }
                    h1 { color: #333; }
                    .success { color: green; }
                    .error { color: red; }
                    .result-item { margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
                    .result-status { font-weight: bold; }
                </style>
            </head>
            <body>
                <h1>Admin Dashboard Fix Results</h1>
            """
            
            for fix_name, result in results.items():
                status_class = "success" if result.get('status') == 'success' else "error"
                result_html += f"""
                <div class="result-item">
                    <div class="result-status {status_class}">
                        {fix_name}: {result.get('status', 'unknown')}
                    </div>
                    <div class="result-message">
                        {result.get('message', '')}
                    </div>
                </div>
                """
            
            result_html += """
                <div style="margin-top: 20px;">
                    <a href="/admin/dashboard">Go to Admin Dashboard</a>
                </div>
            </body>
            </html>
            """
            
            return result_html
        
        except Exception as e:
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Fix Error</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; max-width: 800px; margin: 0 auto; }}
                    h1 {{ color: red; }}
                    .error {{ color: red; }}
                    pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Error Running Admin Fix</h1>
                <div class="error">{str(e)}</div>
                <h2>Traceback:</h2>
                <pre>{traceback.format_exc()}</pre>
                <div>
                    <a href="/">Return to Home</a>
                </div>
            </body>
            </html>
            """
            
            return error_html
