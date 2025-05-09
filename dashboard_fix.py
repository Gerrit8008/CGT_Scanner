#!/usr/bin/env python3
"""
Hotfix script to fix admin dashboard issues
"""
import os
import re
import sys
import sqlite3
import traceback

def apply_dashboard_fix(file_path):
    """Fix the dashboard function in admin.py"""
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        
        # Pattern to match the entire dashboard function
        dashboard_pattern = r"@admin_bp\.route\('/dashboard'\)[\s\S]*?def dashboard[\s\S]*?return render_template\([^)]*\)"
        
        # Check if we can find the pattern
        if not re.search(dashboard_pattern, content):
            print("Could not find dashboard function in admin.py. Manual fix required.")
            return False
        
        # New dashboard function implementation
        new_dashboard_function = """@admin_bp.route('/dashboard')
@admin_required
def dashboard(user):
    """Admin dashboard with summary statistics"""
    try:
        # Connect to the database
        from client_db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get dashboard summary data with the cursor parameter
        summary = get_dashboard_summary(cursor)
        
        # Get recent clients with proper parameters
        # Removed sort_by parameter that was causing an error
        recent_clients = list_clients(page=1, per_page=5)['clients']
        
        # Close the connection
        conn.close()
        
        # Render dashboard template
        # Changed 'summary' to 'dashboard_stats' to match template expectations
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
        
        # Replace the old function with the new one
        updated_content = re.sub(dashboard_pattern, new_dashboard_function, content)
        
        # Write the updated content back to the file
        with open(file_path, 'w') as file:
            file.write(updated_content)
        
        print("Successfully fixed dashboard function in admin.py")
        return True
    except Exception as e:
        print(f"Error applying dashboard fix: {e}")
        traceback.print_exc()
        return False

def add_get_dashboard_summary(client_db_path):
    """Add or update the get_dashboard_summary function in client_db.py"""
    try:
        with open(client_db_path, 'r') as file:
            content = file.read()
        
        # Check if the function already exists
        if 'def get_dashboard_summary' in content:
            # Replace the existing function
            pattern = r"def get_dashboard_summary\([^)]*\):[\s\S]*?(?=def |$)"
            new_function = """def get_dashboard_summary(cursor=None):
    """
    Get dashboard summary statistics
    
    Args:
        cursor (sqlite3.Cursor, optional): Database cursor. If None, a new connection is created.
        
    Returns:
        dict: Dashboard summary statistics
    """
    # Create connection and cursor if not provided
    conn = None
    close_conn = False
    if cursor is None:
        conn = get_db_connection()
        cursor = conn.cursor()
        close_conn = True
    
    try:
        # Get total clients count
        cursor.execute("SELECT COUNT(*) FROM clients")
        total_clients = cursor.fetchone()[0]
        
        # Get active clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 1")
        active_clients = cursor.fetchone()[0]
        
        # Get inactive clients count
        cursor.execute("SELECT COUNT(*) FROM clients WHERE active = 0")
        inactive_clients = cursor.fetchone()[0]
        
        # Get total scan count
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        # Get today's scan count
        import datetime
        today = datetime.date.today().isoformat()
        cursor.execute("SELECT COUNT(*) FROM scans WHERE DATE(scan_date) = ?", (today,))
        scans_today = cursor.fetchone()[0]
        
        # Get total users count
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        # Get client distribution by subscription
        cursor.execute(\"\"\"
            SELECT subscription, COUNT(*) as count
            FROM clients
            GROUP BY subscription
        \"\"\")
        subscription_distribution = {}
        for row in cursor.fetchall():
            subscription_distribution[row[0]] = row[1]
        
        # Return summary data
        return {
            'total_clients': total_clients,
            'active_clients': active_clients,
            'inactive_clients': inactive_clients,
            'total_scans': total_scans,
            'scans_today': scans_today,
            'total_users': total_users,
            'subscription_distribution': subscription_distribution
        }
    finally:
        # Close connection if we opened it
        if close_conn and conn:
            conn.close()
"""
            updated_content = re.sub(pattern, new_function, content)
        else:
            # Append the new function to the end of the file
            updated_content = content + "\n\n" + new_function
        
        # Write the updated content back to the file
        with open(client_db_path, 'w') as file:
            file.write(updated_content)
        
        print("Successfully added/updated get_dashboard_summary function in client_db.py")
        return True
    except Exception as e:
        print(f"Error updating get_dashboard_summary function: {e}")
        traceback.print_exc()
        return False

def fix_list_clients(client_db_path):
    """Fix the list_clients function in client_db.py"""
    try:
        with open(client_db_path, 'r') as file:
            content = file.read()
        
        # Check if the function already exists
        if 'def list_clients' in content:
            # Pattern to match the entire list_clients function
            pattern = r"def list_clients\([^)]*\):[\s\S]*?(?=def |$)"
            
            # New list_clients function implementation
            new_function = """def list_clients(page=1, per_page=10, filters=None, sort_by=None, sort_dir='asc'):
    """
    List clients with pagination and filtering
    
    Args:
        page (int): Page number
        per_page (int): Items per page
        filters (dict, optional): Filter conditions
        sort_by (str, optional): Column to sort by
        sort_dir (str, optional): Sort direction ('asc' or 'desc')
        
    Returns:
        dict: Dictionary with clients and pagination info
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Base query
    query = "SELECT * FROM clients"
    count_query = "SELECT COUNT(*) FROM clients"
    
    # Add filter conditions if provided
    params = []
    where_clauses = []
    
    if filters:
        if 'subscription' in filters and filters['subscription']:
            where_clauses.append("subscription = ?")
            params.append(filters['subscription'])
        
        if 'status' in filters and filters['status']:
            active = 1 if filters['status'].lower() == 'active' else 0
            where_clauses.append("active = ?")
            params.append(active)
        
        if 'search' in filters and filters['search']:
            search_term = f"%{filters['search']}%"
            where_clauses.append("(business_name LIKE ? OR business_domain LIKE ? OR contact_email LIKE ?)")
            params.extend([search_term, search_term, search_term])
    
    # Add WHERE clause if there are filter conditions
    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)
        count_query += " WHERE " + " AND ".join(where_clauses)
    
    # Add sorting
    if sort_by:
        valid_columns = ['id', 'business_name', 'business_domain', 'created_at', 'subscription']
        if sort_by in valid_columns:
            sort_direction = "DESC" if sort_dir.lower() == 'desc' else "ASC"
            query += f" ORDER BY {sort_by} {sort_direction}"
        else:
            # Default sorting
            query += " ORDER BY id DESC"
    else:
        # Default sorting
        query += " ORDER BY id DESC"
    
    # Get total count for pagination
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]
    
    # Add pagination
    offset = (page - 1) * per_page
    query += " LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    # Execute final query
    cursor.execute(query, params)
    clients = [dict(row) for row in cursor.fetchall()]
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
    
    # Build pagination object
    pagination = {
        'page': page,
        'per_page': per_page,
        'total_count': total_count,
        'total_pages': total_pages
    }
    
    conn.close()
    
    return {
        'clients': clients,
        'pagination': pagination
    }
"""
            # Replace the old function with the new one
            updated_content = re.sub(pattern, new_function, content)
            
            # Write the updated content back to the file
            with open(client_db_path, 'w') as file:
                file.write(updated_content)
            
            print("Successfully fixed list_clients function in client_db.py")
            return True
        else:
            print("Could not find list_clients function in client_db.py. Manual fix required.")
            return False
    except Exception as e:
        print(f"Error fixing list_clients function: {e}")
        traceback.print_exc()
        return False

def create_missing_tables():
    """Create any missing tables in the database"""
    try:
        # Get the database path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, 'client_scanner.db')
        
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the scans table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        if not cursor.fetchone():
            print("Creating missing 'scans' table...")
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER,
                scan_id TEXT,
                target TEXT,
                scan_date TEXT,
                results TEXT,
                FOREIGN KEY (client_id) REFERENCES clients(id)
            )
            ''')
            print("Successfully created 'scans' table.")
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating missing tables: {e}")
        traceback.print_exc()
        return False

def main():
    """Main function to apply all fixes"""
    print("Starting hotfix for admin dashboard issues...")
    
    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define file paths
    admin_py = os.path.join(script_dir, 'admin.py')
    client_db_py = os.path.join(script_dir, 'client_db.py')
    
    # Verify files exist
    if not os.path.exists(admin_py):
        print(f"Error: admin.py not found at {admin_py}")
        return False
    
    if not os.path.exists(client_db_py):
        print(f"Error: client_db.py not found at {client_db_py}")
        return False
    
    # Apply fixes
    dashboard_fix = apply_dashboard_fix(admin_py)
    dashboard_summary_fix = add_get_dashboard_summary(client_db_py)
    list_clients_fix = fix_list_clients(client_db_py)
    tables_fix = create_missing_tables()
    
    # Report results
    if dashboard_fix and dashboard_summary_fix and list_clients_fix and tables_fix:
        print("\nAll fixes applied successfully!")
        print("\nThe admin dashboard should now work correctly.")
        return True
    else:
        print("\nSome fixes could not be applied. Please check the logs above.")
        print("\nManual intervention may be required.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
