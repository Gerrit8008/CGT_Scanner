# admin_fix_integration.py
"""
Integration script to apply admin dashboard fixes.
This script calls the fix functions from both dashboard_fix.py and route_fix.py
"""

import os
import logging
import traceback

def apply_admin_fixes(app):
    """
    Apply all admin dashboard fixes
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if all fixes were applied successfully, False otherwise
    """
    try:
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logger = logging.getLogger(__name__)
        
        logger.info("Starting admin dashboard fixes...")
        
        # Get file paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        admin_py_path = os.path.join(script_dir, 'admin.py')
        client_db_py_path = os.path.join(script_dir, 'client_db.py')
        
        # Verify files exist
        if not os.path.exists(admin_py_path):
            logger.error(f"Error: admin.py not found at {admin_py_path}")
            return False
        
        if not os.path.exists(client_db_py_path):
            logger.error(f"Error: client_db.py not found at {client_db_py_path}")
            return False
        
        # Import fix functions
        from dashboard_fix import apply_dashboard_fix, add_get_dashboard_summary, fix_list_clients, create_missing_tables
        from route_fix import fix_admin_routes
        
        # Apply dashboard fixes
        logger.info("Applying dashboard function fix...")
        dashboard_result = apply_dashboard_fix(admin_py_path)
        
        logger.info("Adding/updating get_dashboard_summary function...")
        summary_result = add_get_dashboard_summary(client_db_py_path)
        
        logger.info("Fixing list_clients function...")
        list_clients_result = fix_list_clients(client_db_py_path)
        
        logger.info("Creating missing database tables...")
        tables_result = create_missing_tables()
        
        # Apply route fixes
        logger.info("Adding missing admin routes...")
        routes_result = fix_admin_routes(app)
        
        # Calculate overall success
        success = dashboard_result and summary_result and list_clients_result and tables_result and routes_result
        
        if success:
            logger.info("All admin dashboard fixes applied successfully!")
        else:
            logger.warning("Some fixes could not be applied. Check the logs for details.")
            
            # Log specific failures
            if not dashboard_result:
                logger.error("Failed to fix dashboard function")
            if not summary_result:
                logger.error("Failed to add/update get_dashboard_summary function")
            if not list_clients_result:
                logger.error("Failed to fix list_clients function")
            if not tables_result:
                logger.error("Failed to create missing database tables")
            if not routes_result:
                logger.error("Failed to add missing admin routes")
        
        return success
    except Exception as e:
        logging.error(f"Error applying admin fixes: {e}")
        logging.error(traceback.format_exc())
        return False

# If script is run directly
if __name__ == "__main__":
    print("This script should be imported and used in your Flask application.")
    print("Add the following code to your app.py file:")
    print("\n# Import and apply admin fixes")
    print("from admin_fix_integration import apply_admin_fixes")
    print("apply_admin_fixes(app)\n")
