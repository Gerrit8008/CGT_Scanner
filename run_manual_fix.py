# run_manual_fix.py
# This script applies the admin route fixes without needing to modify the app.py file

import os
import sys
import logging
import importlib.util
import flask

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def run_fix():
    """Run the admin route fixes"""
    # First, check if admin_route_fix.py exists
    if not os.path.exists('admin_route_fix.py'):
        logger.error("admin_route_fix.py not found in the current directory")
        print("Please make sure admin_route_fix.py is in the same directory as this script")
        return False
    
    # Load the admin_route_fix module
    spec = importlib.util.spec_from_file_location("admin_route_fix", "admin_route_fix.py")
    admin_route_fix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admin_route_fix)
    
    # Try to import the Flask app
    try:
        from app import app
        logger.info("Successfully imported Flask app from app.py")
    except ImportError:
        logger.error("Could not import Flask app from app.py")
        print("Please make sure app.py is in the same directory and contains a Flask app")
        return False
    
    # Apply the fixes
    try:
        success = admin_route_fix.apply_admin_route_fixes(app)
        return success
    except Exception as e:
        logger.error(f"Error applying admin route fixes: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    print("Running Admin Route Fix")
    print("----------------------")
    
    success = run_fix()
    
    if success:
        print("\n✅ Admin routes fixed successfully!")
        print("You can now access the following routes:")
        print("  - /admin/dashboard")
        print("  - /admin/clients")
        print("  - /admin/subscriptions")
        print("  - /admin/reports")
        print("  - /admin/settings")
        print("  - /admin/scanners")
        sys.exit(0)
    else:
        print("\n❌ Failed to fix admin routes. Check the output above for details.")
        sys.exit(1)
