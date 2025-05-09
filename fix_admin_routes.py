
import os
import sys
import logging
import importlib.util
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_module_from_file(file_path, module_name):
    """Load a Python module from a file path"""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if not spec:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.error(f"Error loading module {module_name} from {file_path}: {e}")
        return None

def import_flask_app():
    """Import the Flask app from app.py"""
    try:
        # Try to find app.py in the current directory
        if os.path.exists('app.py'):
            app_module = load_module_from_file('app.py', 'app')
            if hasattr(app_module, 'app'):
                logger.info("Successfully imported Flask app from app.py")
                return app_module.app
            else:
                # Look for create_app pattern
                if hasattr(app_module, 'create_app'):
                    logger.info("Found create_app function in app.py")
                    app = app_module.create_app()
                    return app
        
        # If we can't find it, try to import it using standard import
        import app
        if hasattr(app, 'app'):
            logger.info("Successfully imported Flask app using import app")
            return app.app
        elif hasattr(app, 'create_app'):
            logger.info("Using create_app function from import app")
            return app.create_app()
        
        logger.error("Could not find Flask app in app.py")
        return None
    except ImportError:
        logger.error("Could not import app.py")
        return None
    except Exception as e:
        logger.error(f"Error importing Flask app: {e}")
        logger.error(traceback.format_exc())
        return None

def apply_route_fixes(app=None):
    """Apply all the route fixes"""
    # First, check if admin_route_fix.py exists
    route_fix_path = 'admin_route_fix.py'
    if not os.path.exists(route_fix_path):
        # Try route_fix.py instead
        route_fix_path = 'route_fix.py'
        if not os.path.exists(route_fix_path):
            logger.error("Could not find admin_route_fix.py or route_fix.py")
            return False

    # Load the admin_route_fix module
    route_fix_module = load_module_from_file(route_fix_path, 'route_fix')
    if not route_fix_module:
        logger.error(f"Failed to load {route_fix_path}")
        return False
    
    # Check if the module has the necessary function
    if not hasattr(route_fix_module, 'fix_admin_routes'):
        logger.error(f"{route_fix_path} does not contain fix_admin_routes function")
        return False
    
    try:
        # If app is not provided, try to import it
        if app is None:
            app = import_flask_app()
            if not app:
                logger.error("Could not import Flask app")
                return False
        
        # Apply the fixes
        logger.info("Applying admin route fixes...")
        result = route_fix_module.fix_admin_routes(app)
        
        if result:
            logger.info("Admin route fixes applied successfully!")
            return True
        else:
            logger.error("Failed to apply admin route fixes")
            return False
    except Exception as e:
        logger.error(f"Error applying admin route fixes: {e}")
        logger.error(traceback.format_exc())
        return False

def print_instructions():
    """Print additional instructions after successful fix"""
    print("\nTo apply these fixes permanently, add the following to your app.py:")
    print("\n# Import and apply admin route fixes")
    print("from route_fix import fix_admin_routes")
    print("fix_admin_routes(app)\n")
    print("Alternatively, you can add these lines to a startup script that runs before the Flask app starts.")

def check_flask_app():
    """Check if Flask app is set up correctly"""
    try:
        import flask
        print(f"Flask version: {flask.__version__}")
        return True
    except ImportError:
        print("Flask is not installed. Please install it with: pip install flask")
        return False

def main():
    """Main function to run the fix script"""
    print("=" * 60)
    print("Admin Route Fix Script")
    print("=" * 60)
    
    # Check if Flask is installed
    if not check_flask_app():
        return 1
    
    # Try to apply the fixes
    success = apply_route_fixes()
    
    if success:
        print("\n✅ Admin routes fixed successfully!")
        print("You can now access the following routes:")
        print("  - /admin/dashboard")
        print("  - /admin/clients")
        print("  - /admin/subscriptions")
        print("  - /admin/reports")
        print("  - /admin/settings")
        print("  - /admin/scanners")
        
        print_instructions()
        return 0
    else:
        print("\n❌ Failed to apply admin route fixes. Check the logs above for details.")
        return 1

# If the script is run directly
if __name__ == "__main__":
    sys.exit(main())
