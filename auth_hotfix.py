# auth_hotfix.py - Register the authentication fix with Flask app
import logging

logger = logging.getLogger(__name__)

def register_auth_hotfix(app):
    """Register the authentication hotfix with the Flask app"""
    @app.before_first_request
    def apply_hotfix():
        try:
            # Import and apply the fix
            from fix_auth import apply_authentication_fix, create_admin_user
            
            # Apply the fix to the authentication system
            apply_authentication_fix()
            
            # Create/update admin user with known credentials
            create_admin_user()
            
            app.logger.info("Authentication hotfix applied successfully")
        except Exception as e:
            app.logger.error(f"Failed to apply authentication hotfix: {str(e)}")
    
    app.logger.info("Authentication hotfix registered")
    return app
