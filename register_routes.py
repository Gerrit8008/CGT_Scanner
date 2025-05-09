# register_routes.py
from flask import Flask
import logging

def register_all_routes(app: Flask):
    """Register all route blueprints with the Flask application"""
    
    try:
        # Import all blueprints
        from admin import admin_bp
        from auth import auth_bp
        
        # Register the basic blueprints first
        app.register_blueprint(auth_bp)
        app.register_blueprint(admin_bp)
        
        # Log registered blueprints so far
        app.logger.info("Registered basic blueprints: %s", ", ".join(app.blueprints.keys()))
        
        # Try to import and register the remaining blueprints
        try:
            from client_routes import client_bp
            app.register_blueprint(client_bp)
            app.logger.info("Registered client_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import client_bp: {e}")

        try:
            from subscription_routes import subscription_bp
            app.register_blueprint(subscription_bp)
            app.logger.info("Registered subscription_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import subscription_bp: {e}")

        try:
            from reports_routes import reports_bp
            app.register_blueprint(reports_bp)
            app.logger.info("Registered reports_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import reports_bp: {e}")

        try:
            from settings_routes import settings_bp
            app.register_blueprint(settings_bp)
            app.logger.info("Registered settings_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import settings_bp: {e}")

        try:
            from scanner_router import scanner_bp
            app.register_blueprint(scanner_bp)
            app.logger.info("Registered scanner_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import scanner_bp: {e}")

        try:
            from api import api_bp
            app.register_blueprint(api_bp)
            app.logger.info("Registered api_bp blueprint")
        except ImportError as e:
            app.logger.error(f"Failed to import api_bp: {e}")
        
        # Log final registered blueprints
        app.logger.info("All registered blueprints: %s", ", ".join(app.blueprints.keys()))
        
    except Exception as e:
        app.logger.error(f"Error registering routes: {e}")
        # Still return the app even if there's an error
    
    return app
