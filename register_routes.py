# register_routes.py
from flask import Flask

def register_all_routes(app: Flask):
    """Register all route blueprints with the Flask application"""
    
    # Import all blueprints
    from admin import admin_bp
    from auth import auth_bp
    from client_routes import client_bp
    from subscription_routes import subscription_bp
    from reports_routes import reports_bp
    from settings_routes import settings_bp
    from scanner_router import scanner_bp
    from api import api_bp
    
    # Register all blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(subscription_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(api_bp)
    
    # Log registered blueprints
    app.logger.info("Registered blueprints: %s", ", ".join(app.blueprints.keys()))
    
    return app
