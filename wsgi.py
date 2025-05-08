#!/usr/bin/env python3
# wsgi.py - WSGI application entry point
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

logger.info("Starting application initialization in WSGI")

try:
    # Import the Flask app
    from app import app as application
    logger.info("Successfully imported app")
except Exception as e:
    logger.error(f"Error importing app: {e}")
    import traceback
    logger.error(traceback.format_exc())
    # Create a minimal application for error reporting
    from flask import Flask, Response
    application = Flask(__name__)
    
    @application.route('/')
    def error_page():
        return Response(f"Application failed to start: {str(e)}", mimetype='text/plain')

# This allows the file to be run directly
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    application.run(host='0.0.0.0', port=port)
