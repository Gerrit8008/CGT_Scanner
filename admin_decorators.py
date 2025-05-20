# admin_decorators.py
from flask import redirect, url_for, session, request, flash

def admin_required(f):
    """Decorator that requires admin privileges"""
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
            
        # Verify session
        try:
            # Try auth_utils first
            try:
                from auth_utils import verify_session
            except ImportError:
                # Fall back to client_db
                from client_db import verify_session
                
            result = verify_session(session_token)
            
            if result['status'] != 'success' or result['user']['role'] != 'admin':
                flash('You need admin privileges to access this page', 'danger')
                return redirect(url_for('auth.login'))
                
            # Add user to kwargs
            kwargs['user'] = result['user']
            
        except Exception as e:
            import logging
            logging.error(f"Error in admin_required: {e}")
            flash('Authentication error', 'danger')
            return redirect(url_for('auth.login'))
            
        return f(*args, **kwargs)
        
    # Preserve function name
    decorated_function.__name__ = f.__name__
    return decorated_function
