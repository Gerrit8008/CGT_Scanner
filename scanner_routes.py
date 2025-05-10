from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
import sqlite3
import logging
from datetime import datetime
from functools import wraps

scanner_bp = Blueprint('scanner', __name__)

def get_db_connection():
    conn = sqlite3.connect('client_scanner.db')
    conn.row_factory = sqlite3.Row
    return conn

def client_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not hasattr(current_user, 'client_id'):
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return decorated_function

@scanner_bp.route('/api/scanners/<int:scanner_id>/activate', methods=['POST'])
@login_required
@client_required
def activate_scanner(scanner_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if scanner exists and belongs to the current client
        cursor.execute('''
            SELECT * FROM deployed_scanners 
            WHERE id = ? AND client_id = ?
        ''', (scanner_id, current_user.client_id))
        
        scanner = cursor.fetchone()
        
        if not scanner:
            return jsonify({
                'status': 'error',
                'message': 'Scanner not found or unauthorized'
            }), 404
        
        if scanner['deploy_status'] != 'pending':
            return jsonify({
                'status': 'error',
                'message': 'Scanner is not in pending state'
            }), 400

        # Update scanner status to deployed
        cursor.execute('''
            UPDATE deployed_scanners 
            SET deploy_status = ?, last_updated = ?
            WHERE id = ?
        ''', ('deployed', datetime.now().isoformat(), scanner_id))
        
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Scanner activated successfully'
        })

    except Exception as e:
        logging.error(f"Error activating scanner {scanner_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while activating the scanner'
        }), 500
    finally:
        if conn:
            conn.close()
