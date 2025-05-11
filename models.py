from database_manager import DatabaseManager
from database_utils import get_db_connection, get_client_db
from datetime import datetime
import sqlite3
import logging

logger = logging.getLogger(__name__)
db_manager = DatabaseManager()

def get_user_by_id(user_id: int) -> dict:
    """Get user information by ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, role, full_name, created_at, last_login, active 
            FROM users WHERE id = ?
        ''', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'full_name': user[4],
                'created_at': user[5],
                'last_login': user[6],
                'active': bool(user[7])
            }
        return None
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None

def get_client_by_id(client_id: int) -> dict:
    """Get client information by ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, user_id, business_name, business_domain, contact_email,
                   contact_phone, scanner_name, subscription_level, subscription_status,
                   subscription_start, subscription_end, api_key, created_at, active
            FROM clients WHERE id = ?
        ''', (client_id,))
        client = cursor.fetchone()
        conn.close()
        
        if client:
            return {
                'id': client[0],
                'user_id': client[1],
                'business_name': client[2],
                'business_domain': client[3],
                'contact_email': client[4],
                'contact_phone': client[5],
                'scanner_name': client[6],
                'subscription_level': client[7],
                'subscription_status': client[8],
                'subscription_start': client[9],
                'subscription_end': client[10],
                'api_key': client[11],
                'created_at': client[12],
                'active': bool(client[13])
            }
        return None
    except Exception as e:
        logger.error(f"Error getting client by ID: {e}")
        return None

def get_scanner_by_id(scanner_id: int) -> dict:
    """Get scanner information by ID"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, client_id, subdomain, domain, deploy_status,
                   deploy_date, last_updated, config_path, template_version
            FROM deployed_scanners WHERE id = ?
        ''', (scanner_id,))
        scanner = cursor.fetchone()
        conn.close()
        
        if scanner:
            return {
                'id': scanner[0],
                'client_id': scanner[1],
                'subdomain': scanner[2],
                'domain': scanner[3],
                'deploy_status': scanner[4],
                'deploy_date': scanner[5],
                'last_updated': scanner[6],
                'config_path': scanner[7],
                'template_version': scanner[8]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting scanner by ID: {e}")
        return None

def get_scan_history(client_id: int, limit: int = 10) -> list:
    """Get scan history for a client"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, scan_id, timestamp, target, scan_type, status, report_path
            FROM scan_history 
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (client_id, limit))
        scans = cursor.fetchall()
        conn.close()
        
        return [{
            'id': scan[0],
            'scan_id': scan[1],
            'timestamp': scan[2],
            'target': scan[3],
            'scan_type': scan[4],
            'status': scan[5],
            'report_path': scan[6]
        } for scan in scans]
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return []

def get_client_customization(client_id: int) -> dict:
    """Get customization settings for a client"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, primary_color, secondary_color, logo_path,
                   favicon_path, email_subject, email_intro,
                   email_footer, default_scans, css_override,
                   html_override, last_updated
            FROM customizations WHERE client_id = ?
        ''', (client_id,))
        custom = cursor.fetchone()
        conn.close()
        
        if custom:
            return {
                'id': custom[0],
                'primary_color': custom[1],
                'secondary_color': custom[2],
                'logo_path': custom[3],
                'favicon_path': custom[4],
                'email_subject': custom[5],
                'email_intro': custom[6],
                'email_footer': custom[7],
                'default_scans': custom[8],
                'css_override': custom[9],
                'html_override': custom[10],
                'last_updated': custom[11]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting client customization: {e}")
        return None

def get_client_transactions(client_id: int, limit: int = 10) -> list:
    """Get billing transactions for a client"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, transaction_id, amount, currency, payment_method,
                   status, timestamp, notes
            FROM billing_transactions 
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (client_id, limit))
        transactions = cursor.fetchall()
        conn.close()
        
        return [{
            'id': tx[0],
            'transaction_id': tx[1],
            'amount': tx[2],
            'currency': tx[3],
            'payment_method': tx[4],
            'status': tx[5],
            'timestamp': tx[6],
            'notes': tx[7]
        } for tx in transactions]
    except Exception as e:
        logger.error(f"Error getting client transactions: {e}")
        return []

def get_audit_log(entity_type: str, entity_id: int, limit: int = 10) -> list:
    """Get audit log entries for an entity"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, user_id, action, changes, timestamp, ip_address
            FROM audit_log 
            WHERE entity_type = ? AND entity_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (entity_type, entity_id, limit))
        logs = cursor.fetchall()
        conn.close()
        
        return [{
            'id': log[0],
            'user_id': log[1],
            'action': log[2],
            'changes': log[3],
            'timestamp': log[4],
            'ip_address': log[5]
        } for log in logs]
    except Exception as e:
        logger.error(f"Error getting audit log: {e}")
        return []

def get_active_sessions(user_id: int) -> list:
    """Get active sessions for a user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute('''
            SELECT id, session_token, created_at, expires_at,
                   ip_address, user_agent
            FROM sessions 
            WHERE user_id = ? AND expires_at > ?
            ORDER BY created_at DESC
        ''', (user_id, now))
        sessions = cursor.fetchall()
        conn.close()
        
        return [{
            'id': session[0],
            'session_token': session[1],
            'created_at': session[2],
            'expires_at': session[3],
            'ip_address': session[4],
            'user_agent': session[5]
        } for session in sessions]
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return []
