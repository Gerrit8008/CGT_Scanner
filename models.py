from database_manager import DatabaseManager
from database_utils import get_db_connection, get_client_db
from datetime import datetime, timedelta
from functools import wraps
import logging
import sqlite3

logger = logging.getLogger(__name__)
db_manager = DatabaseManager()

def with_transaction(f):
    """Decorator to handle database transactions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        conn = None
        try:
            conn = get_db_connection(db_manager.admin_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            result = f(conn, cursor, *args, **kwargs)
            conn.commit()
            return result
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error in {f.__name__}: {e}")
            raise
        finally:
            if conn:
                conn.close()
    return decorated_function

@with_transaction
def get_user_by_id(conn, cursor, user_id: int) -> dict:
    """Get user information by ID"""
    try:
        cursor.execute('''
            SELECT id, username, email, role, full_name, created_at, 
                   last_login, active 
            FROM users 
            WHERE id = ? AND active = 1
        ''', (user_id,))
        user = cursor.fetchone()
        
        return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None

@with_transaction
def get_client_by_id(conn, cursor, client_id: int) -> dict:
    """Get client information by ID"""
    try:
        cursor.execute('''
            SELECT c.*, u.email as user_email 
            FROM clients c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.id = ? AND c.active = 1
        ''', (client_id,))
        client = cursor.fetchone()
        
        return dict(client) if client else None
    except Exception as e:
        logger.error(f"Error getting client by ID: {e}")
        return None

@with_transaction
def get_scanner_by_id(conn, cursor, scanner_id: int) -> dict:
    """Get scanner information by ID"""
    try:
        cursor.execute('''
            SELECT ds.*, c.business_name, c.business_domain
            FROM deployed_scanners ds
            JOIN clients c ON ds.client_id = c.id
            WHERE ds.id = ?
        ''', (scanner_id,))
        scanner = cursor.fetchone()
        
        return dict(scanner) if scanner else None
    except Exception as e:
        logger.error(f"Error getting scanner by ID: {e}")
        return None

@with_transaction
def get_scan_history(conn, cursor, client_id: int, limit: int = 10) -> list:
    """Get scan history for a client"""
    try:
        cursor.execute('''
            SELECT sh.*, c.business_name
            FROM scan_history sh
            JOIN clients c ON sh.client_id = c.id
            WHERE sh.client_id = ?
            ORDER BY sh.timestamp DESC
            LIMIT ?
        ''', (client_id, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return []

@with_transaction
def get_client_customization(conn, cursor, client_id: int) -> dict:
    """Get customization settings for a client"""
    try:
        cursor.execute('''
            SELECT * FROM customizations 
            WHERE client_id = ?
        ''', (client_id,))
        custom = cursor.fetchone()
        
        return dict(custom) if custom else None
    except Exception as e:
        logger.error(f"Error getting client customization: {e}")
        return None

@with_transaction
def get_client_transactions(conn, cursor, client_id: int, limit: int = 10) -> list:
    """Get billing transactions for a client"""
    try:
        cursor.execute('''
            SELECT bt.*, c.business_name
            FROM billing_transactions bt
            JOIN clients c ON bt.client_id = c.id
            WHERE bt.client_id = ?
            ORDER BY bt.timestamp DESC
            LIMIT ?
        ''', (client_id, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting client transactions: {e}")
        return []

@with_transaction
def get_audit_log(conn, cursor, entity_type: str, entity_id: int, limit: int = 10) -> list:
    """Get audit log entries for an entity"""
    try:
        cursor.execute('''
            SELECT al.*, u.username
            FROM audit_log al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.entity_type = ? AND al.entity_id = ?
            ORDER BY al.timestamp DESC
            LIMIT ?
        ''', (entity_type, entity_id, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting audit log: {e}")
        return []

@with_transaction
def get_active_sessions(conn, cursor, user_id: int) -> list:
    """Get active sessions for a user"""
    try:
        now = datetime.now().isoformat()
        cursor.execute('''
            SELECT s.*, u.username, u.email
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.user_id = ? AND s.expires_at > ?
            ORDER BY s.created_at DESC
        ''', (user_id, now))
        
        return [dict(session) for session in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return []

@with_transaction
def get_client_stats(conn, cursor, client_id: int) -> dict:
    """Get comprehensive statistics for a client"""
    try:
        stats = {
            'scans': {
                'total': 0,
                'today': 0,
                'week': 0,
                'month': 0
            },
            'subscription': None,
            'billing': None,
            'recent_transactions': [],
            'recent_scans': []
        }
        
        # Get scan counts
        today = datetime.now().date().isoformat()
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        month_ago = (datetime.now() - timedelta(days=30)).isoformat()
        
        cursor.execute('SELECT COUNT(*) FROM scan_history WHERE client_id = ?', 
                      (client_id,))
        stats['scans']['total'] = cursor.fetchone()[0]
        
        cursor.execute('''SELECT COUNT(*) FROM scan_history 
                         WHERE client_id = ? AND DATE(timestamp) = ?''', 
                      (client_id, today))
        stats['scans']['today'] = cursor.fetchone()[0]
        
        cursor.execute('''SELECT COUNT(*) FROM scan_history 
                         WHERE client_id = ? AND timestamp > ?''', 
                      (client_id, week_ago))
        stats['scans']['week'] = cursor.fetchone()[0]
        
        cursor.execute('''SELECT COUNT(*) FROM scan_history 
                         WHERE client_id = ? AND timestamp > ?''', 
                      (client_id, month_ago))
        stats['scans']['month'] = cursor.fetchone()[0]
        
        # Get subscription info
        cursor.execute('''
            SELECT subscription_level, subscription_status, 
                   subscription_start, subscription_end
            FROM clients WHERE id = ?
        ''', (client_id,))
        stats['subscription'] = dict(cursor.fetchone())
        
        # Get recent transactions
        cursor.execute('''
            SELECT * FROM billing_transactions
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT 5
        ''', (client_id,))
        stats['recent_transactions'] = [dict(tx) for tx in cursor.fetchall()]
        
        # Get recent scans
        cursor.execute('''
            SELECT * FROM scan_history
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT 5
        ''', (client_id,))
        stats['recent_scans'] = [dict(scan) for scan in cursor.fetchall()]
        
        return stats
    except Exception as e:
        logger.error(f"Error getting client stats: {e}")
        return None
