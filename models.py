from database_manager import DatabaseManager
from database_utils import get_db_connection, get_client_db
from datetime import datetime

db_manager = DatabaseManager()

def get_client_by_user_id(user_id: int) -> dict:
    """Get client information by user ID"""
    try:
        with get_db_connection(db_manager.admin_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.*, u.email as user_email 
                FROM clients c
                JOIN users u ON c.user_id = u.id
                WHERE c.user_id = ? AND c.active = 1
            """, (user_id,))
            result = cursor.fetchone()
            return dict(result) if result else None
    except Exception as e:
        logging.error(f"Error getting client: {e}")
        return None

def get_client_scans(client_id: int, limit: int = 10) -> list:
    """Get recent scans for a client"""
    try:
        with get_client_db(db_manager, client_id) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scans 
                ORDER BY scan_timestamp DESC 
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logging.error(f"Error getting client scans: {e}")
        return []

# Add other model functions similarly...
