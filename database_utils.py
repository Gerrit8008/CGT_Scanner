from contextlib import contextmanager
import sqlite3

@contextmanager
def get_db_connection(db_path=None):
    """Context manager for database connections with improved error handling"""
    if db_path is None:
        from client_db import CLIENT_DB_PATH
        db_path = CLIENT_DB_PATH
        
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=20.0)  # Increase timeout value
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()  # Auto-commit if no exceptions
    except sqlite3.OperationalError as oe:
        if conn:
            conn.rollback()
        if "database is locked" in str(oe):
            # Add specific handling for locked database errors
            logging.error("Database lock error: Increase timeout or implement retry logic")
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logging.error(f"Database error: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()

@contextmanager
def get_client_db(db_manager, client_id):
    """Context manager for client database connections"""
    conn = None
    try:
        conn = db_manager.get_client_connection(client_id)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()
