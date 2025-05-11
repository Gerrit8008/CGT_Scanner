from contextlib import contextmanager
import sqlite3

@contextmanager
def get_db_connection(db_path):
    """Context manager for database connections"""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        yield conn
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
