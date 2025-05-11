import os
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

class DatabaseManager:
    def __init__(self, base_path='./databases'):
        self.base_path = Path(base_path)
        self.admin_db_path = self.base_path / 'client_scanner.db'
        self.base_path.mkdir(exist_ok=True)
        
        # Initialize admin database
        self._init_admin_database()

    def _init_admin_database(self):
        """Initialize the main admin database"""
        with open('admin_schema.sql', 'r') as f:
            schema = f.read()
            
        conn = sqlite3.connect(self.admin_db_path)
        conn.executescript(schema)
        conn.close()

    def create_client_database(self, client_id, business_name):
        """Create a new database for a client"""
        # Create sanitized database name
        db_name = f"client_{client_id}_{business_name.lower().replace(' ', '_')}.db"
        db_path = self.base_path / db_name
        
        # Create the client database using the template
        with open('client_template.sql', 'r') as f:
            schema = f.read()
            
        conn = sqlite3.connect(db_path)
        conn.executescript(schema)
        conn.close()
        
        # Update the main database with the client's database name
        admin_conn = sqlite3.connect(self.admin_db_path)
        cursor = admin_conn.cursor()
        cursor.execute("""
            UPDATE clients 
            SET database_name = ? 
            WHERE id = ?
        """, (db_name, client_id))
        admin_conn.commit()
        admin_conn.close()
        
        return db_name

    def get_client_db_connection(self, client_id):
        """Get a connection to a client's specific database"""
        admin_conn = sqlite3.connect(self.admin_db_path)
        cursor = admin_conn.cursor()
        cursor.execute("SELECT database_name FROM clients WHERE id = ?", (client_id,))
        result = cursor.fetchone()
        admin_conn.close()
        
        if result:
            db_path = self.base_path / result[0]
            if db_path.exists():
                return sqlite3.connect(db_path)
        return None

    def create_scanner(self, client_id, scanner_name):
        """Create a new scanner for a client"""
        conn = sqlite3.connect(self.admin_db_path)
        cursor = conn.cursor()
        
        # Generate unique API key
        api_key = f"scanner_{client_id}_{datetime.now().timestamp()}"
        
        cursor.execute("""
            INSERT INTO deployed_scanners (
                client_id, scanner_name, api_key, created_at, status
            ) VALUES (?, ?, ?, ?, ?)
        """, (client_id, scanner_name, api_key, datetime.now().isoformat(), 'active'))
        
        scanner_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scanner_id, api_key

    def save_scan_result(self, client_id, scanner_id, scan_data):
        """Save scan results to client's database"""
        client_conn = self.get_client_db_connection(client_id)
        if not client_conn:
            return False
            
        cursor = client_conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                scanner_id, scan_timestamp, target, scan_type, 
                status, results, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scanner_id,
            datetime.now().isoformat(),
            scan_data['target'],
            scan_data['type'],
            'completed',
            scan_data['results'],
            datetime.now().isoformat()
        ))
        
        client_conn.commit()
        client_conn.close()
        return True
