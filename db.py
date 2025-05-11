import os
import sqlite3
import json
from datetime import datetime
import logging
from pathlib import Path

# Configure database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases', 'scanner.db')

# Ensure database directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create scans table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        timestamp TEXT,
        email TEXT,
        target TEXT,
        results TEXT,
        status TEXT DEFAULT 'completed',
        created_at TEXT
    )
    ''')

    # Create leads table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        company TEXT,
        phone TEXT,
        timestamp TEXT,
        scan_id TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
    )
    ''')

    conn.commit()
    conn.close()
    logging.info("Database initialized successfully")

def save_scan_results(scan_data):
    """Save scan results to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Convert scan results to JSON string
        results_json = json.dumps(scan_data)
        timestamp = datetime.now().isoformat()

        cursor.execute('''
        INSERT INTO scans (scan_id, timestamp, email, target, results, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            scan_data.get('scan_id'),
            scan_data.get('timestamp', timestamp),
            scan_data.get('email', ''),
            scan_data.get('target', ''),
            results_json,
            timestamp
        ))

        conn.commit()
        scan_id = scan_data.get('scan_id')
        conn.close()

        logging.info(f"Scan results saved successfully with ID: {scan_id}")
        return scan_id

    except Exception as e:
        logging.error(f"Error saving scan results: {e}")
        if 'conn' in locals():
            conn.close()
        return None

def get_scan_results(scan_id):
    """Retrieve scan results from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('SELECT results FROM scans WHERE scan_id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            scan_results = json.loads(row[0])
            return scan_results
        return None

    except Exception as e:
        logging.error(f"Error retrieving scan results: {e}")
        if 'conn' in locals():
            conn.close()
        return None

def save_lead_data(lead_data):
    """Save lead information to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
        INSERT INTO leads (name, email, company, phone, timestamp, scan_id)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            lead_data.get('name', ''),
            lead_data.get('email', ''),
            lead_data.get('company', ''),
            lead_data.get('phone', ''),
            lead_data.get('timestamp', datetime.now().isoformat()),
            lead_data.get('scan_id')
        ))

        conn.commit()
        lead_id = cursor.lastrowid
        conn.close()

        logging.info(f"Lead data saved successfully with ID: {lead_id}")
        return lead_id

    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        if 'conn' in locals():
            conn.close()
        return None

# Initialize database when module is imported
init_db()
