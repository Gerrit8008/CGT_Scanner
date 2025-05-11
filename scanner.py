def save_scan_results(client_id: int, scanner_id: str, scan_data: dict) -> dict:
    """Save scan results to client's database"""
    try:
        with get_client_db(db_manager, client_id) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scans (
                    scanner_id, scan_timestamp, target, 
                    scan_type, status, results, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scanner_id,
                datetime.now().isoformat(),
                scan_data['target'],
                scan_data['type'],
                'completed',
                json.dumps(scan_data['results']),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            
            return {
                "status": "success",
                "scan_id": cursor.lastrowid
            }
            
    except Exception as e:
        logging.error(f"Error saving scan results: {e}")
        return {
            "status": "error",
            "message": str(e)
        }
