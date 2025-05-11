from database_manager import DatabaseManager

db_manager = DatabaseManager()

def handle_scan_results(client_id, scanner_id, scan_data):
    """Handle the results of a security scan"""
    try:
        # Save scan results to client's specific database
        success = db_manager.save_scan_result(
            client_id=client_id,
            scanner_id=scanner_id,
            scan_data={
                'target': scan_data.get('target'),
                'type': scan_data.get('scan_type', 'general'),
                'results': json.dumps(scan_data.get('results', {}))
            }
        )
        
        if success:
            return {
                'status': 'success',
                'message': 'Scan results saved successfully'
            }
        else:
            return {
                'status': 'error',
                'message': 'Failed to save scan results'
            }
            
    except Exception as e:
        logging.error(f"Error saving scan results: {e}")
        return {
            'status': 'error',
            'message': f'Error saving scan results: {str(e)}'
        }
