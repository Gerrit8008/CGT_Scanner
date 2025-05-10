from flask import jsonify, request
from client_db import update_deployment_status, get_scanner_config
from scanner_template import generate_scanner

@app.route('/api/scanners/<int:scanner_id>/activate', methods=['POST'])
@login_required
def activate_scanner(scanner_id):
    try:
        # Get scanner details
        scanner = get_scanner_details(scanner_id)
        
        # Verify scanner belongs to current user
        if scanner['client_id'] != current_user.client_id:
            return jsonify({
                'status': 'error',
                'message': 'Unauthorized access'
            }), 403
        
        # Verify scanner is in pending state
        if scanner['deploy_status'] != 'pending':
            return jsonify({
                'status': 'error',
                'message': 'Scanner is not in pending state'
            }), 400
        
        # Get scanner configuration
        config = get_scanner_config(scanner_id)
        
        # Generate scanner with configuration
        success = generate_scanner(scanner['client_id'], config)
        
        if success:
            # Update scanner status to deployed
            update_deployment_status(scanner_id, 'deployed')
            
            return jsonify({
                'status': 'success',
                'message': 'Scanner activated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to generate scanner'
            }), 500
            
    except Exception as e:
        logging.error(f"Error activating scanner {scanner_id}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while activating the scanner'
        }), 500
