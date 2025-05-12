from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
from app.models.scanner import Scanner
from app.database import db

scanner_bp = Blueprint('scanner', __name__)

@scanner_bp.route('/api/scanner/save', methods=['POST'])
def save_scanner():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['companyName', 'email', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400

        # Create new scanner
        new_scanner = Scanner(
            company_name=data['companyName'],
            email=data['email'],
            phone=data['phone'],
            created_by=current_app.config.get('USER_ID', 'Gerrit8008'),  # Get from session/auth
            created_at=datetime.utcnow(),
            status='draft'
        )

        # Save to database
        db.session.add(new_scanner)
        db.session.commit()

        return jsonify({
            'success': True,
            'scannerId': new_scanner.id,
            'message': 'Scanner saved successfully'
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving scanner: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to save scanner'
        }), 500

@scanner_bp.route('/scanner/preview/<scanner_id>', methods=['GET'])
def preview_scanner(scanner_id):
    try:
        scanner = Scanner.query.get(scanner_id)
        if not scanner:
            return jsonify({
                'success': False,
                'error': 'Scanner not found'
            }), 404

        return render_template('scanner_preview.html', scanner=scanner)

    except Exception as e:
        current_app.logger.error(f"Error previewing scanner: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to load scanner preview'
        }), 500
