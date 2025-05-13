@scanner_preview_bp.route('/api/scanner/preview', methods=['POST'])
@require_login
def preview_scanner_configuration():
    """Preview scanner with specific configuration"""
    try:
        data = request.get_json()
        scanner_id = data.get('scanner_id')
        if not scanner_id:
            return jsonify({'status': 'error', 'message': 'Scanner ID required'}), 400

        # Save configuration temporarily for preview
        preview_config = save_scanner_configuration(scanner_id, get_client_id_from_session(), data)
        
        return jsonify({
            'status': 'success',
            'preview_url': url_for('scanner_preview.render_preview', 
                                 api_key=preview_config['api_key'], 
                                 _external=True),
            'html_snippet': preview_config['html_snippet']
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@scanner_preview_bp.route('/api/scanner/<api_key>', methods=['GET'])
def get_scanner_config(api_key):
    """Get scanner configuration by API key"""
    try:
        config = get_scanner_configuration(api_key)
        if config:
            return jsonify({
                'status': 'success',
                'configuration': config
            })
        return jsonify({'status': 'error', 'message': 'Scanner not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@scanner_preview_bp.route('/preview/<api_key>')
def render_preview(api_key):
    """Render scanner preview page"""
    config = get_scanner_configuration(api_key)
    if not config:
        abort(404)
    
    return render_template('scanner/preview.html', 
                         config=config['configuration'],
                         scanner_id=config['scanner_id'])
