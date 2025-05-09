def fix_admin_routes(app):
    """Add missing routes to the admin blueprint"""
    from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
    import logging
    
    # Get a logger
    logger = logging.getLogger(__name__)
    
    # Get the admin blueprint
    admin_bp = None
    for name, blueprint in app.blueprints.items():
        if name == 'admin':
            admin_bp = blueprint
            break
    
    if not admin_bp:
        logger.error("Could not find admin blueprint")
        return False
    
    # Add proper client list route
    @admin_bp.route('/clients')
    def client_list():
        """Client management page with actual content"""
        try:
            # Try to get client data from database
            from client_db import get_db_connection, list_clients
            
            # Get pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            
            # Get filter parameters
            filters = {}
            if 'subscription' in request.args and request.args.get('subscription'):
                filters['subscription'] = request.args.get('subscription')
            if 'search' in request.args and request.args.get('search'):
                filters['search'] = request.args.get('search')
            if 'status' in request.args and request.args.get('status') and request.args.get('status') != 'all':
                filters['active'] = request.args.get('status') == 'active'
            
            # Get clients data with pagination and filtering
            clients_data = list_clients(page=page, per_page=per_page, filters=filters)
            
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            return render_template(
                'admin/client-management.html',
                clients=clients_data.get('clients', []),
                pagination=clients_data.get('pagination', {}),
                subscription_filter=filters.get('subscription', ''),
                search=filters.get('search', ''),
                user=user
            )
        except Exception as e:
            logger.error(f"Error in client_list: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error loading client list: {str(e)}"
            )
    
    # Add subscriptions page
    @admin_bp.route('/subscriptions')
    def subscriptions():
        """Subscriptions management page"""
        try:
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            # For now, just render a basic template
            # In a full implementation, you'd get subscription data from the database
            return render_template(
                'admin/subscription-management.html',
                user=user
            )
        except Exception as e:
            logger.error(f"Error in subscriptions: {e}")
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error loading subscriptions: {str(e)}"
            )
    
    # Add reports page
    @admin_bp.route('/reports')
    def reports():
        """Reports dashboard page"""
        try:
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            # For now, just render a basic template
            # In a full implementation, you'd get report data from the database
            return render_template(
                'admin/reports-dashboard.html',
                user=user
            )
        except Exception as e:
            logger.error(f"Error in reports: {e}")
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error loading reports: {str(e)}"
            )
    
    # Add settings page
    @admin_bp.route('/settings')
    def settings():
        """Settings dashboard page"""
        try:
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            # For now, just render a basic template
            # In a full implementation, you'd get settings data from the database
            return render_template(
                'admin/settings-dashboard.html',
                user=user
            )
        except Exception as e:
            logger.error(f"Error in settings: {e}")
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error loading settings: {str(e)}"
            )
    
    # Add scanner management routes
    @admin_bp.route('/scanners')
    def scanners():
        """Scanner management page"""
        try:
            # Try to get scanner data from database
            from client_db import get_db_connection, list_deployed_scanners
            
            # Get pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 10, type=int)
            
            # Get filter parameters
            filters = {}
            if 'status' in request.args and request.args.get('status'):
                filters['status'] = request.args.get('status')
            if 'search' in request.args and request.args.get('search'):
                filters['search'] = request.args.get('search')
            
            # Get deployed scanners
            conn = get_db_connection()
            deployed_scanners = list_deployed_scanners(conn, page, per_page, filters)
            conn.close()
            
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            return render_template(
                'admin/scanner-management.html',
                deployed_scanners=deployed_scanners,
                filters=filters,
                user=user
            )
        except Exception as e:
            logger.error(f"Error in scanners: {e}")
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error loading scanners: {str(e)}"
            )
    
    @admin_bp.route('/scanners/<int:scanner_id>/view')
    def view_scanner(scanner_id):
        """View scanner details"""
        try:
            # Get scanner data from the database
            from client_db import get_db_connection, get_scanner_by_id
            
            conn = get_db_connection()
            scanner = get_scanner_by_id(conn, scanner_id)
            conn.close()
            
            if not scanner:
                flash("Scanner not found", "danger")
                return redirect(url_for('admin.scanners'))
            
            # Get user from session for template
            from auth_utils import verify_session
            session_token = request.cookies.get('session_token')
            user = None
            if session_token:
                result = verify_session(session_token)
                if result['status'] == 'success':
                    user = result['user']
            
            return render_template(
                'admin/client-view.html',  # Using client-view template for now
                client=scanner,
                user=user
            )
        except Exception as e:
            logger.error(f"Error in view_scanner: {e}")
            
            # Return error page
            return render_template(
                'admin/error.html',
                error=f"Error viewing scanner: {str(e)}"
            )
    
    @admin_bp.route('/scanners/<int:scanner_id>/edit')
    def edit_scanner(scanner_id):
        """Edit scanner configuration"""
        # For now, just redirect to view page
        return redirect(url_for('admin.view_scanner', scanner_id=scanner_id))
    
    @admin_bp.route('/scanners/<int:scanner_id>/stats')
    def scanner_stats(scanner_id):
        """Scanner statistics page"""
        # For now, just redirect to view page
        return redirect(url_for('admin.view_scanner', scanner_id=scanner_id))
    
    # Add API endpoints for scanner management
    @admin_bp.route('/scanners/<int:scanner_id>/regenerate-api-key', methods=['POST'])
    def regenerate_api_key(scanner_id):
        """Regenerate API key for a scanner"""
        try:
            from client_db import get_db_connection, regenerate_api_key
            
            # Get client_id from scanner_id
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT client_id FROM deployed_scanners WHERE id = ?", (scanner_id,))
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                return jsonify({
                    "status": "error",
                    "message": "Scanner not found"
                })
            
            client_id = result[0]
            
            # Regenerate API key
            api_key_result = regenerate_api_key(client_id)
            conn.close()
            
            if api_key_result['status'] == 'success':
                return jsonify({
                    "status": "success",
                    "api_key": api_key_result['api_key']
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": api_key_result.get('message', 'Failed to regenerate API key')
                })
        except Exception as e:
            logger.error(f"Error regenerating API key: {e}")
            
            return jsonify({
                "status": "error",
                "message": f"Error: {str(e)}"
            })
    
    @admin_bp.route('/scanners/<int:scanner_id>/toggle-status', methods=['POST'])
    def toggle_scanner_status(scanner_id):
        """Toggle scanner status (active/inactive)"""
        try:
            # For now, just return a success response
            # In a full implementation, you'd update the database
            return jsonify({
                "status": "success",
                "current_status": "inactive"  # or "deployed" depending on the toggle
            })
        except Exception as e:
            logger.error(f"Error toggling scanner status: {e}")
            
            return jsonify({
                "status": "error",
                "message": f"Error: {str(e)}"
            })
        
    logger.info("Added missing admin routes")
    return True
