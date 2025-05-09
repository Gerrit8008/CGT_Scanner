def fix_auth_routes(app):
    """Add missing routes to the auth blueprint"""
    from flask import Blueprint
    
    # Get the auth blueprint
    auth_bp = None
    for name, blueprint in app.blueprints.items():
        if name == 'auth':
            auth_bp = blueprint
            break
    
    if not auth_bp:
        print("Could not find auth blueprint")
        return False
    
    # Add admin_create_user route
    @auth_bp.route('/admin/users/create', methods=['GET', 'POST'])
    def admin_create_user():
        """Redirect to admin user create page"""
        from flask import redirect, url_for
        return redirect(url_for('admin.user_create'))
    
    # Add admin_edit_user route
    @auth_bp.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
    def admin_edit_user(user_id):
        """Redirect to admin user edit page"""
        from flask import redirect, url_for
        return redirect(url_for('admin.user_edit', user_id=user_id))
    
    print("Added missing auth routes")
    return True
