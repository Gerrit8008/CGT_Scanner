def fix_admin_routes(app):
    """Add missing routes to the admin blueprint"""
    from flask import Blueprint, render_template, redirect, url_for
    
    # Get the admin blueprint
    admin_bp = None
    for name, blueprint in app.blueprints.items():
        if name == 'admin':
            admin_bp = blueprint
            break
    
    if not admin_bp:
        print("Could not find admin blueprint")
        return False
    
    # Add stub routes for sections that don't exist yet
    @admin_bp.route('/clients')
    def client_list():
        """Stub for client list page"""
        return render_template('admin/client-management.html')
    
    @admin_bp.route('/subscriptions')
    def subscriptions():
        """Stub for subscriptions page"""
        return redirect(url_for('admin.dashboard'))
    
    @admin_bp.route('/reports')
    def reports():
        """Stub for reports page"""
        return redirect(url_for('admin.dashboard'))
    
    @admin_bp.route('/settings')
    def settings():
        """Stub for settings page"""
        return redirect(url_for('admin.dashboard'))
    
    # Add scanner management routes
    @admin_bp.route('/scanners/<int:scanner_id>/view')
    def view_scanner(scanner_id):
        """View scanner"""
        return redirect(url_for('admin.dashboard'))
    
    @admin_bp.route('/scanners/<int:scanner_id>/edit')
    def edit_scanner(scanner_id):
        """Edit scanner"""
        return redirect(url_for('admin.dashboard'))
    
    @admin_bp.route('/scanners/<int:scanner_id>/stats')
    def scanner_stats(scanner_id):
        """Scanner statistics"""
        return redirect(url_for('admin.dashboard'))
        
    print("Added missing admin routes")
    return True
