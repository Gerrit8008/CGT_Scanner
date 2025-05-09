# admin_route_fix.py
# This script directly applies the admin route fixes to the Flask application

import os
import sys
import logging
import importlib
from flask import Flask, Blueprint, render_template, request, redirect, url_for, flash, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Main application function to apply the fixes
def apply_admin_route_fixes(app=None):
    """
    Apply admin route fixes to Flask application
    
    Args:
        app: Flask application instance (optional)
        
    Returns:
        bool: True if fixes were successfully applied, False otherwise
    """
    try:
        # Create templates if they don't exist
        create_basic_templates()
        
        # If app is not provided, let's try to import it
        if app is None:
            try:
                # Try to import the Flask app from app.py
                from app import app as flask_app
                app = flask_app
                logger.info("Successfully imported Flask app from app.py")
            except ImportError:
                logger.error("Could not import Flask app from app.py")
                return False
        
        # Ensure admin routes
        routes_fixed = ensure_admin_routes(app)
        
        return routes_fixed
    except Exception as e:
        logger.error(f"Error applying admin route fixes: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def ensure_admin_routes(app):
    """
    Ensure that all admin routes are properly registered
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if routes were successfully registered, False otherwise
    """
    try:
        # Get the admin blueprint from the app
        admin_bp = None
        for name, blueprint in app.blueprints.items():
            if name == 'admin':
                admin_bp = blueprint
                break
        
        if not admin_bp:
            logger.error("Could not find admin blueprint")
            return False
        
        # Register missing routes
        logger.info("Adding missing admin routes...")
        
        # Subscriptions route
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
        
        # Reports route
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
        
        # Settings route
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
        
        # Scanners route
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
                
                try:
                    # Get deployed scanners
                    conn = get_db_connection()
                    deployed_scanners = list_deployed_scanners(conn, page, per_page, filters)
                    conn.close()
                except Exception as db_error:
                    logger.error(f"Database error: {db_error}")
                    deployed_scanners = {"scanners": [], "pagination": {"page": 1, "per_page": 10, "total_pages": 1, "total_count": 0}}
                
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
        
        logger.info("Added missing admin routes successfully!")
        return True
    
    except Exception as e:
        logger.error(f"Error ensuring admin routes: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def create_basic_templates():
    """Create basic templates for missing routes if they don't exist"""
    try:
        # Create templates directory if it doesn't exist
        template_dir = 'templates/admin'
        os.makedirs(template_dir, exist_ok=True)
        
        # Create error template first as it's used by other templates
        error_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Scanner Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 p-0 sidebar">
                <div class="text-center mb-4">
                    <h4>Scanner Platform</h4>
                    <p class="mb-0 small">Admin Panel</p>
                </div>
    
                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/customize" class="sidebar-link">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ms-auto main-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>Error</h2>
                    <div>
                        <span class="badge bg-primary">Admin</span>
                        <span class="ms-2">{{ user.username if user else 'Admin' }}</span>
                    </div>
                </div>
                
                <div class="alert alert-danger">
                    <h4 class="alert-heading">Error!</h4>
                    <p>{{ error }}</p>
                </div>
                
                <a href="/admin/dashboard" class="btn btn-primary">Return to Dashboard</a>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""
        
        error_path = os.path.join(template_dir, 'error.html')
        if not os.path.exists(error_path):
            with open(error_path, 'w') as f:
                f.write(error_template)
                logger.info(f"Created error template at {error_path}")
        
        # Define basic templates
        templates = {
            'subscription-management.html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subscription Management - Scanner Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 p-0 sidebar">
                <div class="text-center mb-4">
                    <h4>Scanner Platform</h4>
                    <p class="mb-0 small">Admin Panel</p>
                </div>
    
                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/customize" class="sidebar-link">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link active">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ms-auto main-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>Subscription Management</h2>
                    <div>
                        <span class="badge bg-primary">Admin</span>
                        <span class="ms-2">{{ user.username if user else 'Admin' }}</span>
                    </div>
                </div>
                
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Content -->
                <div class="row">
                    <div class="col-12">
                        <div class="card border-0 shadow-sm">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">Active Subscriptions</h5>
                                <button class="btn btn-sm btn-primary">Add New Plan</button>
                            </div>
                            <div class="card-body">
                                <p>Subscription management content will be displayed here.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
            """,
            'reports-dashboard.html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports Dashboard - Scanner Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 p-0 sidebar">
                <div class="text-center mb-4">
                    <h4>Scanner Platform</h4>
                    <p class="mb-0 small">Admin Panel</p>
                </div>
    
                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/customize" class="sidebar-link">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link active">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ms-auto main-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>Reports Dashboard</h2>
                    <div>
                        <span class="badge bg-primary">Admin</span>
                        <span class="ms-2">{{ user.username if user else 'Admin' }}</span>
                    </div>
                </div>
                
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Content -->
                <div class="row">
                    <div class="col-12">
                        <div class="card border-0 shadow-sm">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">System Reports</h5>
                                <button class="btn btn-sm btn-primary">Generate New Report</button>
                            </div>
                            <div class="card-body">
                                <p>Reports dashboard content will be displayed here.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
            """,
            'settings-dashboard.html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - Scanner Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 p-0 sidebar">
                <div class="text-center mb-4">
                    <h4>Scanner Platform</h4>
                    <p class="mb-0 small">Admin Panel</p>
                </div>
    
                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/customize" class="sidebar-link">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link active">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ms-auto main-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>Settings</h2>
                    <div>
                        <span class="badge bg-primary">Admin</span>
                        <span class="ms-2">{{ user.username if user else 'Admin' }}</span>
                    </div>
                </div>
                
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Content -->
                <div class="row">
                    <div class="col-12">
                        <div class="card border-0 shadow-sm">
                            <div class="card-header bg-white">
                                <h5 class="mb-0">System Settings</h5>
                            </div>
                            <div class="card-body">
                                <p>Settings dashboard content will be displayed here.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
            """,
            'scanner-management.html': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scanner Management - Scanner Platform</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 p-0 sidebar">
                <div class="text-center mb-4">
                    <h4>Scanner Platform</h4>
                    <p class="mb-0 small">Admin Panel</p>
                </div>
    
                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/customize" class="sidebar-link">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/scanners" class="sidebar-link active">
                        <i class="bi bi-search"></i> Scanner Management
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 ms-auto main-content">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h2>Scanner Management</h2>
                    <div>
                        <span class="badge bg-primary">Admin</span>
                        <span class="ms-2">{{ user.username if user else 'Admin' }}</span>
                    </div>
                </div>
                
                <!-- Flash Messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Content -->
                <div class="row">
                    <div class="col-12">
                        <div class="card border-0 shadow-sm">
                            <div class="card-header bg-white d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">Deployed Scanners</h5>
                                <a href="/customize" class="btn btn-sm btn-primary">Create New Scanner</a>
                            </div>
                            <div class="card-body p-0">
                                <div class="table-responsive">
                                    <table class="table table-hover mb-0">
                                        <thead>
                                            <tr>
                                                <th>Client</th>
                                                <th>Scanner Name</th>
                                                <th>Subdomain</th>
                                                <th>Status</th>
                                                <th>Created Date</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {% if deployed_scanners and deployed_scanners.scanners %}
                                                {% for scanner in deployed_scanners.scanners %}
                                                <tr>
                                                    <td>
                                                        <div class="d-flex align-items-center">
                                                            <div class="client-logo me-3">{{ scanner.business_name|truncate(2, True, '') }}</div>
                                                            <div>
                                                                <div class="fw-bold">{{ scanner.business_name }}</div>
                                                                <div class="text-muted small">{{ scanner.business_domain }}</div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td>{{ scanner.scanner_name }}</td>
                                                    <td>
                                                        <a href="https://{{ scanner.subdomain }}.yourscannerdomain.com" target="_blank">
                                                            {{ scanner.subdomain }}.yourscannerdomain.com
                                                        </a>
                                                    </td>
                                                    <td>
                                                        <span class="badge {% if scanner.deploy_status == 'deployed' %}bg-success{% elif scanner.deploy_status == 'pending' %}bg-warning text-dark{% else %}bg-danger{% endif %}">
                                                            {{ scanner.deploy_status|title }}
                                                        </span>
                                                    </td>
                                                    <td>{{ scanner.deploy_date|default(scanner.created_at) }}</td>
                                                    <td>
                                                        <div class="d-flex">
                                                            <a href="/admin/scanners/{{ scanner.id }}/view" class="client-action" data-bs-toggle="tooltip" title="View Scanner">
                                                                <i class="bi bi-eye"></i>
                                                            </a>
                                                            <a href="/admin/scanners/{{ scanner.id }}/edit" class="client-action" data-bs-toggle="tooltip" title="Edit Scanner">
                                                                <i class="bi bi-pencil"></i>
                                                            </a>
                                                            <a href="/admin/scanners/{{ scanner.id }}/stats" class="client-action" data-bs-toggle="tooltip" title="Scanner Stats">
                                                                <i class="bi bi-graph-up"></i>
                                                            </a>
                                                            <button class="client-action" data-bs-toggle="modal" data-bs-target="#scannerOptionsModal" data-scanner-id="{{ scanner.id }}" title="More Options">
                                                                <i class="bi bi-three-dots-vertical"></i>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                                {% endfor %}
                                            {% else %}
                                                <tr>
                                                    <td colspan="6" class="text-center py-4">
                                                        <p class="mb-0">No scanners found.</p>
                                                        <a href="/customize" class="btn btn-sm btn-primary mt-2">Create New Scanner</a>
                                                    </td>
                                                </tr>
                                            {% endif %}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Scanner Options Modal -->
    <div class="modal fade" id="scannerOptionsModal" tabindex="-1" aria-labelledby="scannerOptionsModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="scannerOptionsModalLabel">Scanner Options</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="list-group">
                        <a href="#" class="list-group-item list-group-item-action" id="viewScannerLink">
                            <i class="bi bi-eye me-2"></i> View Scanner Interface
                        </a>
                        <a href="#" class="list-group-item list-group-item-action" id="editScannerLink">
                            <i class="bi bi-pencil me-2"></i> Edit Scanner Configuration
                        </a>
                        <a href="#" class="list-group-item list-group-item-action" id="regenerateApiKeyLink">
                            <i class="bi bi-key me-2"></i> Regenerate API Key
                        </a>
                        <a href="#" class="list-group-item list-group-item-action" id="scanHistoryLink">
                            <i class="bi bi-clock-history me-2"></i> View Scan History
                        </a>
                        <a href="#" class="list-group-item list-group-item-action" id="downloadConfigLink">
                            <i class="bi bi-download me-2"></i> Download Scanner Configuration
                        </a>
                        <button class="list-group-item list-group-item-action text-danger" id="deactivateScannerBtn">
                            <i class="bi bi-slash-circle me-2"></i> Deactivate Scanner
                        </button>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize tooltips
            var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
            var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
            
            // Add pagination if needed
            if (document.querySelector('.pagination')) {
                document.querySelectorAll('.page-link').forEach(link => {
                    link.addEventListener('click', function(e) {
                        if (!this.getAttribute('href')) {
                            e.preventDefault();
                        }
                    });
                });
            }
            
            // Set up scanner options modal links
            document.querySelectorAll('[data-bs-target="#scannerOptionsModal"]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const scannerId = this.getAttribute('data-scanner-id');
                    document.getElementById('viewScannerLink').href = `/admin/scanners/${scannerId}/view`;
                    document.getElementById('editScannerLink').href = `/admin/scanners/${scannerId}/edit`;
                    document.getElementById('scanHistoryLink').href = `/admin/scanners/${scannerId}/stats`;
                    document.getElementById('downloadConfigLink').href = `/admin/scanners/${scannerId}/download-config`;
                    document.getElementById('regenerateApiKeyLink').onclick = function() {
                        // Hide scanner options modal and show regenerate API key modal
                        bootstrap.Modal.getInstance(document.getElementById('scannerOptionsModal')).hide();
                        
                        if (confirm('Are you sure you want to regenerate the API key? The old key will no longer work.')) {
                            fetch(`/admin/scanners/${scannerId}/regenerate-api-key`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                }
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.status === 'success') {
                                    alert(`New API Key: ${data.api_key}\n\nPlease save this key as it won't be shown again.`);
                                } else {
                                    alert(`Error: ${data.message || 'Failed to regenerate API key'}`);
                                }
                            })
                            .catch(error => {
                                console.error('Error:', error);
                                alert('An error occurred while regenerating the API key.');
                            });
                        }
                    };
                    
                    document.getElementById('deactivateScannerBtn').onclick = function() {
                        if (confirm('Are you sure you want to deactivate this scanner? This will make it inaccessible to users.')) {
                            fetch(`/admin/scanners/${scannerId}/toggle-status`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                }
                            })
                            .then(response => response.json())
                            .then(data => {
                                if (data.status === 'success') {
                                    alert(`Scanner status changed to: ${data.current_status}`);
                                    bootstrap.Modal.getInstance(document.getElementById('scannerOptionsModal')).hide();
                                    // Reload page to see the updated status
                                    window.location.reload();
                                } else {
                                    alert(`Error: ${data.message || 'Failed to toggle scanner status'}`);
                                }
                            })
                            .catch(error => {
                                console.error('Error:', error);
                                alert('An error occurred while toggling scanner status.');
                            });
                        }
                    };
                });
            });
        });
    </script>
</body>
</html>
            """
        }
        
        # Create each template file if it doesn't exist
        for filename, content in templates.items():
            file_path = os.path.join(template_dir, filename)
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)
                    logger.info(f"Created template: {file_path}")
            else:
                logger.info(f"Template already exists: {file_path}")
        
        return True
    except Exception as e:
        logger.error(f"Error creating templates: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

# If script is run directly
if __name__ == "__main__":
    try:
        logger.info("Applying admin route fixes...")
        result = apply_admin_route_fixes()
        if result:
            logger.info("Admin route fixes applied successfully!")
            sys.exit(0)
        else:
            logger.error("Failed to apply admin route fixes.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)
