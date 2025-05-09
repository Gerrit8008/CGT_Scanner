# fix_admin_templates.py
import os
import logging
from flask import render_template, session, Blueprint, url_for, redirect, request, flash

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def ensure_templates_exist():
    """Create template files if they don't exist"""
    templates_dir = 'templates/admin'
    
    # Make sure the templates directory exists
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir, exist_ok=True)
        logger.info(f"Created templates directory: {templates_dir}")
    
    # Define templates to create
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
                                                            <a href="#" class="client-action" data-bs-toggle="tooltip" title="View Scanner">
                                                                <i class="bi bi-eye"></i>
                                                            </a>
                                                            <a href="#" class="client-action" data-bs-toggle="tooltip" title="Edit Scanner">
                                                                <i class="bi bi-pencil"></i>
                                                            </a>
                                                            <a href="#" class="client-action" data-bs-toggle="tooltip" title="Scanner Stats">
                                                                <i class="bi bi-graph-up"></i>
                                                            </a>
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
    
    <!-- JavaScript -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """,
        'error.html': """
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
    }
    
    # Create each template
    for template_name, template_content in templates.items():
        template_path = os.path.join(templates_dir, template_name)
        
        # Only create if it doesn't exist
        if not os.path.exists(template_path):
            with open(template_path, 'w') as f:
                f.write(template_content)
            logger.info(f"Created template: {template_name}")
        else:
            logger.info(f"Template already exists: {template_name}")
    
    return True

def create_admin_routes_file():
    """Create a Python module with routes"""
    route_file = 'admin_routes.py'
    
    # Only create if it doesn't exist
    if os.path.exists(route_file):
        logger.info(f"File already exists: {route_file}")
        return True
    
    # Content for the file
    content = """
# admin_routes.py
from flask import Blueprint, render_template, redirect, url_for, session, request, flash
from auth_utils import verify_session

# Create the admin_routes blueprint for missing admin pages
admin_routes_bp = Blueprint('admin_routes', __name__, url_prefix='/admin')

# Middleware to require admin login
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        result = verify_session(session_token)
        
        if result['status'] != 'success' or result['user']['role'] != 'admin':
            flash('You need administrative privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Add user info to kwargs
        kwargs['user'] = result['user']
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_routes_bp.route('/subscriptions')
@admin_required
def subscriptions(user):
    """Subscriptions management page"""
    return render_template(
        'admin/subscription-management.html',
        user=user
    )

@admin_routes_bp.route('/reports')
@admin_required
def reports(user):
    """Reports dashboard page"""
    return render_template(
        'admin/reports-dashboard.html',
        user=user
    )

@admin_routes_bp.route('/settings')
@admin_required
def settings(user):
    """Settings dashboard page"""
    return render_template(
        'admin/settings-dashboard.html',
        user=user
    )

@admin_routes_bp.route('/scanners')
@admin_required
def scanners(user):
    """Scanner management page"""
    # In a real implementation, you'd retrieve deployed scanners from the database
    return render_template(
        'admin/scanner-management.html',
        user=user,
        deployed_scanners={
            'scanners': [],
            'pagination': {
                'page': 1,
                'per_page': 10,
                'total_count': 0, 
                'total_pages': 1
            }
        },
        filters={}
    )
"""
    
    # Write the file
    with open(route_file, 'w') as f:
        f.write(content)
    
    logger.info(f"Created file: {route_file}")
    return True

def create_fix_route():
    """Create a route in the Flask app to fix the admin dashboard"""
    # Create file
    file_path = 'fix_route.py'
    
    # Only create if it doesn't exist
    if os.path.exists(file_path):
        logger.info(f"File already exists: {file_path}")
        return True
    
    # Content for the file
    content = """
# fix_route.py
from flask import Flask, render_template, url_for
import os
import logging

logger = logging.getLogger(__name__)

def fix_dashboard():
    """Fix the admin dashboard by creating necessary templates and routes"""
    try:
        # Import functions to create templates and routes
        from fix_admin_templates import ensure_templates_exist, create_admin_routes_file
        
        # Make sure templates exist
        templates_created = ensure_templates_exist()
        
        # Create admin routes file
        routes_created = create_admin_routes_file()
        
        return {
            'templates_created': templates_created,
            'routes_created': routes_created,
            'status': 'success' if templates_created and routes_created else 'partial'
        }
    except Exception as e:
        logger.error(f"Error fixing dashboard: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        return {
            'templates_created': False,
            'routes_created': False,
            'status': 'error',
            'error': str(e)
        }

def add_fix_route(app):
    """Add a route to the Flask app to fix the admin dashboard"""
    @app.route('/fix_admin_dashboard')
    def fix_admin_dashboard():
        # Run the fix
        result = fix_dashboard()
        
        # Create HTML response
        if result['status'] == 'success':
            status_class = 'success'
            status_text = 'Success'
        elif result['status'] == 'partial':
            status_class = 'warning'
            status_text = 'Partial Success'
        else:
            status_class = 'danger'
            status_text = 'Error'
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Dashboard Fix</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                h1 {{ color: #333; }}
                .success {{ color: green; }}
                .warning {{ color: orange; }}
                .danger {{ color: red; }}
                .result {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>Admin Dashboard Fix</h1>
            
            <div class="result">
                <h2 class="{status_class}">Status: {status_text}</h2>
                
                <h3>Results:</h3>
                <ul>
                    <li>Templates Created: {'✅ Yes' if result['templates_created'] else '❌ No'}</li>
                    <li>Routes Created: {'✅ Yes' if result['routes_created'] else '❌ No'}</li>
                </ul>
                
                {f'<p class="danger">Error: {result["error"]}</p>' if result.get('error') else ''}
            </div>
            
            <h3>Next Steps:</h3>
            <p>Now that the templates have been created, follow these steps to complete the fix:</p>
            <ol>
                <li>Make sure you've registered the admin_routes blueprint in your app.py:
                    <pre>
from admin_routes import admin_routes_bp
app.register_blueprint(admin_routes_bp)
                    </pre>
                </li>
                <li>Restart your Flask application</li>
                <li><a href="/admin/dashboard">Go to Admin Dashboard</a></li>
            </ol>
        </body>
        </html>
        '''
        
        return html
"""

def register_admin_routes(app):
    """Register the admin_routes blueprint with the Flask app"""
    try:
        # Import the blueprint - this requires the file to exist
        from admin_routes import admin_routes_bp
        
        # Register the blueprint
        app.register_blueprint(admin_routes_bp)
        
        return True
    except ImportError:
        logger.error("Could not import admin_routes_bp - make sure admin_routes.py exists")
        return False
    except Exception as e:
        logger.error(f"Error registering admin_routes blueprint: {e}")
        return False
