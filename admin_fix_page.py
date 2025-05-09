# admin_fix_page.py
from flask import render_template_string, redirect, url_for
import os
import logging

logger = logging.getLogger(__name__)

def ensure_templates_exist():
    """Create template files if they don't exist"""
    templates_dir = 'templates/admin'
    
    # Make sure the templates directory exists
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir, exist_ok=True)
    
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
                                                    <td>{{ scanner.business_name }}</td>
                                                    <td>{{ scanner.scanner_name }}</td>
                                                    <td>{{ scanner.subdomain }}</td>
                                                    <td>{{ scanner.deploy_status }}</td>
                                                    <td>{{ scanner.deploy_date }}</td>
                                                    <td>
                                                        <div class="d-flex">
                                                            <a href="#" class="btn btn-sm btn-outline-primary me-2">View</a>
                                                            <a href="#" class="btn btn-sm btn-outline-secondary">Edit</a>
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
        """
    }
    
    # Create each template
    for template_name, template_content in templates.items():
        template_path = os.path.join(templates_dir, template_name)
        
        # Only create if it doesn't exist
        if not os.path.exists(template_path):
            os.makedirs(os.path.dirname(template_path), exist_ok=True)
            with open(template_path, 'w') as f:
                f.write(template_content)
            logger.info(f"Created template: {template_name}")
        else:
            logger.info(f"Template already exists: {template_name}")
    
    return True

def create_admin_routes():
    """Create admin_routes.py with routes for admin pages"""
    admin_routes_content = """# admin_routes.py
from flask import Blueprint, render_template, redirect, url_for, session, request, flash

# Create a blueprint for the missing admin routes
admin_routes_bp = Blueprint('admin_routes', __name__, url_prefix='/admin')

# Middleware for admin authorization
def admin_required(f):
    def decorated_function(*args, **kwargs):
        session_token = session.get('session_token')
        
        if not session_token:
            return redirect(url_for('auth.login', next=request.url))
        
        # Get user information from session
        username = session.get('username')
        role = session.get('role')
        
        if role != 'admin':
            flash('You need administrative privileges to access this page', 'danger')
            return redirect(url_for('auth.login'))
        
        # Create user dict for templates
        user = {'username': username, 'role': role}
        
        # Add user info to kwargs
        kwargs['user'] = user
        return f(*args, **kwargs)
    
    # Preserve function metadata
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_routes_bp.route('/subscriptions')
@admin_required
def subscriptions(user):
    """Subscriptions management page"""
    return render_template('admin/subscription-management.html', user=user)

@admin_routes_bp.route('/reports')
@admin_required
def reports(user):
    """Reports dashboard page"""
    return render_template('admin/reports-dashboard.html', user=user)

@admin_routes_bp.route('/settings')
@admin_required
def settings(user):
    """Settings dashboard page"""
    return render_template('admin/settings-dashboard.html', user=user)

@admin_routes_bp.route('/scanners')
@admin_required
def scanners(user):
    """Scanner management page"""
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
    with open('admin_routes.py', 'w') as f:
        f.write(admin_routes_content)
    
    return True

def add_fix_page(app):
    """Add a page to fix the admin dashboard"""
    @app.route('/admin_fix')
    def admin_fix():
        """Fix the admin dashboard"""
        # Create templates if they don't exist
        templates_created = ensure_templates_exist()
        
        # Create admin_routes.py if it doesn't exist
        routes_created = create_admin_routes()
        
        # Try to register the blueprint
        blueprint_registered = False
        
        if routes_created:
            try:
                from admin_routes import admin_routes_bp
                app.register_blueprint(admin_routes_bp)
                blueprint_registered = True
            except ImportError:
                logger.error("Could not import admin_routes_bp")
            except Exception as e:
                logger.error(f"Error registering admin_routes_bp: {e}")
        
        # Create HTML output
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Dashboard Fix</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                h1, h2 {{ color: #333; }}
                .success {{ color: green; }}
                .error {{ color: red; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .result {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Admin Dashboard Fix</h1>
                
                <div class="result">
                    <h2>Fix Results:</h2>
                    <p class="{'success' if templates_created else 'error'}">Templates Created: {'✅ Yes' if templates_created else '❌ No'}</p>
                    <p class="{'success' if routes_created else 'error'}">Routes Created: {'✅ Yes' if routes_created else '❌ No'}</p>
                    <p class="{'success' if blueprint_registered else 'error'}">Blueprint Registered: {'✅ Yes' if blueprint_registered else '❌ No'}</p>
                </div>
                
                <h2>Next Steps:</h2>
                <p><a href="/admin/dashboard">Go to Admin Dashboard</a></p>
                <p><a href="/admin/settings">Go to Settings</a></p>
                <p><a href="/admin/reports">Go to Reports</a></p>
                <p><a href="/admin/subscriptions">Go to Subscriptions</a></p>
                <p><a href="/admin/scanners">Go to Scanner Management</a></p>
            </div>
        </body>
        </html>
        """
        
        return render_template_string(html)
    
    return app
