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
        
                    <a href="/auth/logout"
