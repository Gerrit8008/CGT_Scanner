# reports_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from client_db import get_db_connection
from auth_utils import verify_session
import sqlite3
from datetime import datetime, timedelta
import json

# Define reports blueprint
reports_bp = Blueprint('reports', __name__, url_prefix='/admin')

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
    decorated_function.__doc__ = f.__doc__
    return decorated_function

@reports_bp.route('/reports')
@admin_required
def reports_dashboard(user):
    """Reports dashboard"""
    report_type = request.args.get('type', 'scans')
    period = request.args.get('period', 'month')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get summary statistics
        stats = get_summary_stats(cursor, period)
        
        # Get report data based on type
        if report_type == 'scans':
            report_data = get_scan_reports(cursor, period)
        elif report_type == 'clients':
            report_data = get_client_reports(cursor, period)
        elif report_type == 'subscriptions':
            report_data = get_subscription_reports(cursor, period)
        elif report_type == 'users':
            report_data = get_user_reports(cursor, period)
        else:
            report_data = get_scan_reports(cursor, period)
            
    except Exception as e:
        conn.close()
        flash(f"Error generating reports: {str(e)}", "danger")
        return render_template(
            'admin/reports-dashboard.html',
            user=user,
            report_type=report_type,
            period=period,
            stats={},
            report_data={}
        )
    
    conn.close()
    
    return render_template(
        'admin/reports-dashboard.html',
        user=user,
        report_type=report_type,
        period=period,
        stats=stats,
        report_data=report_data
    )

@reports_bp.route('/reports/generate', methods=['POST'])
@admin_required
def generate_report(user):
    """Generate a custom report"""
    report_type = request.form.get('report_type')
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    
    if not report_type or not start_date or not end_date:
        flash("Please provide all required parameters", "danger")
        return redirect(url_for('reports.reports_dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Generate custom report based on type and date range
        if report_type == 'scans':
            report_data = generate_custom_scan_report(cursor, start_date, end_date)
        elif report_type == 'clients':
            report_data = generate_custom_client_report(cursor, start_date, end_date)
        elif report_type == 'subscriptions':
            report_data = generate_custom_subscription_report(cursor, start_date, end_date)
        elif report_type == 'users':
            report_data = generate_custom_user_report(cursor, start_date, end_date)
        else:
            flash("Invalid report type", "danger")
            conn.close()
            return redirect(url_for('reports.reports_dashboard'))
            
        conn.close()
        
        # Store report data in session for download
        session['report_data'] = json.dumps(report_data)
        
        flash("Report generated successfully", "success")
        return redirect(url_for('reports.reports_dashboard', type=report_type))
        
    except Exception as e:
        conn.close()
        flash(f"Error generating custom report: {str(e)}", "danger")
        return redirect(url_for('reports.reports_dashboard'))

@reports_bp.route('/api/report-data')
@admin_required
def api_report_data(user):
    """API endpoint to get report data"""
    report_type = request.args.get('type', 'scans')
    period = request.args.get('period', 'month')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get report data based on type
        if report_type == 'scans':
            report_data = get_scan_reports(cursor, period)
        elif report_type == 'clients':
            report_data = get_client_reports(cursor, period)
        elif report_type == 'subscriptions':
            report_data = get_subscription_reports(cursor, period)
        elif report_type == 'users':
            report_data = get_user_reports(cursor, period)
        else:
            report_data = get_scan_reports(cursor, period)
            
        conn.close()
        
        return jsonify({
            'status': 'success',
            'data': report_data
        })
        
    except Exception as e:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Helper functions for generating reports
def get_summary_stats(cursor, period):
    """Get summary statistics for dashboard"""
    # Calculate date range based on period
    today = datetime.now()
    
    if period == 'week':
        start_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')
    elif period == 'month':
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
    elif period == 'quarter':
        start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
    elif period == 'year':
        start_date = (today - timedelta(days=365)).strftime('%Y-%m-%d')
    else:
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
    
    end_date = today.strftime('%Y-%m-%d')
    
    # Get scan statistics
    cursor.execute("""
        SELECT COUNT(*) as total_scans
        FROM scan_history
        WHERE timestamp BETWEEN ? AND ?
    """, (start_date, end_date))
    
    total_scans = cursor.fetchone()[0] or 0
    
    # Get new clients
    cursor.execute("""
        SELECT COUNT(*) as new_clients
        FROM clients
        WHERE created_at BETWEEN ? AND ?
    """, (start_date, end_date))
    
    new_clients = cursor.fetchone()[0] or 0
    
    # Get active users
    cursor.execute("""
        SELECT COUNT(DISTINCT user_id) as active_users
        FROM sessions
        WHERE created_at BETWEEN ? AND ?
    """, (start_date, end_date))
    
    active_users = cursor.fetchone()[0] or 0
    
    # Get subscription revenue
    cursor.execute("""
        SELECT SUM(
            CASE 
                WHEN subscription_level = 'basic' THEN 49
                WHEN subscription_level = 'pro' THEN 149
                WHEN subscription_level = 'enterprise' THEN 399
                ELSE 0
            END
        ) as revenue
        FROM clients
        WHERE subscription_status = 'active'
    """)
    
    monthly_revenue = cursor.fetchone()[0] or 0
    
    return {
        'total_scans': total_scans,
        'new_clients': new_clients,
        'active_users': active_users,
        'monthly_revenue': "${:,.2f}".format(monthly_revenue),
        'period': period,
        'start_date': start_date,
        'end_date': end_date
    }

def get_scan_reports(cursor, period):
    """Get scan report data"""
    # Calculate date range based on period
    today = datetime.now()
    
    if period == 'week':
        start_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', timestamp)"
        label_format = "%Y-%m-%d"
    elif period == 'month':
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', timestamp)"
        label_format = "%Y-%m-%d"
    elif period == 'quarter':
        start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%W', timestamp)"
        label_format = "Week %W, %Y"
    elif period == 'year':
        start_date = (today - timedelta(days=365)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m', timestamp)"
        label_format = "%Y-%m"
    else:
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', timestamp)"
        label_format = "%Y-%m-%d"
    
    end_date = today.strftime('%Y-%m-%d')
    
    # Get scan counts by date
    cursor.execute(f"""
        SELECT 
            {group_by} as date_group,
            COUNT(*) as scan_count
        FROM scan_history
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY date_group
        ORDER BY date_group
    """, (start_date, end_date))
    
    scan_data = {}
    for row in cursor.fetchall():
        scan_data[row['date_group']] = row['scan_count']
    
    # Fill in missing dates with 0
    current_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
    
    chart_data = []
    
    while current_date <= end_datetime:
        if period == 'week':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'month':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'quarter':
            date_key = current_date.strftime('%Y-%W')
        elif period == 'year':
            date_key = current_date.strftime('%Y-%m')
        else:
            date_key = current_date.strftime('%Y-%m-%d')
        
        if date_key in scan_data:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': scan_data[date_key]
            })
        else:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': 0
            })
        
        if period == 'week' or period == 'month':
            current_date += timedelta(days=1)
        elif period == 'quarter':
            current_date += timedelta(days=7)
        elif period == 'year':
            current_date += timedelta(days=30)
        else:
            current_date += timedelta(days=1)
    
    # Get scan counts by type
    cursor.execute("""
        SELECT 
            scan_type,
            COUNT(*) as scan_count
        FROM scan_history
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY scan_type
        ORDER BY scan_count DESC
    """, (start_date, end_date))
    
    scan_types = []
    for row in cursor.fetchall():
        scan_types.append({
            'type': row['scan_type'] or 'Unknown',
            'count': row['scan_count']
        })
    
    # Get top clients by scan count
    cursor.execute("""
        SELECT 
            c.business_name,
            COUNT(s.id) as scan_count
        FROM scan_history s
        JOIN clients c ON s.client_id = c.id
        WHERE s.timestamp BETWEEN ? AND ?
        GROUP BY c.id
        ORDER BY scan_count DESC
        LIMIT 5
    """, (start_date, end_date))
    
    top_clients = []
    for row in cursor.fetchall():
        top_clients.append({
            'name': row['business_name'],
            'count': row['scan_count']
        })
    
    return {
        'chart_data': chart_data,
        'scan_types': scan_types,
        'top_clients': top_clients,
        'period': period,
        'start_date': start_date,
        'end_date': end_date
    }

def get_client_reports(cursor, period):
    """Get client report data"""
    # Calculate date range based on period
    today = datetime.now()
    
    if period == 'week':
        start_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    elif period == 'month':
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    elif period == 'quarter':
        start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%W', created_at)"
        label_format = "Week %W, %Y"
    elif period == 'year':
        start_date = (today - timedelta(days=365)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m', created_at)"
        label_format = "%Y-%m"
    else:
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    
    end_date = today.strftime('%Y-%m-%d')
    
    # Get new clients by date
    cursor.execute(f"""
        SELECT 
            {group_by} as date_group,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY date_group
        ORDER BY date_group
    """, (start_date, end_date))
    
    client_data = {}
    for row in cursor.fetchall():
        client_data[row['date_group']] = row['client_count']
    
    # Fill in missing dates with 0
    current_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
    
    chart_data = []
    
    while current_date <= end_datetime:
        if period == 'week':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'month':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'quarter':
            date_key = current_date.strftime('%Y-%W')
        elif period == 'year':
            date_key = current_date.strftime('%Y-%m')
        else:
            date_key = current_date.strftime('%Y-%m-%d')
        
        if date_key in client_data:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': client_data[date_key]
            })
        else:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': 0
            })
        
        if period == 'week' or period == 'month':
            current_date += timedelta(days=1)
        elif period == 'quarter':
            current_date += timedelta(days=7)
        elif period == 'year':
            current_date += timedelta(days=30)
        else:
            current_date += timedelta(days=1)
    
    # Get clients by subscription level
    cursor.execute("""
        SELECT 
            subscription_level,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY subscription_level
        ORDER BY client_count DESC
    """, (start_date, end_date))
    
    subscription_levels = []
    for row in cursor.fetchall():
        subscription_levels.append({
            'level': row['subscription_level'] or 'Unknown',
            'count': row['client_count']
        })
    
    # Get clients by status
    cursor.execute("""
        SELECT 
            CASE WHEN active = 1 THEN 'Active' ELSE 'Inactive' END as status,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY active
        ORDER BY client_count DESC
    """, (start_date, end_date))
    
    status_counts = []
    for row in cursor.fetchall():
        status_counts.append({
            'status': row['status'],
            'count': row['client_count']
        })
    
    return {
        'chart_data': chart_data,
        'subscription_levels': subscription_levels,
        'status_counts': status_counts,
        'period': period,
        'start_date': start_date,
        'end_date': end_date
    }

def get_subscription_reports(cursor, period):
    """Get subscription report data"""
    # Calculate date range based on period
    today = datetime.now()
    
    if period == 'week':
        start_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')
    elif period == 'month':
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
    elif period == 'quarter':
        start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
    elif period == 'year':
        start_date = (today - timedelta(days=365)).strftime('%Y-%m-%d')
    else:
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
    
    end_date = today.strftime('%Y-%m-%d')
    
    # Get subscription level distribution
    cursor.execute("""
        SELECT 
            subscription_level,
            COUNT(*) as subscription_count
        FROM clients
        WHERE subscription_status = 'active'
        GROUP BY subscription_level
        ORDER BY subscription_count DESC
    """)
    
    subscription_levels = []
    for row in cursor.fetchall():
        subscription_levels.append({
            'level': row['subscription_level'] or 'Unknown',
            'count': row['subscription_count']
        })
    
    # Calculate monthly recurring revenue
    subscription_prices = {
        'basic': 49,
        'pro': 149,
        'enterprise': 399
    }
    
    mrr_data = []
    for level in subscription_levels:
        price = subscription_prices.get(level['level'].lower(), 0)
        mrr_data.append({
            'level': level['level'],
            'count': level['count'],
            'price': price,
            'revenue': level['count'] * price
        })
    
    # Calculate total MRR
    total_mrr = sum(item['revenue'] for item in mrr_data)
    
    # Get subscription status distribution
    cursor.execute("""
        SELECT 
            subscription_status,
            COUNT(*) as status_count
        FROM clients
        GROUP BY subscription_status
        ORDER BY status_count DESC
    """)
    
    status_counts = []
    for row in cursor.fetchall():
        status_counts.append({
            'status': row['subscription_status'] or 'Unknown',
            'count': row['status_count']
        })
    
    return {
        'subscription_levels': subscription_levels,
        'mrr_data': mrr_data,
        'total_mrr': "${:,.2f}".format(total_mrr),
        'status_counts': status_counts,
        'period': period,
        'start_date': start_date,
        'end_date': end_date
    }

def get_user_reports(cursor, period):
    """Get user report data"""
    # Calculate date range based on period
    today = datetime.now()
    
    if period == 'week':
        start_date = (today - timedelta(days=7)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    elif period == 'month':
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    elif period == 'quarter':
        start_date = (today - timedelta(days=90)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%W', created_at)"
        label_format = "Week %W, %Y"
    elif period == 'year':
        start_date = (today - timedelta(days=365)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m', created_at)"
        label_format = "%Y-%m"
    else:
        start_date = (today - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = "strftime('%Y-%m-%d', created_at)"
        label_format = "%Y-%m-%d"
    
    end_date = today.strftime('%Y-%m-%d')
    
    # Get new users by date
    cursor.execute(f"""
        SELECT 
            {group_by} as date_group,
            COUNT(*) as user_count
        FROM users
        WHERE created_at BETWEEN ? AND ?
        GROUP BY date_group
        ORDER BY date_group
    """, (start_date, end_date))
    
    user_data = {}
    for row in cursor.fetchall():
        user_data[row['date_group']] = row['user_count']
    
    # Fill in missing dates with 0
    current_date = datetime.strptime(start_date, '%Y-%m-%d')
    end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
    
    chart_data = []
    
    while current_date <= end_datetime:
        if period == 'week':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'month':
            date_key = current_date.strftime('%Y-%m-%d')
        elif period == 'quarter':
            date_key = current_date.strftime('%Y-%W')
        elif period == 'year':
            date_key = current_date.strftime('%Y-%m')
        else:
            date_key = current_date.strftime('%Y-%m-%d')
        
        if date_key in user_data:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': user_data[date_key]
            })
        else:
            chart_data.append({
                'date': current_date.strftime(label_format),
                'count': 0
            })
        
        if period == 'week' or period == 'month':
            current_date += timedelta(days=1)
        elif period == 'quarter':
            current_date += timedelta(days=7)
        elif period == 'year':
            current_date += timedelta(days=30)
        else:
            current_date += timedelta(days=1)
    
    # Get users by role
    cursor.execute("""
        SELECT 
            role,
            COUNT(*) as user_count
        FROM users
        GROUP BY role
        ORDER BY user_count DESC
    """)
    
    role_counts = []
    for row in cursor.fetchall():
        role_counts.append({
            'role': row['role'] or 'Unknown',
            'count': row['user_count']
        })
    
    # Get users by status
    cursor.execute("""
        SELECT 
            CASE WHEN active = 1 THEN 'Active' ELSE 'Inactive' END as status,
            COUNT(*) as user_count
        FROM users
        GROUP BY active
        ORDER BY user_count DESC
    """)
    
    status_counts = []
    for row in cursor.fetchall():
        status_counts.append({
            'status': row['status'],
            'count': row['user_count']
        })
    
    # Get login activity
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d', created_at) as login_date,
            COUNT(*) as login_count
        FROM sessions
        WHERE created_at BETWEEN ? AND ?
        GROUP BY login_date
        ORDER BY login_date
    """, (start_date, end_date))
    
    login_data = {}
    for row in cursor.fetchall():
        login_data[row['login_date']] = row['login_count']
    
    # Fill in missing dates for login data
    login_chart_data = []
    current_date = datetime.strptime(start_date, '%Y-%m-%d')
    
    while current_date <= end_datetime:
        date_key = current_date.strftime('%Y-%m-%d')
        
        if date_key in login_data:
            login_chart_data.append({
                'date': date_key,
                'count': login_data[date_key]
            })
        else:
            login_chart_data.append({
                'date': date_key,
                'count': 0
            })
        
        current_date += timedelta(days=1)
    
    return {
        'chart_data': chart_data,
        'role_counts': role_counts,
        'status_counts': status_counts,
        'login_chart_data': login_chart_data,
        'period': period,
        'start_date': start_date,
        'end_date': end_date
    }

def generate_custom_scan_report(cursor, start_date, end_date):
    """Generate a custom scan report for the given date range"""
    # Get scan counts by date
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d', timestamp) as scan_date,
            COUNT(*) as scan_count
        FROM scan_history
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY scan_date
        ORDER BY scan_date
    """, (start_date, end_date))
    
    scan_data = []
    for row in cursor.fetchall():
        scan_data.append({
            'date': row['scan_date'],
            'count': row['scan_count']
        })
    
    # Get scan counts by type
    cursor.execute("""
        SELECT 
            scan_type,
            COUNT(*) as scan_count
        FROM scan_history
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY scan_type
        ORDER BY scan_count DESC
    """, (start_date, end_date))
    
    scan_types = []
    for row in cursor.fetchall():
        scan_types.append({
            'type': row['scan_type'] or 'Unknown',
            'count': row['scan_count']
        })
    
    # Get top clients by scan count
    cursor.execute("""
        SELECT 
            c.business_name,
            COUNT(s.id) as scan_count
        FROM scan_history s
        JOIN clients c ON s.client_id = c.id
        WHERE s.timestamp BETWEEN ? AND ?
        GROUP BY c.id
        ORDER BY scan_count DESC
        LIMIT 10
    """, (start_date, end_date))
    
    top_clients = []
    for row in cursor.fetchall():
        top_clients.append({
            'name': row['business_name'],
            'count': row['scan_count']
        })
    
    return {
        'report_type': 'scans',
        'start_date': start_date,
        'end_date': end_date,
        'scan_data': scan_data,
        'scan_types': scan_types,
        'top_clients': top_clients
    }

def generate_custom_client_report(cursor, start_date, end_date):
    """Generate a custom client report for the given date range"""
    # Get new clients by date
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d', created_at) as client_date,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY client_date
        ORDER BY client_date
    """, (start_date, end_date))
    
    client_data = []
    for row in cursor.fetchall():
        client_data.append({
            'date': row['client_date'],
            'count': row['client_count']
        })
    
    # Get clients by subscription level
    cursor.execute("""
        SELECT 
            subscription_level,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY subscription_level
        ORDER BY client_count DESC
    """, (start_date, end_date))
    
    subscription_levels = []
    for row in cursor.fetchall():
        subscription_levels.append({
            'level': row['subscription_level'] or 'Unknown',
            'count': row['client_count']
        })
    
    # Get clients by status
    cursor.execute("""
        SELECT 
            CASE WHEN active = 1 THEN 'Active' ELSE 'Inactive' END as status,
            COUNT(*) as client_count
        FROM clients
        WHERE created_at BETWEEN ? AND ?
        GROUP BY active
        ORDER BY client_count DESC
    """, (start_date, end_date))
    
    status_counts = []
    for row in cursor.fetchall():
        status_counts.append({
            'status': row['status'],
            'count': row['client_count']
        })
    
    return {
        'report_type': 'clients',
        'start_date': start_date,
        'end_date': end_date,
        'client_data': client_data,
        'subscription_levels': subscription_levels,
        'status_counts': status_counts
    }

def generate_custom_subscription_report(cursor, start_date, end_date):
    """Generate a custom subscription report for the given date range"""
    # Get subscription level distribution
    cursor.execute("""
        SELECT 
            subscription_level,
            COUNT(*) as subscription_count
        FROM clients
        WHERE subscription_status = 'active'
        AND (
            (subscription_start BETWEEN ? AND ?) OR
            (subscription_end BETWEEN ? AND ?) OR
            (subscription_start <= ? AND (subscription_end >= ? OR subscription_end IS NULL))
        )
        GROUP BY subscription_level
        ORDER BY subscription_count DESC
    """, (start_date, end_date, start_date, end_date, start_date, end_date))
    
    subscription_levels = []
    for row in cursor.fetchall():
        subscription_levels.append({
            'level': row['subscription_level'] or 'Unknown',
            'count': row['subscription_count']
        })
    
    # Calculate monthly recurring revenue
    subscription_prices = {
        'basic': 49,
        'pro': 149,
        'enterprise': 399
    }
    
    mrr_data = []
    for level in subscription_levels:
        price = subscription_prices.get(level['level'].lower(), 0)
        mrr_data.append({
            'level': level['level'],
            'count': level['count'],
            'price': price,
            'revenue': level['count'] * price
        })
    
    # Calculate total MRR
    total_mrr = sum(item['revenue'] for item in mrr_data)
    
    return {
        'report_type': 'subscriptions',
        'start_date': start_date,
        'end_date': end_date,
        'subscription_levels': subscription_levels,
        'mrr_data': mrr_data,
        'total_mrr': "${:,.2f}".format(total_mrr)
    }

def generate_custom_user_report(cursor, start_date, end_date):
    """Generate a custom user report for the given date range"""
    # Get new users by date
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d', created_at) as user_date,
            COUNT(*) as user_count
        FROM users
        WHERE created_at BETWEEN ? AND ?
        GROUP BY user_date
        ORDER BY user_date
    """, (start_date, end_date))
    
    user_data = []
    for row in cursor.fetchall():
        user_data.append({
            'date': row['user_date'],
            'count': row['user_count']
        })
    
    # Get users by role
    cursor.execute("""
        SELECT 
            role,
            COUNT(*) as user_count
        FROM users
        WHERE created_at BETWEEN ? AND ?
        GROUP BY role
        ORDER BY user_count DESC
    """, (start_date, end_date))
    
    role_counts = []
    for row in cursor.fetchall():
        role_counts.append({
            'role': row['role'] or 'Unknown',
            'count': row['user_count']
        })
    
    # Get login activity
    cursor.execute("""
        SELECT 
            strftime('%Y-%m-%d', created_at) as login_date,
            COUNT(*) as login_count
        FROM sessions
        WHERE created_at BETWEEN ? AND ?
        GROUP BY login_date
        ORDER BY login_date
    """, (start_date, end_date))
    
    login_data = []
    for row in cursor.fetchall():
        login_data.append({
            'date': row['login_date'],
            'count': row['login_count']
        })
    
    return {
        'report_type': 'users',
        'start_date': start_date,
        'end_date': end_date,
        'user_data': user_data,
        'role_counts': role_counts,
        'login_data': login_data
    }
