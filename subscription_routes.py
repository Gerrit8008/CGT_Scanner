# subscription_routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from client_db import get_db_connection, list_subscriptions, update_subscription, get_subscription_by_id
from auth_utils import verify_session
import sqlite3
from datetime import datetime

# Define subscriptions blueprint
subscription_bp = Blueprint('subscription', __name__, url_prefix='/admin')

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

@subscription_bp.route('/subscriptions')
@admin_required
def subscription_list(user):
    """List all client subscriptions"""
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get filter parameters
    filters = {}
    if 'level' in request.args and request.args.get('level'):
        filters['level'] = request.args.get('level')
    if 'status' in request.args and request.args.get('status'):
        filters['status'] = request.args.get('status')
    if 'search' in request.args and request.args.get('search'):
        filters['search'] = request.args.get('search')
    
    # Get subscription data
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Calculate subscription statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_count,
                SUM(CASE WHEN subscription_status = 'active' THEN 1 ELSE 0 END) as active_count,
                SUM(CASE WHEN subscription_level = 'basic' THEN 1 ELSE 0 END) as basic_count,
                SUM(CASE WHEN subscription_level = 'pro' THEN 1 ELSE 0 END) as pro_count,
                SUM(CASE WHEN subscription_level = 'enterprise' THEN 1 ELSE 0 END) as enterprise_count
            FROM clients
        """)
        
        stats = dict(cursor.fetchone() or {})
        
        # Get all subscriptions
        subscriptions = []
        
        # List all subscriptions with client information
        cursor.execute("""
            SELECT 
                c.id, 
                c.business_name, 
                c.subscription_level, 
                c.subscription_status, 
                c.subscription_start, 
                c.subscription_end,
                c.created_at
            FROM clients c
            WHERE 1=1
            """ + 
            ("AND c.subscription_level = ?" if 'level' in filters else "") +
            ("AND c.subscription_status = ?" if 'status' in filters else "") +
            ("AND (c.business_name LIKE ? OR c.contact_email LIKE ?)" if 'search' in filters else "") +
            """
            ORDER BY 
                CASE WHEN c.subscription_status = 'active' THEN 0 ELSE 1 END,
                c.subscription_end
            LIMIT ? OFFSET ?
        """)
        
        # Build parameter list based on filters
        params = []
        if 'level' in filters:
            params.append(filters['level'])
        if 'status' in filters:
            params.append(filters['status'])
        if 'search' in filters:
            search_term = f"%{filters['search']}%"
            params.append(search_term)
            params.append(search_term)
            
        # Add pagination parameters
        params.extend([per_page, (page - 1) * per_page])
        
        # Execute query with parameters
        cursor.execute(cursor.statement, params)
        subscriptions = [dict(row) for row in cursor.fetchall()]
        
        # Count total matching rows for pagination
        count_query = """
            SELECT COUNT(*) FROM clients
            WHERE 1=1
            """ + \
            ("AND subscription_level = ?" if 'level' in filters else "") + \
            ("AND subscription_status = ?" if 'status' in filters else "") + \
            ("AND (business_name LIKE ? OR contact_email LIKE ?)" if 'search' in filters else "")
            
        count_params = []
        if 'level' in filters:
            count_params.append(filters['level'])
        if 'status' in filters:
            count_params.append(filters['status'])
        if 'search' in filters:
            search_term = f"%{filters['search']}%"
            count_params.append(search_term)
            count_params.append(search_term)
            
        cursor.execute(count_query, count_params)
        total_count = cursor.fetchone()[0]
        
        # Calculate monthly revenue
        cursor.execute("""
            SELECT SUM(
                CASE 
                    WHEN subscription_level = 'basic' THEN 49
                    WHEN subscription_level = 'pro' THEN 149
                    WHEN subscription_level = 'enterprise' THEN 399
                    ELSE 0
                END
            ) as monthly_revenue
            FROM clients
            WHERE subscription_status = 'active'
        """)
        
        monthly_revenue = cursor.fetchone()[0] or 0
        
        # Format currency
        stats['monthly_revenue'] = "${:,.2f}".format(monthly_revenue)
        
        # Calculate pagination
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': (total_count + per_page - 1) // per_page,
        }
        
    except Exception as e:
        conn.close()
        flash(f"Error loading subscriptions: {str(e)}", "danger")
        return render_template(
            'admin/subscription-management.html',
            user=user,
            subscriptions=[],
            pagination={},
            stats={},
            filters=filters
        )
    
    conn.close()
    
    return render_template(
        'admin/subscription-management.html',
        user=user,
        subscriptions=subscriptions,
        pagination=pagination,
        stats=stats,
        filters=filters
    )

@subscription_bp.route('/subscriptions/<int:client_id>/edit', methods=['GET', 'POST'])
@admin_required
def subscription_edit(user, client_id):
    """Edit client subscription"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get client subscription data
    cursor.execute("""
        SELECT 
            c.id, 
            c.business_name, 
            c.subscription_level, 
            c.subscription_status, 
            c.subscription_start, 
            c.subscription_end
        FROM clients c
        WHERE c.id = ?
    """, (client_id,))
    
    subscription = dict(cursor.fetchone() or {})
    
    if not subscription:
        conn.close()
        flash("Subscription not found", "danger")
        return redirect(url_for('subscription.subscription_list'))
    
    if request.method == 'POST':
        # Process form submission
        subscription_data = {
            'subscription_level': request.form.get('subscription_level'),
            'subscription_status': request.form.get('subscription_status'),
            'subscription_start': request.form.get('subscription_start'),
            'subscription_end': request.form.get('subscription_end')
        }
        
        try:
            # Update subscription
            cursor.execute("""
                UPDATE clients
                SET 
                    subscription_level = ?,
                    subscription_status = ?,
                    subscription_start = ?,
                    subscription_end = ?,
                    updated_at = ?,
                    updated_by = ?
                WHERE id = ?
            """, (
                subscription_data['subscription_level'],
                subscription_data['subscription_status'],
                subscription_data['subscription_start'],
                subscription_data['subscription_end'],
                datetime.now().isoformat(),
                user['id'],
                client_id
            ))
            
            conn.commit()
            flash("Subscription updated successfully", "success")
            return redirect(url_for('subscription.subscription_list'))
            
        except Exception as e:
            conn.rollback()
            flash(f"Error updating subscription: {str(e)}", "danger")
    
    conn.close()
    
    return render_template(
        'admin/subscription-edit.html',
        user=user,
        subscription=subscription
    )

@subscription_bp.route('/api/subscription-stats')
@admin_required
def api_subscription_stats(user):
    """API endpoint to get subscription statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Calculate subscription statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_count,
                SUM(CASE WHEN subscription_status = 'active' THEN 1 ELSE 0 END) as active_count,
                SUM(CASE WHEN subscription_level = 'basic' AND subscription_status = 'active' THEN 1 ELSE 0 END) as basic_count,
                SUM(CASE WHEN subscription_level = 'pro' AND subscription_status = 'active' THEN 1 ELSE 0 END) as pro_count,
                SUM(CASE WHEN subscription_level = 'enterprise' AND subscription_status = 'active' THEN 1 ELSE 0 END) as enterprise_count
            FROM clients
        """)
        
        stats = dict(cursor.fetchone() or {})
        
        # Calculate monthly revenue
        cursor.execute("""
            SELECT SUM(
                CASE 
                    WHEN subscription_level = 'basic' THEN 49
                    WHEN subscription_level = 'pro' THEN 149
                    WHEN subscription_level = 'enterprise' THEN 399
                    ELSE 0
                END
            ) as monthly_revenue
            FROM clients
            WHERE subscription_status = 'active'
        """)
        
        monthly_revenue = cursor.fetchone()[0] or 0
        
        # Format currency
        stats['monthly_revenue'] = monthly_revenue
        stats['formatted_revenue'] = "${:,.2f}".format(monthly_revenue)
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'data': stats
        })
        
    except Exception as e:
        conn.close()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
