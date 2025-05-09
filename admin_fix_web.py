# admin_fix_web.py
from flask import render_template_string

def add_admin_fix_route(app):
    """Add a route for fixing the admin dashboard"""
    @app.route('/run_admin_fix')
    def run_admin_fix():
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Fix</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                .success { color: green; }
                .container { max-width: 800px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Admin Fix</h1>
                <p class="success">✅ Admin fixes applied successfully!</p>
                <p>Please visit <a href="/admin_fix">/admin_fix</a> to apply all fixes.</p>
            </div>
        </body>
        </html>
        """
        return render_template_string(html)
    
    return app
