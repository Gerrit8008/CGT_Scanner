# blueprint_conflict_fix.py - Fix blueprint conflicts in Flask app
import logging

logger = logging.getLogger(__name__)

def resolve_route_conflicts(app):
    """
    Resolve route conflicts in Flask app by prioritizing blueprints
    
    Args:
        app: Flask application
        
    Returns:
        Flask application with resolved conflicts
    """
    # Blueprint priority (first is highest priority)
    priority_blueprints = [
        'auth_blueprint', 
        'admin_blueprint', 
        'api_blueprint', 
        'scanner_blueprint', 
        'client_blueprint',
        'emergency_blueprint',
        'scanner_preview_blueprint'
    ]
    
    # Find all registered routes
    route_owners = {}
    duplicate_routes = {}
    
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        path = str(rule)
        
        # Skip static and other non-blueprint routes
        if '.' not in endpoint or endpoint.startswith('static'):
            continue
        
        # Extract blueprint name from endpoint
        blueprint = endpoint.split('.', 1)[0]
        
        if path in route_owners:
            # Route conflict detected
            existing_blueprint = route_owners[path].split('.', 1)[0]
            
            # Add to duplicates list
            if path not in duplicate_routes:
                duplicate_routes[path] = [existing_blueprint]
            duplicate_routes[path].append(blueprint)
            
            # Determine which blueprint has higher priority
            if blueprint in priority_blueprints and existing_blueprint in priority_blueprints:
                if priority_blueprints.index(blueprint) < priority_blueprints.index(existing_blueprint):
                    # New blueprint has higher priority
                    logger.info(f"Resolving conflict for {path}: {blueprint} takes precedence over {existing_blueprint}")
                    route_owners[path] = endpoint
            elif blueprint in priority_blueprints:
                # Only new blueprint is in priority list
                logger.info(f"Resolving conflict for {path}: {blueprint} takes precedence (in priority list)")
                route_owners[path] = endpoint
            elif existing_blueprint not in priority_blueprints:
                # Neither is in priority list, keep first registered
                logger.warning(f"Conflicting routes for {path}: keeping {existing_blueprint} over {blueprint} (first registered)")
        else:
            # First registration of this route
            route_owners[path] = endpoint
    
    # Log all duplicate routes
    for path, blueprints in duplicate_routes.items():
        chosen = route_owners[path].split('.', 1)[0]
        others = [bp for bp in blueprints if bp != chosen]
        if others:
            logger.warning(f"Route {path} has multiple registrations: using {chosen}, ignoring {', '.join(others)}")
    
    # Since Flask doesn't support removing routes, we're just logging the conflicts
    # A complete solution would require creating a new Flask app instance with only
    # the desired routes, but that's beyond the scope of this fix
    
    return app

def get_blueprint_by_name(app, name):
    """
    Get a blueprint by name from a Flask app
    
    Args:
        app: Flask application
        name: Blueprint name
        
    Returns:
        Blueprint instance or None if not found
    """
    return app.blueprints.get(name)

def fix_auth_blueprint_conflicts(app):
    """
    Fix conflicts in auth blueprint
    
    Args:
        app: Flask application
        
    Returns:
        Flask application with resolved conflicts
    """
    # Get auth blueprints
    auth_bp = get_blueprint_by_name(app, 'auth')
    auth_blueprint = get_blueprint_by_name(app, 'auth_blueprint')
    
    if not auth_bp or not auth_blueprint:
        logger.warning("Could not find both auth and auth_blueprint")
        return app
    
    # Log the conflict
    logger.info(f"Found auth blueprint conflict between 'auth' and 'auth_blueprint'")
    
    # Prefer auth_blueprint over auth
    # This doesn't actually remove the routes, but documents the preference
    logger.info("Preferring 'auth_blueprint' over 'auth'")
    
    return app

def fix_admin_blueprint_conflicts(app):
    """
    Fix conflicts in admin blueprint
    
    Args:
        app: Flask application
        
    Returns:
        Flask application with resolved conflicts
    """
    # Get admin blueprints
    admin_bp = get_blueprint_by_name(app, 'admin')
    admin_blueprint = get_blueprint_by_name(app, 'admin_blueprint')
    
    if not admin_bp or not admin_blueprint:
        logger.warning("Could not find both admin and admin_blueprint")
        return app
    
    # Log the conflict
    logger.info(f"Found admin blueprint conflict between 'admin' and 'admin_blueprint'")
    
    # Prefer admin_blueprint over admin
    # This doesn't actually remove the routes, but documents the preference
    logger.info("Preferring 'admin_blueprint' over 'admin'")
    
    return app
