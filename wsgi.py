# For debugging, import from app_debug instead of app
try:
    from app_debug import app
except ImportError:
    # Fall back to regular app if debug version is not available
    from app import app

if __name__ == "__main__":
    app.run()
