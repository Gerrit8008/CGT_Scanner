# install_fixes.py
import os
import sys
import importlib
import subprocess

def check_prerequisites():
    """Check if all required files are available"""
    required_files = ['admin.py', 'client_db.py']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print("❌ Missing required files:")
        for f in missing_files:
            print(f"  - {f}")
        return False
    
    return True

def install_fix_scripts():
    """Install the fix scripts"""
    # Create admin_dashboard_fix.py
    with open('admin_dashboard_fix.py', 'w') as f:
        f.write(get_dashboard_fix_content())
    
    # Create route_fix_content.py
    with open('route_fix_content.py', 'w') as f:
        f.write(get_route_fix_content())
    
    print("✅ Fix scripts installed successfully")
    return True

def run_fixes():
    """Run the fix scripts"""
    try:
        result = subprocess.run([sys.executable, 'admin_dashboard_fix.py'], capture_output=True, text=True)
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"❌ Fix script failed with error code {result.returncode}")
            if result.stderr:
                print(f"Error output:\n{result.stderr}")
            return False
        
        return True
    except Exception as e:
        print(f"❌ Error running fix script: {e}")
        return False

def get_dashboard_fix_content():
    """Return the content of admin_dashboard_fix.py"""
    # This would normally be loading from a file or url, but we'll include it for simplicity
    # [Insert the content of admin_dashboard_fix.py here]
    # For brevity, this function is not fully implemented here
    pass

def get_route_fix_content():
    """Return the content of route_fix_content.py"""
    # This would normally be loading from a file or url, but we'll include it for simplicity
    # [Insert the content of route_fix_content.py here]
    # For brevity, this function is not fully implemented here
    pass

def main():
    """Main function"""
    print("=" * 60)
    print("Admin Dashboard Fix Installer")
    print("=" * 60)
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n❌ Prerequisites check failed. Please make sure all required files are available.")
        return 1
    
    # Install fix scripts
    if not install_fix_scripts():
        print("\n❌ Failed to install fix scripts.")
        return 1
    
    # Ask user to proceed with fixes
    print("\nReady to apply fixes to your admin dashboard.")
    response = input("Proceed with applying fixes? (y/n): ")
    
    if response.lower() not in ['y', 'yes']:
        print("Installation cancelled by user.")
        return 0
    
    # Run fixes
    if not run_fixes():
        print("\n❌ Failed to apply fixes.")
        return 1
    
    print("\n✅ All fixes applied successfully!")
    print("You can now access the admin dashboard at: /admin/dashboard")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
