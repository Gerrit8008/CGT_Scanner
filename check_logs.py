import os
import glob

def check_latest_log():
    logs_dir = 'logs'
    log_files = glob.glob(os.path.join(logs_dir, 'security_scan_*.log'))
    if log_files:
        latest_log = max(log_files, key=os.path.getmtime)
        with open(latest_log, 'r') as f:
            return f.read()
    return "No log files found"

if __name__ == "__main__":
    print(check_latest_log())
