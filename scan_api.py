from flask import Flask, request, jsonify
import subprocess
import json
import re
import time
import uuid
import os
from flask_cors import CORS
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-domain requests

# Configuration
SCAN_TIMEOUT = 60  # Maximum time for a scan in seconds
ALLOWED_IPS = ['127.0.0.1', 'localhost', '192.168.1.1']  # List of IPs allowed to be scanned
SCAN_HISTORY_DIR = 'scan_history'

# Create scan history directory if it doesn't exist
if not os.path.exists(SCAN_HISTORY_DIR):
    os.makedirs(SCAN_HISTORY_DIR)

@app.route('/api/scan', methods=['POST'])
def scan_ports():
    """API endpoint to scan ports using Nmap"""
    data = request.json
    
    # Validate input
    if not data or 'target' not in data:
        return jsonify({'error': 'Target IP address is required'}), 400
    
    target = data['target']
    scan_type = data.get('scan_type', 'basic')  # Default to basic scan
    
    # Security check: Only allow scanning of approved IPs
    if target not in ALLOWED_IPS and not target.startswith('192.168.'):
        return jsonify({'error': 'Scanning of this IP is not allowed for security reasons'}), 403
    
    # Generate a unique scan ID
    scan_id = str(uuid.uuid4())
    
    try:
        # Check if nmap is installed
        try:
            subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            # Nmap not available, use alternative port checker
            return perform_socket_scan(target, scan_id)
        
        # Prepare nmap command based on scan type
        if scan_type == 'basic':
            cmd = ['nmap', '-F', target]  # Fast scan of common ports
        elif scan_type == 'full':
            cmd = ['nmap', '-p', '1-65535', target]  # Full port scan
        elif scan_type == 'service':
            cmd = ['nmap', '-sV', target]  # Service detection
        else:
            return jsonify({'error': 'Invalid scan type'}), 400
        
        logging.debug(f"Running command: {' '.join(cmd)}")
        
        # Run nmap command
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            timeout=SCAN_TIMEOUT,
            text=True
        )
        
        # Process the output
        scan_results = parse_nmap_output(result.stdout)
        
        # Save scan results
        save_scan_results(scan_id, target, scan_type, scan_results)
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'results': scan_results
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': f'Scan timed out after {SCAN_TIMEOUT} seconds'}), 500
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        # If nmap fails, fallback to socket scan
        return perform_socket_scan(target, scan_id)

def perform_socket_scan(target, scan_id):
    """Perform a port scan using Python sockets (fallback if nmap is not available)"""
    try:
        logging.debug(f"Performing socket-based scan on {target}")
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        scan_results = {
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'services': {}
        }
        
        # Scan each port
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        scan_results['open_ports'].append(port)
                        service_name = get_service_name(port)
                        scan_results['services'][port] = {
                            'protocol': 'tcp',
                            'service': service_name
                        }
            except:
                scan_results['filtered_ports'].append(port)
        
        # Save scan results
        save_scan_results(scan_id, target, 'basic', scan_results)
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': 'basic',
            'results': scan_results,
            'note': 'Performed using socket-based scan (nmap not available)'
        })
    except Exception as e:
        logging.error(f"Error during socket scan: {str(e)}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

def get_service_name(port):
    """Get service name from common port numbers"""
    common_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5900: 'VNC',
        8080: 'HTTP-ALT',
        8443: 'HTTPS-ALT'
    }
    
    return common_services.get(port, 'Unknown')

def parse_nmap_output(output):
    """Parse Nmap output into a structured format"""
    results = {
        'open_ports': [],
        'filtered_ports': [],
        'closed_ports': [],
        'services': {}
    }
    
    # Extract port information using regex
    port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+([^\n]*)'
    matches = re.findall(port_pattern, output)
    
    for match in matches:
        port, protocol, state, service = match
        port = int(port)
        
        if state == 'open':
            results['open_ports'].append(port)
            results['services'][port] = {
                'protocol': protocol,
                'service': service.strip()
            }
        elif state == 'filtered':
            results['filtered_ports'].append(port)
        elif state == 'closed':
            results['closed_ports'].append(port)
    
    return results

def save_scan_results(scan_id, target, scan_type, results):
    """Save scan results to a file for future reference"""
    scan_data = {
        'scan_id': scan_id,
        'target': target,
        'scan_type': scan_type,
        'timestamp': time.time(),
        'results': results
    }
    
    filename = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
    with open(filename, 'w') as f:
        json.dump(scan_data, f, indent=2)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_results(scan_id):
    """Retrieve results of a previous scan"""
    try:
        filename = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
        if not os.path.exists(filename):
            return jsonify({'error': 'Scan not found'}), 404
        
        with open(filename, 'r') as f:
            scan_data = json.load(f)
        
        return jsonify(scan_data)
    except Exception as e:
        return jsonify({'error': f'Failed to retrieve scan: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'scan_api': 'running'
    })

if __name__ == '__main__':
    import socket  # Import socket here for fallback scan
    port = int(os.environ.get('PORT', 5001))
    logging.info(f"Starting Port Scanning API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
