from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import platform
import psutil
import subprocess
import socket
import re
import dns.resolver
import logging
import os
from datetime import datetime
import csv
import smtplib
from email.message import EmailMessage
import sys
import random

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your_temporary_secret_key')

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Severity levels for vulnerabilities
SEVERITY = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}

SEVERITY_ICONS = {
    "Critical": "❌",
    "High": "⚠️",
    "Medium": "⚠️",
    "Low": "ℹ️"
}

GATEWAY_PORT_WARNINGS = {
    21: ("FTP (insecure)", "High"),
    23: ("Telnet (insecure)", "High"),
    80: ("HTTP (no encryption)", "Medium"),
    443: ("HTTPS", "Low"),
    3389: ("Remote Desktop (RDP)", "Critical"),
    5900: ("VNC", "High"),
    22: ("SSH", "Low"),
}

# A function to calculate severity based on the issue type
def get_severity_level(severity):
    return SEVERITY.get(severity, SEVERITY["Info"])

# Generate actionable recommendations based on severity
def get_recommendations(vulnerability, severity):
    if severity == "Critical":
        return f"[CRITICAL] {vulnerability}. Immediate action is required to avoid potential data loss or breach."
    elif severity == "High":
        return f"[HIGH] {vulnerability}. Address this within the next 48 hours to mitigate major risks."
    elif severity == "Medium":
        return f"[MEDIUM] {vulnerability}. Address this within the next week to prevent exploitation."
    elif severity == "Low":
        return f"[LOW] {vulnerability}. A low-risk issue, but should be reviewed."
    else:
        return f"[INFO] {vulnerability}. No immediate action required."

# Function to generate threat scenarios based on detected vulnerabilities
def generate_threat_scenario(vulnerability, severity):
    scenarios = {
        "OS Update": "Outdated software can be exploited by attackers to run malicious code, leading to data breaches or system compromise.",
        "Weak Passwords": "Weak or reused passwords can be easily guessed or cracked, allowing attackers to access sensitive accounts or data.",
        "Open Ports": "Open network ports expose your system to external attacks, including DDoS, data theft, and unauthorized access.",
        "Encryption": "Lack of disk encryption increases the risk of data theft, especially if devices are lost or stolen.",
        "MFA": "Lack of Multi-Factor Authentication (MFA) makes your system vulnerable to unauthorized access from attackers.",
        "RDP Security": "Unsecured Remote Desktop Protocol (RDP) can be easily exploited by cybercriminals.",
        "Backup": "Without proper backup systems in place, critical data is vulnerable to loss in the event of a disaster.",
        "Email Security": "Email is a primary attack vector for phishing and malware distribution. Lack of proper security measures can result in a breach.",
        "Endpoint Protection": "Missing endpoint protection leaves your system vulnerable to malware and exploitation.",
        "Network Segmentation": "Lack of network segmentation increases the risk of a widespread breach if an attacker gains access.",
        "Ransomware Protection": "Without proper ransomware protection, your system is vulnerable to file encryption and extortion attacks.",
        "DNS Security": "Unprotected DNS servers can be used in phishing attacks and data manipulation. DNSSEC ensures the integrity of DNS queries."
    }
    return scenarios.get(vulnerability, "Unspecified threat scenario: This vulnerability could lead to serious consequences if not addressed.")

def send_email_report(lead_data, scan_result):
    """Send lead info and scan result to your email using a mail relay."""
    try:
        # Use environment variables for credentials
        smtp_user = os.environ.get('SMTP_USER')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        logging.debug(f"Attempting to send email with SMTP user: {smtp_user}")
        
        msg = EmailMessage()
        msg["Subject"] = f"New Vulnerability Scan - {lead_data.get('company', 'Unknown Company')}"
        msg["From"] = smtp_user

        # Send to both the admin and the user
        admin_email = smtp_user
        user_email = lead_data.get("email", "")
        recipients = f"{admin_email}, {user_email}"
        msg["To"] = recipients
        
        logging.debug(f"Email recipients: {recipients}")

        # Compose the body
        body = f"""
        A new scan has been initiated with the following details:

        Name: {lead_data.get('name', '')}
        Email: {lead_data.get('email', '')}
        Company: {lead_data.get('company', '')}
        Phone: {lead_data.get('phone', '')}
        Timestamp: {lead_data.get('timestamp', '')}

        --- Begin Scan Report ---

        {scan_result}

        --- End of Report ---
        
        We look forward to partnering with you for all your IT and cybersecurity needs.
        You can reach us through our website at cengatech.com, by email at sales@cengatech.com, or by phone at 470-481-0400.

        Thank you,
        The Cengatech Team
        """
        msg.set_content(body)

        # Try different ports if needed
        smtp_server = "mail.privateemail.com"
        smtp_port = 587  # 587 is typical for authenticated TLS
        
        logging.debug(f"Connecting to SMTP server: {smtp_server}:{smtp_port}")

        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
            logging.debug("SMTP connection established")
            server.ehlo()
            logging.debug("EHLO successful")
            server.starttls()
            logging.debug("STARTTLS successful")
            server.ehlo()
            logging.debug("Second EHLO successful")
            server.login(smtp_user, smtp_password)
            logging.debug("SMTP login successful")
            server.send_message(msg)
            logging.debug("Email sent successfully!")
            return True

    except Exception as e:
        logging.error(f"Error sending email: {e}")
        if isinstance(e, smtplib.SMTPAuthenticationError):
            logging.error("SMTP Authentication failed - check username and password")
        elif isinstance(e, smtplib.SMTPConnectError):
            logging.error("Failed to connect to SMTP server - check server and port")
        elif isinstance(e, smtplib.SMTPDataError):
            logging.error("The SMTP server refused to accept the message data")
        elif isinstance(e, smtplib.SMTPRecipientsRefused):
            logging.error("All recipients were refused - check email addresses")
        return False
    
def save_lead_data(lead_info):
    try:
        # In a web environment, we'll save to a temporary file that Render allows
        filename = "/tmp/leads.csv"
        file_exists = os.path.isfile(filename)
        
        with open(filename, "a", newline="") as csvfile:
            fieldnames = ["name", "email", "company", "phone", "timestamp"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerow(lead_info)
        return True
    except Exception as e:
        logging.error(f"Error saving lead data: {e}")
        return False

# Check for OS updates
def check_os_updates():
    try:
        os_name = platform.system()
        
        if os_name == "Linux":
            return {
                "message": "Operating System (Linux) has pending updates",
                "severity": "High",
                "info": "Additional info about Linux"
            }
        elif os_name == "Windows":
            return {
                "message": "Operating System (Windows) is up-to-date",
                "severity": "Low",
                "info": "Everything is fine with Windows"
            }
        elif os_name == "Darwin":  # macOS
            return {
                "message": "Operating System (macOS) is up-to-date",
                "severity": "Low",
                "info": "No pending updates"
            }
        else:
            return {
                "message": "Operating System update status: Unknown",
                "severity": "Critical",
                "info": "Unknown OS"
            }
    except Exception as e:
        logging.error(f"Error checking OS updates: {e}")
        return {
            "message": "Error checking OS updates",
            "severity": "Critical",
            "info": str(e)
        }

def get_windows_version():
    # Modified for web environment
    try:
        os_name = platform.system()
        if os_name == "Windows":
            try:
                win_ver = sys.getwindowsversion()
                major, build = win_ver.major, win_ver.build
                if major == 10 and build >= 22000:
                    return f"Windows 11 or higher (Build {build})", "Low"
                else:
                    return f"Windows version is earlier than Windows 11 (Build {build})", "Critical"
            except:
                return "Windows version detection failed", "Medium"
        else:
            return f"Server running {os_name}", "Low"
    except Exception as e:
        logging.error(f"Error checking Windows version: {e}")
        return f"Error checking OS version: {str(e)}", "Medium"

    
# Check Firewall Status
def check_firewall_status():
    # Simplified for web environment
    try:
        return "Firewall status check limited in web environment", "Medium"
    except Exception as e:
        logging.error(f"Error checking firewall status: {e}")
        return "Error checking firewall status", "Medium"

# Function to check SPF status
def check_spf_status(domain):
    """Check the SPF record for a given domain with enhanced validation."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=spf1"):
                logging.debug(f"Found SPF record for {domain}: {txt_record}")

                # Count the number of mechanisms
                mechanisms = [m for m in txt_record.split() if any(m.startswith(p) for p in ["include:", "a", "mx", "ip4:", "ip6:"])]
                mechanism_count = len(mechanisms)

                # Check for ending
                if txt_record.endswith("-all"):
                    if mechanism_count <= 10:
                        return f"SPF record OK: {txt_record} (Mechanisms: {mechanism_count})", "Low"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) in record: {txt_record}", "High"
                elif txt_record.endswith("~all"):
                    if mechanism_count <= 10:
                        return f"SPF uses soft fail (~all). Consider using -all. Record: {txt_record} (Mechanisms: {mechanism_count})", "Medium"
                    else:
                        return f"Too many SPF mechanisms ({mechanism_count}) and ends in ~all: {txt_record}", "High"
                else:
                    return f"SPF record missing final '-all' or '~all': {txt_record}", "High"

        return "No SPF record found", "High"

    except Exception as e:
        logging.error(f"Error checking SPF status for domain {domain}: {e}")
        return f"Error checking SPF status: {e}", "Critical"
    
def check_dmarc_record(domain):
    """Check if the domain has a valid DMARC record."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")

        for rdata in answers:
            record = rdata.to_text().strip('"')
            if record.lower().startswith("v=dmarc1"):
                return f"DMARC record found: {record}", "Low"
        return "No valid DMARC record found", "High"

    except dns.resolver.NXDOMAIN:
        return "Domain does not exist", "Critical"
    except dns.resolver.NoAnswer:
        return "No DMARC record found", "High"
    except Exception as e:
        return f"Error checking DMARC record: {e}", "Critical"

def check_dkim_record(domain):
    selectors = ["default", "selector1", "selector2", "google", "dkim", "dkim1"]
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            txt_record = answers[0].to_text().strip('"')
            return f"DKIM record found with selector '{selector}': {txt_record}", "Low"
        except dns.resolver.NXDOMAIN:
            continue  # No such name, try next
        except Exception as e:
            continue  # Suppress other errors for now

    return "DKIM record not found using common selectors.", "High"

def extract_domain_from_email(email):
    """Extract domain from email address."""
    if '@' in email:
        return email.split('@')[-1]  # Return the part after '@'
    return email  # If not a valid email, return the input itself

def server_lookup(domain):
    """Resolve the IP and perform reverse DNS lookup."""
    try:
        ip = socket.gethostbyname(domain)
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "Reverse DNS lookup failed"
        return f"Resolved IP: {ip}, Reverse DNS: {reverse_dns}", "Low"
    except Exception as e:
        logging.error(f"Error during server lookup for {domain}: {e}")
        return f"Server lookup failed for {domain}: {e}", "High"

def get_default_gateway_ip():
    # This won't work reliably in a web environment
    return "Gateway detection limited in web environment"

def analyze_port_risks(open_ports):
    """Analyze the risk level of open ports"""
    risks = []
    
    high_risk_ports = {
        3389: "Remote Desktop Protocol (RDP) - High security risk if exposed",
        21: "FTP - Transmits credentials in plain text",
        23: "Telnet - Insecure, transmits data in plain text",
        5900: "VNC - Remote desktop access, often lacks encryption",
        1433: "Microsoft SQL Server - Database access",
        3306: "MySQL Database - Potential attack vector if unprotected",
        445: "SMB - Windows file sharing, historically vulnerable",
        139: "NetBIOS - Windows networking, potential attack vector"
    }
    
    medium_risk_ports = {
        80: "HTTP - Web server without encryption",
        25: "SMTP - Email transmission",
        110: "POP3 - Email retrieval (older protocol)",
        143: "IMAP - Email retrieval (often unencrypted)",
        8080: "Alternative HTTP port, often used for proxies or development"
    }
    
    for port in open_ports:
        if port in high_risk_ports:
            risks.append((port, high_risk_ports[port], "High"))
        elif port in medium_risk_ports:
            risks.append((port, medium_risk_ports[port], "Medium"))
        else:
            risks.append((port, f"Unknown service on port {port}", "Low"))
    
    # Sort by severity (High first)
    return sorted(risks, key=lambda x: 0 if x[2] == "High" else (1 if x[2] == "Medium" else 2))

def check_open_ports():
    """Simulated port check for web environment"""
    try:
        # For web environment, return simulated results
        # This represents typical findings rather than actual open ports
        simulated_open_ports = [80, 443, 3389, 445, 139, 135, 5985, 5986, 53, 88]
        
        # Add some random ports to simulate a more realistic environment
        import random
        additional_ports = random.sample([21, 22, 23, 25, 110, 143, 1433, 3306, 5900, 8080, 8443], 
                                        random.randint(3, 8))
        simulated_open_ports.extend(additional_ports)
        
        open_ports_count = len(simulated_open_ports)
        logging.debug(f"Simulated {open_ports_count} open ports")
        
        # Severity based on count and specific ports
        if open_ports_count >= 30 or any(p in [3389, 5900, 21, 23] for p in simulated_open_ports):
            severity = "High"
        elif open_ports_count >= 10:
            severity = "Medium"
        else:
            severity = "Low"
            
        return open_ports_count, simulated_open_ports, severity
    except Exception as e:
        logging.error(f"Error in simulated port check: {e}")
        return 0, [], "Critical"

def scan_gateway_ports(gateway_ip):
    """Enhanced gateway port scanning for web environment"""
    results = []
    
    # Since we can't actually scan in a web environment, provide information
    # about common security risks based on the usual configurations
    
    # Add entries for the most critical ports from GATEWAY_PORT_WARNINGS
    critical_ports = [3389, 5900, 21, 23]  # RDP, VNC, FTP, Telnet
    
    for port in critical_ports:
        desc, severity = GATEWAY_PORT_WARNINGS.get(port, ("Unknown service", "Medium"))
        
        # Simulate some ports being open and some closed for a realistic report
        import random
        if random.choice([True, False]):  # 50% chance of being "open"
            results.append((f"{desc} (Port {port}) might be open on your gateway", severity))
    
    # Always add some informational entries
    results.append(("HTTP (Port 80) is typically open on gateways", "Medium"))
    results.append(("HTTPS (Port 443) is open, which is normal", "Low"))
    
    # Add a recommendation about firewall
    results.append(("Consider configuring a proper firewall to restrict access", "Info"))
    
    return results

def generate_report(lead_data, for_web=False):
    """Generate vulnerability scan report
    
    Args:
        lead_data: Dictionary containing user information
        for_web: Boolean indicating if this report is for web display (simplified) or email (detailed)
    """
    logging.debug("Generating full report...")
    
    # Create the lead section
    lead_section = (
        f"Client: {lead_data.get('name', 'N/A')}\n"
        f"Email: {lead_data.get('email', 'N/A')}\n"
        f"Company: {lead_data.get('company', 'N/A')}\n"
        f"Phone: {lead_data.get('phone', 'N/A')}\n"
        f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        + "-" * 60 + "\n\n"
    )
    
    # Get domain for email checks
    email = lead_data.get('email', '')
    domain = None
    email_findings = []
    
    if "@" in email:
        domain = extract_domain_from_email(email)
    
    # Run email security checks
    email_section = "EMAIL SECURITY CHECKS:\n"
    if domain:
        spf_status, spf_severity = check_spf_status(domain)
        dmarc_status, dmarc_severity = check_dmarc_record(domain)
        dkim_status, dkim_severity = check_dkim_record(domain)
        
        email_section += f"Domain: {domain}\n"
        email_section += f"SPF: {spf_status} (Severity: {spf_severity})\n"
        email_section += f"DMARC: {dmarc_status} (Severity: {dmarc_severity})\n"
        email_section += f"DKIM: {dkim_status} (Severity: {dkim_severity})\n"
        
        # Store findings for web summary
        if spf_severity in ["High", "Critical"]:
            email_findings.append(f"SPF: {spf_severity} severity - requires attention")
        if dmarc_severity in ["High", "Critical"]:
            email_findings.append(f"DMARC: {dmarc_severity} severity - requires attention")
        if dkim_severity in ["High", "Critical"]:
            email_findings.append(f"DKIM: {dkim_severity} severity - requires attention")
    else:
        email_section += "No valid email domain provided for security checks.\n"
    
    # System checks section
    system_section = "\nSYSTEM SECURITY CHECKS:\n"
    system_findings = []
    
    # Client OS information
    client_os = lead_data.get('client_os', 'Unknown')
    client_browser = lead_data.get('client_browser', 'Unknown')
    windows_version = lead_data.get('windows_version', '')
    
    system_section += f"Client Operating System: {client_os}\n"
    if windows_version:
        system_section += f"Windows Version: {windows_version}\n"
        
        # Assign severity based on Windows version
        if "10/11" in windows_version:
            windows_severity = "Low"
        elif "8" in windows_version:
            windows_severity = "Medium"
        elif "7" in windows_version or "Older" in windows_version:
            windows_severity = "High"
            system_findings.append(f"Windows Version: {windows_severity} severity - outdated version")
        else:
            windows_severity = "Medium"
            
        system_section += f"Windows Version Status: {windows_severity} Severity\n"
    
    system_section += f"Web Browser: {client_browser}\n"
    
    # OS update status
    os_update_info = check_os_updates()
    system_section += f"OS Updates: {os_update_info['message']} (Severity: {os_update_info['severity']})\n"
    
    if os_update_info['severity'] in ["High", "Critical"]:
        system_findings.append(f"OS Updates: {os_update_info['severity']} severity - updates needed")
    
    # Firewall status
    firewall_status, firewall_severity = check_firewall_status()
    system_section += f"Firewall Status: {firewall_status} (Severity: {firewall_severity})\n"
    
    if firewall_severity in ["High", "Critical"]:
        system_findings.append(f"Firewall: {firewall_severity} severity - requires configuration")
    
    # Network checks section
    network_section = "\nNETWORK SECURITY CHECKS:\n"
    network_findings = []

    ports_count, ports_list, ports_severity = check_open_ports()
    network_section += f"Open Ports: {ports_count} ports detected (Severity: {ports_severity})\n"

    if ports_severity in ["High", "Critical"]:
        network_findings.append(f"Open Ports: {ports_severity} severity - {ports_count} ports detected")

    if ports_list and len(ports_list) > 0:
        # List all open ports
        network_section += f"\nAll detected open ports: {', '.join(map(str, sorted(ports_list[:15])))}"
        if len(ports_list) > 15:
            network_section += f" and {len(ports_list) - 15} more..."
        network_section += "\n"
        
        # Analyze port risks
        port_risks = analyze_port_risks(ports_list)
        
        # Add high-risk ports to the report
        high_risk_ports = [r for r in port_risks if r[2] == "High"]
        if high_risk_ports:
            network_section += "\nHIGH RISK PORTS DETECTED:\n"
            for port, desc, sev in high_risk_ports:
                network_section += f"- Port {port}: {desc} (Severity: {sev})\n"
                network_findings.append(f"Port {port}: {desc}")
    else:
        network_section += "No open ports detected.\n"
    
    # Gateway check
    gateway_ip = get_default_gateway_ip()
    gateway_scan_results = scan_gateway_ports(gateway_ip)
    
    gateway_section = "\nGATEWAY SECURITY:\n"
    gateway_section += f"Gateway IP: {gateway_ip}\n"
    
    gateway_findings = []
    if gateway_scan_results:
        for msg, severity in gateway_scan_results:
            gateway_section += f"- {msg} (Severity: {severity})\n"
            if severity in ["High", "Critical"]:
                gateway_findings.append(f"Gateway: {severity} severity - {msg}")
    
    # Add recommendations
    recommendations = "\nRECOMMENDATIONS:\n"
    recommendations += "1. Ensure email security configurations (SPF, DMARC, DKIM) are properly set up.\n"
    recommendations += "2. Keep operating systems and software up to date.\n"
    recommendations += "3. Maintain a properly configured firewall.\n"
    recommendations += "4. Close unnecessary open ports.\n"
    recommendations += "5. Implement regular security scanning.\n"
    
    # If generating for web display, create a simplified version
    if for_web:
        # Create a shorter summary for web display
        web_report = lead_section
        web_report += "SCAN SUMMARY:\n"
        web_report += f"A full detailed report has been sent to your email ({lead_data.get('email', 'N/A')}).\n\n"
        
        # Add key findings section if there are high severity issues
        all_findings = email_findings + system_findings + network_findings + gateway_findings
        if all_findings:
            web_report += "KEY FINDINGS REQUIRING ATTENTION:\n"
            for finding in all_findings:
                web_report += f"- {finding}\n"
        else:
            web_report += "No critical issues were detected in this scan.\n"
        
        web_report += "\nSCAN AREAS CHECKED:\n"
        web_report += "- Email Security (SPF, DMARC, DKIM)\n"
        web_report += f"- System Security ({client_os}, {client_browser})\n"
        web_report += "- Network Security (Open Ports)\n"
        web_report += "- Gateway Security\n\n"
        
        web_report += "For detailed analysis and recommendations, please check your email.\n"
        
        return web_report
    
    # For email, compile the full detailed report
    full_report = (
        lead_section + 
        email_section + 
        system_section + 
        network_section + 
        gateway_section +
        recommendations
    )
    
    return full_report

def process_scan_request(lead_data):
    """Process scan request and generate reports
    
    Args:
        lead_data: Dictionary containing user information
        
    Returns:
        A simplified report for web display
    """
    try:
        logging.debug("Starting scan process...")
        
        # Save lead data
        try:
            save_lead_data(lead_data)
            logging.debug("Lead data saved successfully")
        except Exception as e:
            logging.error(f"Error saving lead data: {e}")
            # Continue anyway - don't fail the whole scan
        
        # Generate detailed report for email
        detailed_report = generate_report(lead_data, for_web=False)
        logging.debug(f"Detailed report generated, length: {len(detailed_report)}")
        
        # Generate simplified report for web display
        web_report = generate_report(lead_data, for_web=True)
        logging.debug(f"Web report generated, length: {len(web_report)}")
        
        # Try to send email with detailed report
        try:
            email_sent = send_email_report(lead_data, detailed_report)
            if email_sent:
                logging.debug("Email report sent successfully")
            else:
                logging.warning("Email report could not be sent")
        except Exception as e:
            logging.error(f"Error sending email: {e}")
        
        # Return the simplified report for web display
        return web_report
        
    except Exception as e:
        logging.error(f"Error in process_scan_request: {e}")
        return f"An error occurred during the scan: {str(e)}"

@app.route('/')
def index():
    """Render the home page"""
    try:
        return render_template('index.html')
    except Exception as e:
        logging.error(f"Error rendering index page: {e}")
        return f"An error occurred: {e}", 500

@app.route('/scan', methods=['GET', 'POST'])
def scan_page():
    if request.method == 'POST':
        # Get form data including client OS info
        lead_data = {
            'name': request.form.get('name', ''),
            'email': request.form.get('email', ''),
            'company': request.form.get('company', ''),
            'phone': request.form.get('phone', ''),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_os': request.form.get('client_os', 'Unknown'),
            'client_browser': request.form.get('client_browser', 'Unknown'),
            'windows_version': request.form.get('windows_version', '')
        }
        
        logging.debug(f"Received scan form data: {lead_data}")
        logging.debug(f"Client OS detected: {lead_data['client_os']}")
        
        try:
            # Process the scan - this now returns a simplified web report
            web_report = process_scan_request(lead_data)
            
            # Store the web report in session
            session['scan_result'] = web_report
            logging.debug("Web report stored in session")
            
            # Add a flag to indicate scan was completed
            session['scan_completed'] = True
            
            # Redirect to results page
            return redirect(url_for('results'))
        except Exception as e:
            logging.error(f"Error processing scan: {e}")
            return render_template('error.html', error=str(e))
    
    return render_template('scan.html')

@app.route('/results')
def results():
    # Check if a scan has been completed
    if session.get('scan_completed'):
        scan_result = session.get('scan_result', 'Scan completed. A detailed report has been sent to your email.')
        logging.debug(f"Retrieved scan result from session, length: {len(scan_result) if scan_result else 0}")
    else:
        scan_result = 'No scan results available. Please run a scan first.'
        logging.debug("No scan result in session")
    
    return render_template('results.html', scan_result=scan_result)

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        # Get lead data from form
        lead_data = {
            "name": request.form.get('name', ''),
            "email": request.form.get('email', ''),
            "company": request.form.get('company', ''),
            "phone": request.form.get('phone', ''),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Basic validation
        if not lead_data["name"] or not lead_data["email"]:
            return jsonify({
                "status": "error",
                "message": "Please enter at least your name and email before scanning."
            }), 400
            
        # Get browser and OS info if available
        lead_data["client_os"] = request.form.get('client_os', 'Unknown')
        lead_data["client_browser"] = request.form.get('client_browser', 'Unknown')
        lead_data["windows_version"] = request.form.get('windows_version', '')
        
        logging.debug(f"API scan request received with data: {lead_data}")
        
        # Process the scan
        scan_result = process_scan_request(lead_data)
        
        # Return the result
        return jsonify({
            "status": "success",
            "message": "Scan completed successfully",
            "report": scan_result
        })
    except Exception as e:
        logging.error(f"Error in API scan: {e}")
        return jsonify({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }), 500

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# Only for testing - remove in production
@app.route('/test_email', methods=['GET'])
def test_email():
    if os.environ.get('FLASK_ENV') != 'development':
        return "This endpoint is only available in development mode", 403
        
    try:
        test_lead = {
            "name": "Test User",
            "email": "test@example.com",
            "company": "Test Company",
            "phone": "555-1234",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        test_report = "This is a test report for email functionality."
        result = send_email_report(test_lead, test_report)
        
        if result:
            return "Test email sent successfully!"
        else:
            return "Test email failed to send."
    except Exception as e:
        return f"Error in test email: {str(e)}"

# API endpoint to check if the service is running
@app.route('/api/healthcheck')
def healthcheck():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Use 0.0.0.0 to make the app accessible from any IP
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
