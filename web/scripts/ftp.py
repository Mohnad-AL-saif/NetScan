#!/usr/bin/env python3
"""
FTP Master - Complete FTP Enumeration & Exploitation Suite
Version: 2.0
"""

import sys
import os
import socket
import ftplib
import subprocess
import argparse
import json
from pathlib import Path
from datetime import datetime
import re
import time
from urllib.parse import urlparse

# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    NC = '\033[0m'

# Global variables
results = {
    'anon_login': False,
    'authenticated': False,
    'write_perm': False,
    'mkdir_perm': False,
    'file_count': 0,
    'total_size': '0',
    'ftp_type': 'Unknown',
    'valid_credentials': []
}

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        
    def log(self, level, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        colors = {
            'INFO': Colors.CYAN + '[*]' + Colors.NC,
            'SUCCESS': Colors.GREEN + '[✓]' + Colors.NC,
            'ERROR': Colors.RED + '[✗]' + Colors.NC,
            'WARNING': Colors.YELLOW + '[!]' + Colors.NC,
            'CRITICAL': Colors.RED + Colors.BOLD + '[!!!]' + Colors.NC
        }
        
        print(f"{colors.get(level, '')} {message}")
        
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")

def run_command(cmd, logger=None, description=None, timeout=300, shell=True):
    """Run command with colored output"""
    if description and logger:
        logger.log('INFO', description)
    
    # Print command in red
    print(f"\n{'=' * 60}")
    print(f"{Colors.RED}{cmd if isinstance(cmd, str) else ' '.join(cmd)}{Colors.NC}")
    print(f"{'=' * 60}\n")
    
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Print output in green
        if result.stdout:
            print(f"{Colors.GREEN}{result.stdout}{Colors.NC}")
        
        return result
    except subprocess.TimeoutExpired:
        if logger:
            logger.log('WARNING', f"Command timed out")
        return None
    except Exception as e:
        if logger:
            logger.log('ERROR', f"Command failed: {str(e)}")
        return None

def show_banner():
    #os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{Colors.PURPLE}{Colors.BOLD}")
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   ███████╗████████╗██████╗     ███╗   ███╗ █████╗ ███████╗      ║
    ║   ██╔════╝╚══██╔══╝██╔══██╗    ████╗ ████║██╔══██╗██╔════╝      ║
    ║   █████╗     ██║   ██████╔╝    ██╔████╔██║███████║███████╗      ║
    ║   ██╔══╝     ██║   ██╔═══╝     ██║╚██╔╝██║██╔══██║╚════██║      ║
    ║   ██║        ██║   ██║         ██║ ╚═╝ ██║██║  ██║███████║      ║
    ║   ╚═╝        ╚═╝   ╚═╝         ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝      ║
    ║                                                                   ║
    ║              🔥 Complete FTP Audit & Exploitation 🔥             ║
    ║                         Version 2.0                               ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    print(Colors.NC)

def setup_environment(target, output_dir):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if not output_dir:
        output_dir = f"ftp_{target}_{timestamp}"
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    Path(f"{output_dir}/logs").mkdir(exist_ok=True)
    Path(f"{output_dir}/downloads").mkdir(exist_ok=True)
    Path(f"{output_dir}/reports").mkdir(exist_ok=True)
    Path(f"{output_dir}/evidence").mkdir(exist_ok=True)
    
    log_file = f"{output_dir}/logs/audit_{timestamp}.log"
    
    return output_dir, log_file

def phase1_discovery(target, port, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 1: Network & Service Discovery                     ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    # Port check
    logger.log('INFO', f"Checking if port {port} is open...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            logger.log('SUCCESS', f"Port {port} is OPEN")
        else:
            logger.log('ERROR', f"Port {port} is CLOSED or FILTERED")
            return False
    except Exception as e:
        logger.log('ERROR', f"Connection error: {str(e)}")
        return False
    finally:
        sock.close()
    
    # Banner grabbing
    logger.log('INFO', "Banner grabbing...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        logger.log('SUCCESS', f"Banner: {banner}")
        
        with open(f"{evidence_dir}/banner.txt", 'w') as f:
            f.write(banner)
        
        # Detect FTP type
        if 'vsftpd' in banner.lower():
            results['ftp_type'] = 'vsftpd'
        elif 'proftpd' in banner.lower():
            results['ftp_type'] = 'ProFTPD'
        elif 'filezilla' in banner.lower():
            results['ftp_type'] = 'FileZilla'
        elif 'microsoft' in banner.lower():
            results['ftp_type'] = 'Microsoft IIS'
        
        logger.log('INFO', f"Detected FTP server: {results['ftp_type']}")
        
    except Exception as e:
        logger.log('WARNING', f"Could not grab banner: {str(e)}")
    
    return True

def phase2_authentication(target, port, username, password, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 2: Authentication Testing                          ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    # Test anonymous login
    logger.log('INFO', "Testing anonymous login...")
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login('anonymous', 'anonymous@test.com')
        
        logger.log('CRITICAL', "Anonymous login is ENABLED!")
        results['anon_login'] = True
        
        # Get system info
        try:
            syst = ftp.sendcmd('SYST')
            logger.log('INFO', f"System: {syst}")
            
            with open(f"{evidence_dir}/system_info.txt", 'w') as f:
                f.write(syst)
        except:
            pass
        
        # Get features
        try:
            feat = ftp.sendcmd('FEAT')
            logger.log('INFO', "Extracting supported features...")
            
            with open(f"{evidence_dir}/features.txt", 'w') as f:
                f.write(feat)
        except:
            pass
        
        ftp.quit()
        return 'anonymous', 'anonymous@test.com'
        
    except ftplib.error_perm:
        logger.log('WARNING', "Anonymous login is DISABLED")
        results['anon_login'] = False
        
        # Try provided credentials
        if username and password:
            logger.log('INFO', f"Testing provided credentials: {username}:{password}")
            if test_credentials(target, port, username, password, evidence_dir, logger):
                return username, password
        
        return None, None
        
    except Exception as e:
        logger.log('ERROR', f"Connection error: {str(e)}")
        return None, None

def test_credentials(target, port, username, password, evidence_dir, logger):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login(username, password)
        
        logger.log('CRITICAL', f"Valid credentials found: {username}:{password}")
        results['authenticated'] = True
        results['valid_credentials'].append(f"{username}:{password}")
        
        with open(f"{evidence_dir}/valid_credentials.txt", 'a') as f:
            f.write(f"{username}:{password}\n")
        
        ftp.quit()
        return True
        
    except:
        return False

def phase3_permissions(target, port, username, password, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 3: Permission Analysis                              ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    if not username:
        logger.log('WARNING', "Skipping permission analysis (no valid credentials)")
        return
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login(username, password)
        
        # Test write permission
        logger.log('INFO', "Testing write permission (file upload)...")
        
        test_file = '/tmp/ftp_test_upload.txt'
        with open(test_file, 'w') as f:
            f.write('FTP Master Test File')
        
        try:
            with open(test_file, 'rb') as f:
                ftp.storbinary('STOR test_write.txt', f)
            
            logger.log('CRITICAL', "WRITE permission detected - File upload is ALLOWED!")
            results['write_perm'] = True
            
            # Try to delete test file
            try:
                ftp.delete('test_write.txt')
            except:
                pass
                
        except ftplib.error_perm:
            logger.log('INFO', "Write permission denied")
            results['write_perm'] = False
        
        # Test directory creation
        logger.log('INFO', "Testing directory creation permission...")
        
        try:
            ftp.mkd('test_dir_creation')
            logger.log('CRITICAL', "Directory creation is ALLOWED!")
            results['mkdir_perm'] = True
            
            try:
                ftp.rmd('test_dir_creation')
            except:
                pass
                
        except ftplib.error_perm:
            logger.log('INFO', "Directory creation denied")
            results['mkdir_perm'] = False
        
        ftp.quit()
        
        # Clean up
        try:
            os.remove(test_file)
        except:
            pass
            
    except Exception as e:
        logger.log('ERROR', f"Permission test error: {str(e)}")

def phase4_traversal(target, port, username, password, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 4: Directory Traversal Testing                      ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    if not username:
        logger.log('WARNING', "Skipping traversal testing (no valid credentials)")
        return
    
    logger.log('INFO', "Testing directory traversal vulnerabilities...")
    
    traversal_paths = [
        "/etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\xampp\\passwords.txt"
    ]
    
    vulnerable_paths = []
    
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=10)
        ftp.login(username, password)
        
        for path in traversal_paths:
            try:
                size = ftp.size(path)
                if size:
                    logger.log('CRITICAL', f"Directory traversal SUCCESS: {path} (Size: {size} bytes)")
                    vulnerable_paths.append(f"{path}|{size}")
            except:
                pass
        
        ftp.quit()
        
        if vulnerable_paths:
            logger.log('CRITICAL', "Server is vulnerable to directory traversal!")
            with open(f"{evidence_dir}/traversal_vulnerable.txt", 'w') as f:
                for path in vulnerable_paths:
                    f.write(path + '\n')
        else:
            logger.log('SUCCESS', "No directory traversal vulnerabilities found")
            
    except Exception as e:
        logger.log('ERROR', f"Traversal test error: {str(e)}")

def phase5_download(target, port, username, password, downloads_dir, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 5: File Download & Mirroring                        ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    if not username:
        logger.log('WARNING', "Skipping file download (no valid credentials)")
        return
    
    logger.log('INFO', "Starting recursive file download...")
    
    # Using wget
    logger.log('INFO', "Using wget for mirroring...")
    
    url = f"ftp://{username}:{password}@{target}:{port}/"
    
    cmd = [
        'wget', '-r', '-nH', '--cut-dirs=1',
        '--no-parent',
        '--reject=index.html*',
        '--timeout=30',
        '--tries=3',
        '-P', downloads_dir,
        url
    ]
    
    try:
        result = run_command(cmd, logger, "Executing wget to mirror FTP content", timeout=300, shell=False)
        
        with open(f"{evidence_dir}/wget.log", 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        
        # Count files
        file_count = sum(1 for _ in Path(downloads_dir).rglob('*') if _.is_file())
        results['file_count'] = file_count
        
        if file_count > 0:
            logger.log('SUCCESS', f"Downloaded {file_count} files")
            
            # Calculate size
            result = run_command(['du', '-sh', downloads_dir], logger, "Calculating download size", shell=False)
            total_size = result.stdout.split()[0]
            results['total_size'] = total_size
            logger.log('INFO', f"Total download size: {total_size}")
            
            # Generate file list
            with open(f"{evidence_dir}/downloaded_files.txt", 'w') as f:
                for file in Path(downloads_dir).rglob('*'):
                    if file.is_file():
                        f.write(f"{file}\n")
        else:
            logger.log('WARNING', "No files downloaded")
            
    except subprocess.TimeoutExpired:
        logger.log('WARNING', "Download timed out")
    except Exception as e:
        logger.log('ERROR', f"Download error: {str(e)}")

def phase6_analysis(downloads_dir, evidence_dir, logger):
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  PHASE 6: Content Analysis & Secret Detection              ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    if not Path(downloads_dir).exists() or not any(Path(downloads_dir).iterdir()):
        logger.log('WARNING', "No files to analyze")
        return
    
    logger.log('INFO', "Analyzing downloaded files for sensitive data...")
    
    # Search for sensitive keywords
    keywords = r"password|passwd|pwd|user|username|admin|root|key|token|secret|api|credential|login|auth|private|confidential"
    
    logger.log('INFO', "Searching for sensitive keywords...")
    
    try:
        result = run_command(
            f"grep -rEiI '{keywords}' {downloads_dir} 2>/dev/null | head -100",
            logger,
            "Searching for sensitive keywords",
            shell=True
        )
        
        if result.stdout:
            with open(f"{evidence_dir}/sensitive_keywords.txt", 'w') as f:
                f.write(result.stdout)
            
            match_count = len(result.stdout.strip().split('\n'))
            logger.log('CRITICAL', f"Found {match_count} potential sensitive data matches!")
        else:
            logger.log('SUCCESS', "No obvious sensitive data found")
    except:
        pass
    
    # Search for patterns
    logger.log('INFO', "Searching for specific patterns...")
    
    patterns = {
        'emails': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        'ips': r"\b([0-9]{1,3}\.){3}[0-9]{1,3}\b",
        'urls': r"(https?|ftp)://[^\s\"']+",
        'cc': r"\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"
    }
    
    for name, pattern in patterns.items():
        try:
            result = run_command(
                f"grep -rEhoI '{pattern}' {downloads_dir} 2>/dev/null | sort -u",
                logger,
                f"Searching for {name}",
                shell=True
            )
            
            if result.stdout:
                output_file = f"{evidence_dir}/{name}_found.txt"
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                count = len(result.stdout.strip().split('\n'))
                logger.log('INFO', f"Found {count} {name}")
        except:
            pass
    
    # Search for private keys
    try:
        result = run_command(
            f"grep -rl 'BEGIN.*PRIVATE KEY' {downloads_dir} 2>/dev/null",
            logger,
            "Searching for private keys",
            shell=True
        )
        
        if result.stdout:
            with open(f"{evidence_dir}/private_keys.txt", 'w') as f:
                f.write(result.stdout)
            
            count = len(result.stdout.strip().split('\n'))
            logger.log('CRITICAL', f"Found {count} private key files!")
    except:
        pass

def generate_html_report(target, port, reports_dir, evidence_dir):
    html_file = f"{reports_dir}/ftp_audit_report.html"
    
    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FTP Master - Audit Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(26, 26, 46, 0.9);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            text-align: center;
            border-bottom: 3px solid #00ff88;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            background: rgba(255, 255, 255, 0.05);
            border-left: 4px solid #667eea;
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
        }}
        .section h2 {{
            color: #00ff88;
            margin-bottom: 15px;
            font-size: 1.5em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }}
        .info-item {{
            background: rgba(102, 126, 234, 0.1);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}
        .info-item strong {{
            color: #00ff88;
            display: block;
            margin-bottom: 5px;
        }}
        .findings {{
            background: rgba(255, 71, 87, 0.1);
            border: 2px solid #ff4757;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .findings h3 {{
            color: #ff4757;
            margin-bottom: 15px;
        }}
        ul {{
            list-style-position: inside;
            margin: 10px 0;
        }}
        li {{
            padding: 5px 0;
        }}
        .footer {{
            background: rgba(0, 0, 0, 0.3);
            padding: 20px;
            text-align: center;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }}
        pre {{
            background: #0a0a0a;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid #333;
            color: #00ff88;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 FTP Master - Audit Report 🔥</h1>
            <div class="subtitle">Comprehensive FTP Security Assessment</div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🎯 Target Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <strong>Target IP:</strong>
                        {target}
                    </div>
                    <div class="info-item">
                        <strong>Port:</strong>
                        {port}
                    </div>
                    <div class="info-item">
                        <strong>Server Type:</strong>
                        {results['ftp_type']}
                    </div>
                    <div class="info-item">
                        <strong>Scan Date:</strong>
                        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                </div>
            </div>
            
            <div class="findings">
                <h3>🚨 Critical Security Findings</h3>
                <ul>
"""
    
    if results['anon_login']:
        html_content += "                    <li><span>⚠️</span> Anonymous login is ENABLED</li>\n"
    if results['write_perm']:
        html_content += "                    <li><span>🔴</span> Write permission detected - File upload allowed</li>\n"
    if results['mkdir_perm']:
        html_content += "                    <li><span>🔴</span> Directory creation allowed</li>\n"
    if Path(f"{evidence_dir}/traversal_vulnerable.txt").exists():
        html_content += "                    <li><span>🔴</span> Directory traversal vulnerability detected</li>\n"
    
    html_content += f"""                </ul>
            </div>
            
            <div class="section">
                <h2>📊 Statistics</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <strong>Files Downloaded:</strong>
                        {results['file_count']}
                    </div>
                    <div class="info-item">
                        <strong>Total Size:</strong>
                        {results['total_size']}
                    </div>
                    <div class="info-item">
                        <strong>Authentication:</strong>
                        {'Anonymous' if results['anon_login'] else 'Required'}
                    </div>
                    <div class="info-item">
                        <strong>Write Access:</strong>
                        {'Enabled' if results['write_perm'] else 'Disabled'}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by FTP Master v2.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"""
    
    with open(html_file, 'w') as f:
        f.write(html_content)
    
    return html_file

def generate_json_report(target, port, reports_dir, evidence_dir):
    json_file = f"{reports_dir}/ftp_audit_report.json"
    
    banner = ""
    if Path(f"{evidence_dir}/banner.txt").exists():
        with open(f"{evidence_dir}/banner.txt") as f:
            banner = f.read().strip()
    
    report = {
        "scan_info": {
            "target": target,
            "port": port,
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "version": "2.0"
        },
        "server_info": {
            "type": results['ftp_type'],
            "banner": banner
        },
        "authentication": {
            "anonymous_enabled": results['anon_login'],
            "authenticated": results['authenticated']
        },
        "permissions": {
            "write": results['write_perm'],
            "mkdir": results['mkdir_perm']
        },
        "downloads": {
            "file_count": results['file_count'],
            "total_size": results['total_size']
        },
        "vulnerabilities": {
            "directory_traversal": Path(f"{evidence_dir}/traversal_vulnerable.txt").exists()
        }
    }
    
    with open(json_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return json_file

def generate_text_summary(target, port, reports_dir, evidence_dir):
    summary_file = f"{reports_dir}/summary.txt"
    
    summary = f"""╔═══════════════════════════════════════════════════════════════════════════╗
║                     FTP MASTER - AUDIT SUMMARY                            ║
╚═══════════════════════════════════════════════════════════════════════════╝

TARGET INFORMATION
------------------
IP Address      : {target}
Port            : {port}
Server Type     : {results['ftp_type']}
Scan Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

AUTHENTICATION STATUS
--------------------
Anonymous Login : {'ENABLED ⚠️' if results['anon_login'] else 'DISABLED ✓'}
Authenticated   : {'YES' if results['authenticated'] else 'NO'}

PERMISSIONS
-----------
File Upload     : {'ALLOWED 🔴' if results['write_perm'] else 'DENIED ✓'}
Dir Creation    : {'ALLOWED 🔴' if results['mkdir_perm'] else 'DENIED ✓'}

DOWNLOADS
---------
Files Retrieved : {results['file_count']}
Total Size      : {results['total_size']}

VULNERABILITIES
---------------
"""
    
    if results['anon_login']:
        summary += "⚠️  Anonymous access enabled\n"
    if results['write_perm']:
        summary += "🔴 Write permission (file upload) allowed\n"
    if results['mkdir_perm']:
        summary += "🔴 Directory creation allowed\n"
    if Path(f"{evidence_dir}/traversal_vulnerable.txt").exists():
        summary += "🔴 Directory traversal vulnerability\n"
    
    summary += """
RECOMMENDATIONS
---------------
"""
    
    if results['anon_login']:
        summary += "• Disable anonymous FTP access\n"
    if results['write_perm']:
        summary += "• Restrict write permissions\n"
    if results['mkdir_perm']:
        summary += "• Disable directory creation for untrusted users\n"
    
    summary += """• Use FTPS/SFTP instead of plain FTP
• Implement strong authentication
• Enable logging and monitoring

╔═══════════════════════════════════════════════════════════════════════════╗
║                         END OF REPORT                                     ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
    
    with open(summary_file, 'w') as f:
        f.write(summary)
    
    print(summary)
    
    return summary_file

def main():
    parser = argparse.ArgumentParser(
        description='FTP Master - Complete FTP Enumeration & Exploitation Suite',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('port', help='FTP port')
    parser.add_argument('proto', help='Protocol (tcp/udp)')
    parser.add_argument('outdir', help='Output directory')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    target = args.target
    port = int(args.port)
    output_dir = args.outdir
    
    show_banner()
    
    # Setup environment
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    evidence_dir = f"{output_dir}/evidence"
    downloads_dir = f"{output_dir}/downloads"
    reports_dir = f"{output_dir}/reports"
    
    Path(evidence_dir).mkdir(exist_ok=True)
    Path(downloads_dir).mkdir(exist_ok=True)
    Path(reports_dir).mkdir(exist_ok=True)
    
    log_file = f"{output_dir}/ftp_audit.log"
    logger = Logger(log_file)
    
    logger.log('INFO', f"FTP Master v2.0 - Starting audit of {target}:{port}")
    logger.log('INFO', f"Output directory: {output_dir}")
    
    # Execute phases
    if not phase1_discovery(target, port, evidence_dir, logger):
        logger.log('ERROR', "Discovery phase failed")
        return 1
    
    username, password = phase2_authentication(target, port, args.username, args.password, evidence_dir, logger)
    
    if username:
        phase3_permissions(target, port, username, password, evidence_dir, logger)
        phase4_traversal(target, port, username, password, evidence_dir, logger)
        phase5_download(target, port, username, password, downloads_dir, evidence_dir, logger)
        phase6_analysis(downloads_dir, evidence_dir, logger)
    
    # Generate reports
    print()
    print(f"{Colors.PURPLE}{Colors.BOLD}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}║  Generating Reports                                         ║{Colors.NC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
    print()
    
    logger.log('INFO', "Generating comprehensive reports...")
    
    html_report = generate_html_report(target, port, reports_dir, evidence_dir)
    json_report = generate_json_report(target, port, reports_dir, evidence_dir)
    text_report = generate_text_summary(target, port, reports_dir, evidence_dir)
    
    logger.log('SUCCESS', f"HTML report: {html_report}")
    logger.log('SUCCESS', f"JSON report: {json_report}")
    logger.log('SUCCESS', f"Summary: {text_report}")
    
    # Final message
    print()
    print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.GREEN}{Colors.BOLD}           ✅ FTP AUDIT COMPLETED SUCCESSFULLY ✅              {Colors.NC}")
    print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 All results saved in:{Colors.NC} {Colors.YELLOW}{output_dir}{Colors.NC}")
    print(f"{Colors.CYAN}📊 HTML Report:{Colors.NC} {Colors.YELLOW}{html_report}{Colors.NC}")
    print(f"{Colors.CYAN}📋 Summary:{Colors.NC} {Colors.YELLOW}{text_report}{Colors.NC}")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)