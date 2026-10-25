#!/usr/bin/env python3
"""
Generic Service Enumeration Script - Enhanced Edition with Dual Output
Universal service reconnaissance for unknown/uncommon services
"""

import sys
import subprocess
import shutil
import socket
from pathlib import Path
from datetime import datetime

# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

class Logger:
    def __init__(self, log_file):
        self.log_file = log_file
        
    def log(self, level, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        colors = {
            'INFO': f'{Colors.CYAN}[*]{Colors.NC}',
            'SUCCESS': f'{Colors.GREEN}[✓]{Colors.NC}',
            'ERROR': f'{Colors.RED}[✗]{Colors.NC}',
            'WARNING': f'{Colors.YELLOW}[!]{Colors.NC}'
        }
        print(f"{colors.get(level, '')} {message}")
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")

def save_dual_output(content, base_path, cmd):
    """
    Save output in two versions with command at top:
    1. results/colors/ - with ANSI colors (ملون)
    2. results/plain_text/ - without colors (عادي)
    """
    path = Path(base_path)
    parent = path.parent
    filename = path.name
    
    # Create directories
    colors_dir = parent / "results" / "colors"
    plain_dir = parent / "results" / "plain_text"
    
    colors_dir.mkdir(parents=True, exist_ok=True)
    plain_dir.mkdir(parents=True, exist_ok=True)
    
    # Save PLAIN version (عادي)
    with open(plain_dir / filename, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("COMMAND:\n")
        f.write("=" * 70 + "\n")
        f.write(f"{cmd}\n")
        f.write("=" * 70 + "\n\n")
        f.write("OUTPUT:\n")
        f.write("=" * 70 + "\n")
        f.write(content if content else "[No output]")
        f.write("\n")
    
    # Save COLORED version (ملون)
    with open(colors_dir / filename, 'w', encoding='utf-8') as f:
        f.write(f"\033[0;31m{'=' * 70}\033[0m\n")
        f.write(f"\033[0;31mCOMMAND:\033[0m\n")
        f.write(f"\033[0;31m{'=' * 70}\033[0m\n")
        f.write(f"\033[0;31m{cmd}\033[0m\n")
        f.write(f"\033[0;31m{'=' * 70}\033[0m\n\n")
        f.write(f"\033[0;33mOUTPUT:\033[0m\n")
        f.write(f"\033[0;32m{'=' * 70}\033[0m\n")
        f.write(f"\033[0;32m{content if content else '[No output]'}\033[0m")
        f.write("\n")

def run_command(cmd, logger, description=None, timeout=120):
    if description:
        logger.log('INFO', description)
    
    # Print command in red
    print(f"\n{'=' * 60}")
    print(f"{Colors.RED}{cmd}{Colors.NC}")
    print(f"{'=' * 60}\n")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=timeout)
        
        # Print output in green
        if result.stdout:
            print(f"{Colors.GREEN}{result.stdout}{Colors.NC}")
        
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.log('WARNING', f"Timeout: {cmd}")
        return False, "", "Timeout"
    except Exception as e:
        logger.log('ERROR', f"Failed: {str(e)}")
        return False, "", str(e)

def run_and_save(cmd, outfile, logger, description=None, timeout=120):
    """Run command and save output to dual locations with command at top"""
    success, stdout, stderr = run_command(cmd, logger, description, timeout)
    if outfile:
        save_dual_output(stdout if stdout else stderr, outfile, cmd)
    return success, stdout, stderr

def check_tool(tool):
    return shutil.which(tool) is not None

def banner():
    print(f"{Colors.CYAN}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          Generic Service Enumeration                      ║")
    print("║          Universal Service Reconnaissance                  ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_banner_grab(target, port, proto, outdir, logger):
    """Grab service banner"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Banner Grabbing{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', f"Attempting banner grab on {proto.upper()} port {port}...")
    
    banners = []
    
    # Method 1: netcat
    if check_tool('nc'):
        logger.log('INFO', "Trying with netcat...")
        cmd = f"echo '' | nc -w 3 {target} {port}"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/banner_nc.txt", logger, timeout=5)
        if success and stdout.strip():
            banners.append(('netcat', stdout))
            logger.log('SUCCESS', f"Banner (nc): {stdout[:100]}...")
    
    # Method 2: telnet
    if check_tool('telnet'):
        logger.log('INFO', "Trying with telnet...")
        cmd = f"(sleep 2; echo '') | telnet {target} {port} 2>&1"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/banner_telnet.txt", logger, timeout=10)
        if success and stdout:
            banners.append(('telnet', stdout))
    
    # Method 3: Python socket
    logger.log('INFO', "Trying with Python socket...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target, int(port)))
        
        try:
            sock.send(b'\r\n')
        except:
            pass
        
        try:
            banner_data = sock.recv(4096).decode('utf-8', errors='ignore')
            if banner_data:
                banners.append(('socket', banner_data))
                logger.log('SUCCESS', f"Banner (socket): {banner_data[:100]}...")
                # Save socket banner with dual output
                save_dual_output(banner_data, f"{outdir}/banner_socket.txt", "Python Socket Connection")
        except:
            pass
        
        sock.close()
    except Exception as e:
        logger.log('INFO', f"Socket connection failed: {str(e)}")
    
    # Save summary of all banners
    if banners:
        summary = ""
        for method, banner_text in banners:
            summary += f"=== {method.upper()} ===\n{banner_text}\n\n"
        save_dual_output(summary, f"{outdir}/banners_summary.txt", "All Banner Grabbing Methods")
        return banners[0][1]
    else:
        logger.log('WARNING', "No banner received")
        return None

def phase2_nmap_scan(target, port, proto, outdir, logger):
    """Comprehensive Nmap scan"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Nmap Service Scan{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap service detection...")
    proto_flag = "-sU" if proto.lower() == "udp" else "-sT"
    cmd = f"nmap {proto_flag} -p {port} -sV -sC --version-all --script=banner,default {target}"
    run_and_save(cmd, f"{outdir}/nmap_service.txt", logger, timeout=300)
    logger.log('SUCCESS', "Nmap scan completed")
    
    logger.log('INFO', "Running all available Nmap scripts...")
    cmd = f"nmap {proto_flag} -p {port} --script=default,discovery,safe {target}"
    run_and_save(cmd, f"{outdir}/nmap_all_scripts.txt", logger, timeout=600)
    logger.log('SUCCESS', "Extended Nmap scan completed")

def phase3_version_detection(banner, outdir, logger):
    """Detect service version from banner"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Service Version Detection{Colors.NC}")
    print("=" * 60)
    
    if not banner:
        logger.log('WARNING', "No banner to analyze")
        return []
    
    logger.log('INFO', "Analyzing banner for service identification...")
    
    patterns = {
        'SSH': ['SSH-', 'OpenSSH'],
        'FTP': ['220', 'FTP', 'vsftpd', 'ProFTPD'],
        'HTTP': ['HTTP/', 'Apache', 'nginx', 'IIS'],
        'SMTP': ['220', 'ESMTP', 'Postfix', 'Exim'],
        'POP3': ['+OK', 'POP3'],
        'IMAP': ['OK', 'IMAP'],
        'MySQL': ['mysql', 'MariaDB'],
        'PostgreSQL': ['PostgreSQL'],
        'Redis': ['Redis'],
        'MongoDB': ['MongoDB'],
        'Telnet': ['Telnet'],
        'VNC': ['RFB'],
        'RDP': ['Terminal'],
        'SMB': ['SMB', 'Samba']
    }
    
    detected_services = []
    
    for service, keywords in patterns.items():
        for keyword in keywords:
            if keyword.lower() in banner.lower():
                detected_services.append(service)
                logger.log('SUCCESS', f"Detected: {service}")
                break
    
    # Save detection results with dual output
    detection_text = "Service Detection Results\n"
    detection_text += "=" * 60 + "\n\n"
    
    if detected_services:
        detection_text += "Detected Services:\n"
        for service in detected_services:
            detection_text += f"  - {service}\n"
    else:
        detection_text += "No known service patterns detected\n"
    
    detection_text += "\n" + "=" * 60 + "\n"
    detection_text += "Raw Banner:\n"
    detection_text += "-" * 60 + "\n"
    detection_text += banner
    
    save_dual_output(detection_text, f"{outdir}/service_detection.txt", "Service Pattern Analysis")
    
    return detected_services

def phase4_exploit_search(detected_services, outdir, logger):
    """Search for potential exploits"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Exploit Search{Colors.NC}")
    print("=" * 60)
    
    if not detected_services:
        logger.log('INFO', "No services detected - skipping exploit search")
        return
    
    if check_tool('searchsploit'):
        logger.log('INFO', "Searching exploits with searchsploit...")
        
        all_results = []
        
        for service in detected_services:
            logger.log('INFO', f"Searching exploits for: {service}")
            cmd = f"searchsploit {service}"
            success, stdout, _ = run_and_save(cmd, f"{outdir}/exploits_{service}.txt", logger, timeout=30)
            
            if success and stdout:
                all_results.append(f"\n=== {service} ===\n{stdout}\n")
        
        if all_results:
            combined = "Exploit Search Results\n" + "=" * 60 + "\n" + "".join(all_results)
            save_dual_output(combined, f"{outdir}/exploits_all.txt", 
                           f"searchsploit {' '.join(detected_services)}")
            logger.log('SUCCESS', "Exploit search completed")
    else:
        logger.log('INFO', "searchsploit not found")

def phase5_common_vulnerabilities(target, port, outdir, logger):
    """Check for common vulnerabilities"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Common Vulnerability Checks{Colors.NC}")
    print("=" * 60)
    
    checks = []
    
    logger.log('INFO', "Checking for common weak configurations...")
    checks.append("⚠️  Consider testing for default credentials")
    
    logger.log('INFO', "Analyzing encryption status...")
    if port in ['21', '23', '80', '110', '143']:
        checks.append("⚠️  Service typically uses unencrypted communication")
    
    vuln_text = "Common Vulnerability Checks\n"
    vuln_text += "=" * 60 + "\n\n"
    
    for check in checks:
        vuln_text += f"{check}\n"
    
    vuln_text += "\n" + "=" * 60 + "\n"
    vuln_text += "Recommendations:\n"
    vuln_text += "  1. Test for default credentials\n"
    vuln_text += "  2. Check for known CVEs\n"
    vuln_text += "  3. Verify encryption is enabled\n"
    vuln_text += "  4. Test for misconfigurations\n"
    vuln_text += "  5. Look for information disclosure\n"
    
    save_dual_output(vuln_text, f"{outdir}/vulnerability_notes.txt", "Vulnerability Assessment")

def phase6_custom_probes(target, port, outdir, logger):
    """Send custom probes to identify service"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Custom Service Probes{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Sending custom probes...")
    
    probes = [
        ("HTTP GET", "GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"),
        ("HTTP HEAD", "HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"),
        ("HELP", "HELP\r\n"),
        ("OPTIONS", "OPTIONS\r\n"),
        ("QUIT", "QUIT\r\n"),
        ("EXIT", "EXIT\r\n"),
        ("NULL", ""),
    ]
    
    responses = []
    
    for probe_name, probe_data in probes:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, int(port)))
            
            probe_bytes = probe_data.format(target=target).encode()
            sock.send(probe_bytes)
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            if response:
                responses.append((probe_name, response))
                logger.log('INFO', f"{probe_name} probe: Got response")
            
            sock.close()
        except:
            pass
    
    if responses:
        probe_text = "Custom Probe Responses\n"
        probe_text += "=" * 60 + "\n\n"
        
        for probe_name, response in responses:
            probe_text += f"=== {probe_name} ===\n"
            probe_text += response
            probe_text += "\n\n"
        
        save_dual_output(probe_text, f"{outdir}/probe_responses.txt", "Custom Service Probes")
        logger.log('SUCCESS', f"Saved {len(responses)} probe responses")
    else:
        logger.log('INFO', "No responses from probes")

def generate_summary(target, port, proto, detected_services, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = "=" * 70 + "\n"
    summary_text += f"Generic Service Enumeration Summary\n"
    summary_text += f"Target: {target}:{port} ({proto.upper()})\n"
    summary_text += f"Generated: {datetime.now()}\n"
    summary_text += "=" * 70 + "\n\n"
    
    if detected_services:
        summary_text += "Detected Services:\n"
        summary_text += "-" * 70 + "\n"
        for service in detected_services:
            summary_text += f"  ✓ {service}\n"
        summary_text += "\n"
    
    summary_text += "Output Directories:\n"
    summary_text += "-" * 70 + "\n"
    summary_text += f"  results/colors/      ← Colored outputs (cat file | less -R)\n"
    summary_text += f"  results/plain_text/  ← Plain text outputs\n"
    summary_text += "\n"
    
    # List files in both directories
    colors_dir = Path(outdir) / "results" / "colors"
    plain_dir = Path(outdir) / "results" / "plain_text"
    
    if colors_dir.exists():
        summary_text += "Files in results/colors/:\n"
        summary_text += "-" * 70 + "\n"
        for file in sorted(colors_dir.glob("*.txt")):
            size = file.stat().st_size
            summary_text += f"  {file.name:40} ({size:,} bytes)\n"
        summary_text += "\n"
    
    summary_text += "\n" + "=" * 70 + "\n"
    summary_text += "Next Steps:\n"
    summary_text += "-" * 70 + "\n"
    summary_text += "  1. Review banner and probe responses\n"
    summary_text += "  2. Check Nmap scan results for service details\n"
    summary_text += "  3. Search for service-specific enumeration tools\n"
    summary_text += "  4. Test for default credentials\n"
    summary_text += "  5. Look for known vulnerabilities (CVEs)\n"
    
    summary_text += "\n" + "=" * 70 + "\n"
    summary_text += "Tools Used:\n"
    summary_text += "-" * 70 + "\n"
    
    tools = ['nc', 'nmap', 'telnet', 'searchsploit']
    for tool in tools:
        status = "✓ Available" if check_tool(tool) else "✗ Not found"
        summary_text += f"  {tool:20} {status}\n"
    
    save_dual_output(summary_text, f"{outdir}/SUMMARY.txt", "Summary Report Generation")
    
    logger.log('SUCCESS', f"Summary saved")
    print()
    print(summary_text)

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <IP> <PORT> <PROTO> <OUTDIR>")
        sys.exit(1)
    
    target = sys.argv[1]
    port = sys.argv[2]
    proto = sys.argv[3]
    outdir = sys.argv[4]
    
    # Setup
    Path(outdir).mkdir(parents=True, exist_ok=True)
    log_file = f"{outdir}/generic_enum.log"
    logger = Logger(log_file)
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port} ({proto.upper()})")
    logger.log('INFO', f"Output: {outdir}")
    logger.log('WARNING', "No specific service script found - using generic enumeration")
    
    # Execute phases
    banner_data = phase1_banner_grab(target, port, proto, outdir, logger)
    phase2_nmap_scan(target, port, proto, outdir, logger)
    detected_services = phase3_version_detection(banner_data, outdir, logger) if banner_data else []
    phase4_exploit_search(detected_services, outdir, logger)
    phase5_common_vulnerabilities(target, port, outdir, logger)
    phase6_custom_probes(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, proto, detected_services, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ Generic Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print(f"{Colors.CYAN}📋 Summary: {outdir}/SUMMARY.txt{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.CYAN}💡 Each file contains the command at the top!{Colors.NC}")
    if detected_services:
        print(f"{Colors.YELLOW}💡 Tip: Search for '{detected_services[0]} enumeration' for specific tools{Colors.NC}")
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