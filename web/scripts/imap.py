#!/usr/bin/env python3
"""
IMAP Enumeration Script - Enhanced Edition with Dual Output
Comprehensive IMAP/Email reconnaissance
كل أمر يُحفظ في رأس الملف - نسختان: ملون وعادي
"""

import sys
import subprocess
import shutil
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
    حفظ النتائج في نسختين مع الأمر في الأعلى:
    1. results/colors/ - ملون
    2. results/plain_text/ - عادي
    """
    path = Path(base_path)
    parent = path.parent
    filename = path.name
    
    colors_dir = parent / "results" / "colors"
    plain_dir = parent / "results" / "plain_text"
    
    colors_dir.mkdir(parents=True, exist_ok=True)
    plain_dir.mkdir(parents=True, exist_ok=True)
    
    # ═══ PLAIN VERSION (عادي) ═══
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
    
    # ═══ COLORED VERSION (ملون) ═══
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
    
    print(f"\n{'=' * 60}")
    print(f"{Colors.RED}{cmd}{Colors.NC}")
    print(f"{'=' * 60}\n")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=timeout)
        
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
    """تنفيذ الأمر وحفظه تلقائياً في مجلدين"""
    success, stdout, stderr = run_command(cmd, logger, description, timeout)
    if outfile:
        save_dual_output(stdout if stdout else stderr, outfile, cmd)
    return success, stdout, stderr

def check_tool(tool):
    return shutil.which(tool) is not None

def banner():
    print(f"{Colors.CYAN}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          IMAP Enumeration - Advanced Edition              ║")
    print("║          Email Server Reconnaissance                       ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_banner_grab(target, port, outdir, logger):
    """Grab IMAP banner"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Banner Grabbing{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Grabbing IMAP banner...")
    
    cmd = f"echo 'a001 CAPABILITY' | nc -w 3 {target} {port}"
    success, stdout, _ = run_and_save(cmd, f"{outdir}/banner.txt", logger, timeout=10)
    
    server_type = "Unknown"
    if success and stdout:
        logger.log('SUCCESS', f"Banner: {stdout[:100]}...")
        
        if "Dovecot" in stdout:
            server_type = "Dovecot"
        elif "Courier" in stdout:
            server_type = "Courier"
        elif "Exchange" in stdout or "Microsoft" in stdout:
            server_type = "Microsoft Exchange"
        elif "Cyrus" in stdout:
            server_type = "Cyrus"
        
        logger.log('INFO', f"Detected server: {server_type}")
    
    return server_type

def phase2_capabilities(target, port, outdir, logger):
    """Enumerate IMAP capabilities"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Capability Enumeration{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Enumerating IMAP capabilities...")
    
    cmd = f"echo 'a001 CAPABILITY' | nc -w 3 {target} {port}"
    success, stdout, _ = run_and_save(cmd, f"{outdir}/capabilities.txt", logger, timeout=10)
    
    if success and stdout:
        if "CAPABILITY" in stdout:
            logger.log('SUCCESS', "Capabilities retrieved")
            
            interesting_caps = ['AUTH=PLAIN', 'STARTTLS', 'LOGINDISABLED', 'IDLE']
            for cap in interesting_caps:
                if cap in stdout:
                    logger.log('INFO', f"Found capability: {cap}")
        
        return stdout
    
    return None

def phase3_ssl_check(target, port, outdir, logger):
    """Check SSL/TLS support"""
    print()
    print(f"{Colors.CYAN}[Phase 3] SSL/TLS Analysis{Colors.NC}")
    print("=" * 60)
    
    if port == '993':
        logger.log('INFO', "Port 993 detected - IMAPS (SSL/TLS)")
        
        if check_tool('openssl'):
            logger.log('INFO', "Testing SSL connection...")
            cmd = f"echo 'a001 CAPABILITY' | openssl s_client -connect {target}:{port} -quiet 2>&1"
            run_and_save(cmd, f"{outdir}/ssl_connection.txt", logger, timeout=10)
            logger.log('SUCCESS', "SSL connection test completed")
    else:
        logger.log('INFO', "Standard IMAP port - checking STARTTLS support...")
        cmd = f"echo -e 'a001 CAPABILITY\\na002 STARTTLS' | nc -w 3 {target} {port}"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/starttls_test.txt", logger, timeout=10)
        
        if success and "STARTTLS" in stdout:
            logger.log('SUCCESS', "STARTTLS is supported")
        else:
            logger.log('WARNING', "STARTTLS may not be supported")

def phase4_nmap_scripts(target, port, outdir, logger):
    """Run Nmap IMAP scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Nmap IMAP Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap IMAP scripts...")
    
    scripts = ["imap-capabilities", "imap-ntlm-info"]
    if port == '993':
        scripts.append("ssl-enum-ciphers")
    
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_imap_scripts.txt", logger, timeout=180)
    
    logger.log('SUCCESS', "Nmap IMAP scripts completed")

def phase5_user_enumeration(target, port, outdir, logger):
    """User enumeration attempts"""
    print()
    print(f"{Colors.CYAN}[Phase 5] User Enumeration{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Attempting user enumeration...")
    
    common_users = ['admin', 'administrator', 'root', 'test', 'user', 'info', 'support', 'sales']
    
    found_users = []
    
    for username in common_users:
        cmd = f"echo 'a001 LOGIN {username} invalid_password' | nc -w 2 {target} {port}"
        success, stdout, _ = run_command(cmd, logger, timeout=5)
        
        if success and stdout:
            if "NO" in stdout or "BAD" in stdout:
                if "invalid" not in stdout.lower():
                    found_users.append(username)
    
    if found_users:
        logger.log('WARNING', f"Potential users: {', '.join(found_users)}")
        users_text = "\n".join(found_users)
        save_dual_output(users_text, f"{outdir}/potential_users.txt", "User Enumeration Test")
    else:
        logger.log('INFO', "No obvious user enumeration vectors found")

def phase6_brute_force_warning(target, port, outdir, logger):
    """Brute force capabilities (info only)"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Brute Force Information{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Brute force attack information:")
    print()
    print(f"{Colors.YELLOW}Note: Brute force attacks are not performed by this script.{Colors.NC}")
    print(f"{Colors.YELLOW}If you have credentials to test, consider using:{Colors.NC}")
    print()
    print(f"  hydra -l <username> -P <wordlist> imap://{target}:{port}")
    print(f"  nmap -p {port} --script imap-brute {target}")
    print()
    
    info_text = f"""Brute Force Attack Commands
{'=' * 60}

Hydra:
  hydra -l <username> -P <wordlist> imap://{target}:{port}

Nmap:
  nmap -p {port} --script imap-brute --script-args userdb=users.txt,passdb=pass.txt {target}
"""
    
    save_dual_output(info_text, f"{outdir}/brute_force_info.txt", "Brute Force Information")

def phase7_security_check(target, port, capabilities, outdir, logger):
    """Security configuration check"""
    print()
    print(f"{Colors.CYAN}[Phase 7] Security Configuration Check{Colors.NC}")
    print("=" * 60)
    
    security_issues = []
    
    if capabilities and "AUTH=PLAIN" in capabilities:
        if port != '993':
            logger.log('WARNING', "Plain text authentication enabled on non-SSL port!")
            security_issues.append("Plain text auth on unencrypted connection")
    
    if capabilities and "LOGINDISABLED" in capabilities:
        logger.log('INFO', "LOGIN command is disabled (good security practice)")
    else:
        if port != '993':
            logger.log('WARNING', "LOGIN command may be enabled on unencrypted port")
            security_issues.append("LOGIN enabled on unencrypted connection")
    
    security_text = f"""IMAP Security Check
{'=' * 60}

"""
    
    if security_issues:
        security_text += "⚠️  Security Issues Found:\n"
        for issue in security_issues:
            security_text += f"  - {issue}\n"
    else:
        security_text += "✓ No obvious security issues detected\n"
    
    security_text += f"""
{'=' * 60}
Recommendations:
  1. Use IMAPS (port 993) instead of IMAP
  2. Disable plain text authentication
  3. Implement rate limiting
  4. Use strong passwords
  5. Enable TLS/SSL encryption
"""
    
    save_dual_output(security_text, f"{outdir}/security_check.txt", "Security Configuration Assessment")
    
    if security_issues:
        logger.log('WARNING', f"Found {len(security_issues)} security issue(s)")
    else:
        logger.log('SUCCESS', "No obvious security issues")

def generate_summary(target, port, server_type, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
IMAP Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

Server Information:
{'-' * 70}
  Server Type: {server_type}
  Port: {port} ({'IMAPS (SSL)' if port == '993' else 'IMAP'})

Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

Key Findings:
{'-' * 70}
"""
    
    # Check files
    colors_dir = Path(outdir) / "results" / "colors"
    if colors_dir.exists():
        if (colors_dir / "capabilities.txt").exists():
            summary_text += "  ✓ Capabilities enumerated\n"
        
        if (colors_dir / "potential_users.txt").exists():
            summary_text += "  ⚠️  Potential users identified\n"
        
        if (colors_dir / "security_check.txt").exists():
            summary_text += "  ⚠️  Security issues may exist\n"
    
    summary_text += f"""
{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nc', 'nmap', 'openssl']
    for tool in tools:
        status = "✓ Available" if check_tool(tool) else "✗ Not found"
        summary_text += f"  {tool:20} {status}\n"
    
    save_dual_output(summary_text, f"{outdir}/SUMMARY.txt", "Summary Report Generation")
    
    logger.log('SUCCESS', "Summary saved")
    print()
    print(summary_text)

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <IP> <PORT> <PROTO> <OUTDIR>")
        sys.exit(1)
    
    target, port, proto, outdir = sys.argv[1:]
    
    Path(outdir).mkdir(parents=True, exist_ok=True)
    logger = Logger(f"{outdir}/imap_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    server_type = phase1_banner_grab(target, port, outdir, logger)
    capabilities = phase2_capabilities(target, port, outdir, logger)
    phase3_ssl_check(target, port, outdir, logger)
    phase4_nmap_scripts(target, port, outdir, logger)
    phase5_user_enumeration(target, port, outdir, logger)
    phase6_brute_force_warning(target, port, outdir, logger)
    phase7_security_check(target, port, capabilities, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, server_type, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ IMAP Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.CYAN}💡 Each file contains the command at the top!{Colors.NC}")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)