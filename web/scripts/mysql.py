#!/usr/bin/env python3
"""
MySQL Enumeration Script - Enhanced Edition with Dual Output
Comprehensive MySQL/MariaDB reconnaissance
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
    PURPLE = '\033[0;35m'
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
            'WARNING': f'{Colors.YELLOW}[!]{Colors.NC}',
            'CRITICAL': f'{Colors.RED}[!!!]{Colors.NC}'
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
    print(f"{Colors.PURPLE}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          MySQL/MariaDB Enumeration - Enhanced             ║")
    print("║          Database Security Assessment                      ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Run Nmap MySQL scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap MySQL Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running comprehensive Nmap MySQL scripts...")
    
    scripts = [
        "mysql-audit", "mysql-databases", "mysql-dump-hashes",
        "mysql-empty-password", "mysql-enum", "mysql-info",
        "mysql-query", "mysql-users", "mysql-variables",
        "mysql-vuln-cve2012-2122"
    ]
    
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_mysql_scripts.txt", logger, timeout=180)
    
    logger.log('SUCCESS', "Nmap scripts completed")

def phase2_authentication_test(target, port, outdir, logger):
    """Test MySQL authentication"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Authentication Testing{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('mysql'):
        logger.log('WARNING', "MySQL client not found")
        return False
    
    creds = [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('admin', ''),
        ('admin', 'admin'),
        ('mysql', 'mysql'),
        ('test', 'test')
    ]
    
    valid_creds = []
    
    for username, password in creds:
        logger.log('INFO', f"Testing: {username}:{password if password else '(empty)'}")
        
        if password:
            cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SELECT VERSION();' 2>/dev/null"
        else:
            cmd = f"mysql -h {target} -P {port} -u {username} -e 'SELECT VERSION();' 2>/dev/null"
        
        success, stdout, _ = run_command(cmd, logger, timeout=10)
        
        if success and stdout:
            logger.log('CRITICAL', f"Valid credentials found: {username}:{password if password else '(empty)'}")
            
            valid_creds.append(f"{username}:{password if password else '(empty)'}")
            
            # Save version
            save_dual_output(stdout, f"{outdir}/mysql_version.txt", cmd)
            
            # Return first valid
            return (username, password)
    
    if valid_creds:
        creds_text = "\n".join(valid_creds)
        save_dual_output(creds_text, f"{outdir}/valid_credentials.txt", "Authentication Test Results")
    
    logger.log('INFO', "No valid credentials found with common passwords")
    return None

def phase3_database_enumeration(target, port, username, password, outdir, logger):
    """Enumerate databases"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Database Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not username:
        logger.log('WARNING', "Skipping database enumeration (no valid credentials)")
        return
    
    logger.log('INFO', "Enumerating databases...")
    
    # List databases
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SHOW DATABASES;'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SHOW DATABASES;'"
    
    run_and_save(cmd, f"{outdir}/databases.txt", logger, timeout=30)
    
    # List users
    logger.log('INFO', "Enumerating users...")
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SELECT User, Host FROM mysql.user;'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SELECT User, Host FROM mysql.user;'"
    
    run_and_save(cmd, f"{outdir}/users.txt", logger, timeout=30)
    
    # Get privileges
    logger.log('INFO', "Checking privileges...")
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SHOW GRANTS;'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SHOW GRANTS;'"
    
    run_and_save(cmd, f"{outdir}/privileges.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Database enumeration completed")

def phase4_version_detection(target, port, username, password, outdir, logger):
    """Detect MySQL version and configuration"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Version & Configuration{Colors.NC}")
    print("=" * 60)
    
    if not username:
        logger.log('WARNING', "Skipping version detection (no valid credentials)")
        return
    
    logger.log('INFO', "Detecting version and configuration...")
    
    # Version
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SELECT VERSION();'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SELECT VERSION();'"
    
    run_and_save(cmd, f"{outdir}/version_detailed.txt", logger, timeout=10)
    
    # Variables
    logger.log('INFO', "Extracting system variables...")
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SHOW VARIABLES;'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SHOW VARIABLES;'"
    
    run_and_save(cmd, f"{outdir}/variables.txt", logger, timeout=30)
    
    # Status
    logger.log('INFO', "Getting server status...")
    if password:
        cmd = f"mysql -h {target} -P {port} -u {username} -p{password} -e 'SHOW STATUS;'"
    else:
        cmd = f"mysql -h {target} -P {port} -u {username} -e 'SHOW STATUS;'"
    
    run_and_save(cmd, f"{outdir}/status.txt", logger, timeout=30)

def phase5_security_check(target, port, outdir, logger):
    """Security configuration check"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Security Check{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking for security issues...")
    
    security_issues = []
    
    # Check credentials file
    plain_dir = Path(outdir) / "results" / "plain_text"
    creds_file = plain_dir / "valid_credentials.txt"
    
    if creds_file.exists():
        with open(creds_file) as f:
            content = f.read()
            if "OUTPUT:" in content:
                output = content.split("OUTPUT:")[1].strip()
                for line in output.split('\n'):
                    if ':' in line and (line.strip().endswith(':(empty)') or line.strip().endswith(':')):
                        security_issues.append(f"Empty password detected: {line.strip()}")
                        logger.log('CRITICAL', f"Empty password: {line.strip()}")
    
    # Check for root remote access
    users_file = plain_dir / "users.txt"
    if users_file.exists():
        with open(users_file) as f:
            content = f.read()
            if 'root' in content.lower() and '%' in content:
                security_issues.append("Root user can connect remotely")
                logger.log('WARNING', "Root user has remote access enabled")
    
    security_text = f"""MySQL Security Assessment
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
  1. Use strong passwords for all accounts
  2. Disable remote root access
  3. Remove unused accounts
  4. Enable SSL/TLS encryption
  5. Implement proper firewall rules
  6. Keep MySQL updated to latest version
"""
    
    save_dual_output(security_text, f"{outdir}/security_report.txt", "Security Assessment")
    
    if security_issues:
        logger.log('WARNING', f"Found {len(security_issues)} security issue(s)")
    else:
        logger.log('SUCCESS', "No obvious security issues")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
MySQL Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

"""
    
    # Check credentials
    plain_dir = Path(outdir) / "results" / "plain_text"
    creds_file = plain_dir / "valid_credentials.txt"
    
    if creds_file.exists():
        summary_text += f"""🔑 Valid Credentials:
{'-' * 70}
"""
        with open(creds_file) as f:
            content = f.read()
            if "OUTPUT:" in content:
                output = content.split("OUTPUT:")[1].strip()
                summary_text += output[:200] + "\n\n"
    
    # Check databases
    db_file = plain_dir / "databases.txt"
    if db_file.exists():
        summary_text += f"""📊 Databases:
{'-' * 70}
"""
        with open(db_file) as f:
            content = f.read()
            if "OUTPUT:" in content:
                output = content.split("OUTPUT:")[1].strip()
                db_count = len([l for l in output.split('\n') if l.strip() and 'Database' not in l])
                summary_text += f"Found {db_count} database(s)\n\n"
    
    summary_text += f"""Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'mysql']
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
    logger = Logger(f"{outdir}/mysql_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    creds = phase2_authentication_test(target, port, outdir, logger)
    
    if creds:
        username, password = creds
        phase3_database_enumeration(target, port, username, password, outdir, logger)
        phase4_version_detection(target, port, username, password, outdir, logger)
    
    phase5_security_check(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ MySQL Enumeration Completed ✅{Colors.NC}")
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