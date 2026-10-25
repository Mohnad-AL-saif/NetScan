#!/usr/bin/env python3
"""
MongoDB Enumeration Script - Enhanced Edition with Dual Output
Comprehensive MongoDB/NoSQL reconnaissance
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
    print("║          MongoDB Enumeration - Enhanced Edition           ║")
    print("║          NoSQL Database Security Assessment                ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Run Nmap MongoDB scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap MongoDB Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running comprehensive Nmap MongoDB scripts...")
    
    scripts = ["mongodb-info", "mongodb-databases", "mongodb-brute"]
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_mongodb_scripts.txt", logger, timeout=180)
    
    logger.log('SUCCESS', "Nmap scripts completed")

def phase2_anonymous_access(target, port, outdir, logger):
    """Test for anonymous access"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Anonymous Access Test{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('mongo') and not check_tool('mongosh'):
        logger.log('WARNING', "No MongoDB client found (mongo/mongosh)")
        return False
    
    logger.log('INFO', "Testing anonymous access...")
    
    mongo_cmd = 'mongosh' if check_tool('mongosh') else 'mongo'
    cmd = f"{mongo_cmd} --host {target}:{port} --eval 'db.version()' --quiet"
    
    success, stdout, _ = run_and_save(cmd, f"{outdir}/version_check.txt", logger, timeout=10)
    
    if success and stdout:
        logger.log('CRITICAL', "Anonymous access is ENABLED!")
        
        access_info = f"✓ Anonymous access successful\nVersion: {stdout}"
        save_dual_output(access_info, f"{outdir}/anonymous_access.txt", "Anonymous Access Test Result")
        
        return True
    else:
        logger.log('INFO', "Anonymous access is disabled")
        return False

def phase3_database_enumeration(target, port, outdir, logger, has_access):
    """Enumerate databases"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Database Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping database enumeration (no access)")
        return
    
    mongo_cmd = 'mongosh' if check_tool('mongosh') else 'mongo'
    
    logger.log('INFO', "Listing databases...")
    cmd = f"{mongo_cmd} --host {target}:{port} --eval 'db.adminCommand({{listDatabases: 1}})' --quiet"
    run_and_save(cmd, f"{outdir}/databases.txt", logger, timeout=30)
    
    logger.log('INFO', "Getting server information...")
    cmd = f"{mongo_cmd} --host {target}:{port} --eval 'db.serverStatus()' --quiet"
    run_and_save(cmd, f"{outdir}/server_status.txt", logger, timeout=30)
    
    logger.log('INFO', "Getting build information...")
    cmd = f"{mongo_cmd} --host {target}:{port} --eval 'db.serverBuildInfo()' --quiet"
    run_and_save(cmd, f"{outdir}/build_info.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Database enumeration completed")

def phase4_collection_enumeration(target, port, outdir, logger, has_access):
    """Enumerate collections"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Collection Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping collection enumeration (no access)")
        return
    
    mongo_cmd = 'mongosh' if check_tool('mongosh') else 'mongo'
    
    common_dbs = ['admin', 'test', 'local', 'config', 'users', 'data']
    
    for db_name in common_dbs:
        logger.log('INFO', f"Checking database: {db_name}")
        
        cmd = f"{mongo_cmd} --host {target}:{port} {db_name} --eval 'db.getCollectionNames()' --quiet"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/collections_{db_name}.txt", 
                                         logger, timeout=10)
        
        if success and stdout.strip():
            logger.log('SUCCESS', f"Found collections in {db_name}")

def phase5_user_enumeration(target, port, outdir, logger, has_access):
    """Enumerate users"""
    print()
    print(f"{Colors.CYAN}[Phase 5] User Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping user enumeration (no access)")
        return
    
    mongo_cmd = 'mongosh' if check_tool('mongosh') else 'mongo'
    
    logger.log('INFO', "Enumerating users...")
    cmd = f"{mongo_cmd} --host {target}:{port} admin --eval 'db.system.users.find()' --quiet"
    run_and_save(cmd, f"{outdir}/users.txt", logger, timeout=30)
    
    logger.log('INFO', "Enumerating roles...")
    cmd = f"{mongo_cmd} --host {target}:{port} admin --eval 'db.system.roles.find()' --quiet"
    run_and_save(cmd, f"{outdir}/roles.txt", logger, timeout=30)

def phase6_security_check(target, port, outdir, logger, has_access):
    """Security configuration check"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Security Check{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking security configuration...")
    
    security_issues = []
    
    if has_access:
        security_issues.append("Anonymous access is enabled")
        logger.log('CRITICAL', "Anonymous access is a security risk!")
    
    # Check if user info is accessible
    plain_users = Path(outdir) / "results" / "plain_text" / "users.txt"
    if plain_users.exists():
        with open(plain_users) as f:
            content = f.read()
            if content.strip() and "No output" not in content:
                security_issues.append("User information accessible")
    
    security_text = f"""MongoDB Security Assessment
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
  1. Enable authentication (--auth)
  2. Create admin user with strong password
  3. Bind to localhost only if not needed externally
  4. Enable TLS/SSL encryption
  5. Implement IP whitelisting
  6. Keep MongoDB updated
  7. Disable HTTP status interface
  8. Enable authorization
"""
    
    save_dual_output(security_text, f"{outdir}/security_report.txt", "Security Assessment")
    
    if security_issues:
        logger.log('WARNING', f"Found {len(security_issues)} security issue(s)")
    else:
        logger.log('SUCCESS', "No obvious security issues")

def generate_summary(target, port, outdir, logger, has_access):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
MongoDB Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🔐 Access Status:
{'-' * 70}
"""
    
    if has_access:
        summary_text += "⚠️  Anonymous access is ENABLED\n"
    else:
        summary_text += "✓ Authentication required\n"
    summary_text += "\n"
    
    # Check version
    plain_dir = Path(outdir) / "results" / "plain_text"
    version_file = plain_dir / "version_check.txt"
    if version_file.exists():
        summary_text += f"""📌 Version:
{'-' * 70}
"""
        with open(version_file) as f:
            content = f.read()
            # Extract just the output part
            if "OUTPUT:" in content:
                output_part = content.split("OUTPUT:")[1].strip()
                summary_text += output_part[:200] + "\n\n"
    
    # Count collection files
    collection_files = list(plain_dir.glob("collections_*.txt")) if plain_dir.exists() else []
    if collection_files:
        summary_text += f"""📊 Databases with Collections:
{'-' * 70}
Found {len(collection_files)} database(s) with collections
"""
    
    summary_text += f"""
Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'mongo', 'mongosh']
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
    logger = Logger(f"{outdir}/mongodb_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    has_access = phase2_anonymous_access(target, port, outdir, logger)
    phase3_database_enumeration(target, port, outdir, logger, has_access)
    phase4_collection_enumeration(target, port, outdir, logger, has_access)
    phase5_user_enumeration(target, port, outdir, logger, has_access)
    phase6_security_check(target, port, outdir, logger, has_access)
    
    # Generate summary
    generate_summary(target, port, outdir, logger, has_access)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ MongoDB Enumeration Completed ✅{Colors.NC}")
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