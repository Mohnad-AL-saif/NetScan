#!/usr/bin/env python3
"""
MSSQL Enumeration Script - Enhanced Edition with Dual Output
Comprehensive Microsoft SQL Server reconnaissance
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
    print("║          MSSQL Enumeration - Enhanced Edition             ║")
    print("║          Microsoft SQL Server Assessment                   ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Run Nmap MSSQL scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap MSSQL Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running comprehensive Nmap MSSQL scripts...")
    
    scripts = [
        "ms-sql-info", "ms-sql-empty-password", "ms-sql-xp-cmdshell",
        "ms-sql-config", "ms-sql-ntlm-info", "ms-sql-dac",
        "ms-sql-dump-hashes", "ms-sql-query", "ms-sql-tables"
    ]
    
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_mssql_scripts.txt", logger, timeout=300)
    
    logger.log('SUCCESS', "Nmap scripts completed")

def phase2_authentication_test(target, port, outdir, logger):
    """Test MSSQL authentication"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Authentication Testing{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('sqsh') and not check_tool('mssql-cli'):
        logger.log('WARNING', "No MSSQL client found (sqsh/mssql-cli)")
        logger.log('INFO', "Relying on Nmap script results only")
        return None
    
    creds = [
        ('sa', ''),
        ('sa', 'sa'),
        ('sa', 'password'),
        ('sa', 'Password123'),
        ('sa', 'P@ssw0rd'),
        ('admin', 'admin'),
        ('MSSQLSERVER', 'MSSQLSERVER')
    ]
    
    valid_creds = []
    
    for username, password in creds:
        logger.log('INFO', f"Testing: {username}:{password if password else '(empty)'}")
        
        if check_tool('sqsh'):
            if password:
                cmd = f"sqsh -S {target}:{port} -U {username} -P {password} -C 'SELECT @@VERSION' -h -w 300"
            else:
                cmd = f"sqsh -S {target}:{port} -U {username} -C 'SELECT @@VERSION' -h -w 300"
        elif check_tool('mssql-cli'):
            if password:
                cmd = f"mssql-cli -S {target},{port} -U {username} -P {password} -Q 'SELECT @@VERSION'"
            else:
                cmd = f"mssql-cli -S {target},{port} -U {username} -Q 'SELECT @@VERSION'"
        
        success, stdout, _ = run_command(cmd, logger, timeout=10)
        
        if success and stdout:
            logger.log('CRITICAL', f"Valid credentials found: {username}:{password if password else '(empty)'}")
            
            valid_creds.append(f"{username}:{password if password else '(empty)'}")
            
            # Save version info
            save_dual_output(stdout, f"{outdir}/mssql_version.txt", cmd)
            
            # Return first valid credentials
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
    
    if not check_tool('sqsh') and not check_tool('mssql-cli'):
        logger.log('WARNING', "No MSSQL client available")
        return
    
    logger.log('INFO', "Enumerating databases...")
    
    queries = {
        'databases': "SELECT name FROM sys.databases",
        'users': "SELECT name FROM sys.server_principals WHERE type = 'S'",
        'tables': "SELECT table_schema, table_name FROM information_schema.tables",
        'linked_servers': "SELECT name FROM sys.servers WHERE is_linked = 1"
    }
    
    for query_name, query in queries.items():
        logger.log('INFO', f"Running query: {query_name}")
        
        if check_tool('sqsh'):
            cmd = f"sqsh -S {target}:{port} -U {username} -P {password} -C \"{query}\" -h -w 300"
        elif check_tool('mssql-cli'):
            cmd = f"mssql-cli -S {target},{port} -U {username} -P {password} -Q \"{query}\""
        
        run_and_save(cmd, f"{outdir}/{query_name}.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Database enumeration completed")

def phase4_privilege_check(target, port, username, password, outdir, logger):
    """Check privileges and security"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Privilege & Security Check{Colors.NC}")
    print("=" * 60)
    
    if not username:
        logger.log('WARNING', "Skipping privilege check (no valid credentials)")
        return
    
    if not check_tool('sqsh') and not check_tool('mssql-cli'):
        logger.log('WARNING', "No MSSQL client available")
        return
    
    logger.log('INFO', "Checking user privileges...")
    
    # Check xp_cmdshell
    logger.log('INFO', "Checking xp_cmdshell status...")
    query = "SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'"
    
    if check_tool('sqsh'):
        cmd = f"sqsh -S {target}:{port} -U {username} -P {password} -C \"{query}\" -h -w 300"
    elif check_tool('mssql-cli'):
        cmd = f"mssql-cli -S {target},{port} -U {username} -P {password} -Q \"{query}\""
    
    run_and_save(cmd, f"{outdir}/xp_cmdshell_status.txt", logger, timeout=10)
    
    # Check sysadmin role
    logger.log('INFO', "Checking server roles...")
    query = "SELECT IS_SRVROLEMEMBER('sysadmin')"
    
    if check_tool('sqsh'):
        cmd = f"sqsh -S {target}:{port} -U {username} -P {password} -C \"{query}\" -h -w 300"
    elif check_tool('mssql-cli'):
        cmd = f"mssql-cli -S {target},{port} -U {username} -P {password} -Q \"{query}\""
    
    run_and_save(cmd, f"{outdir}/is_sysadmin.txt", logger, timeout=10)

def phase5_impacket_tools(target, port, outdir, logger):
    """Use Impacket tools if available"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Impacket Tools (if available){Colors.NC}")
    print("=" * 60)
    
    tools_info = ""
    
    if check_tool('mssqlclient.py'):
        logger.log('INFO', "mssqlclient.py available for manual testing")
        tools_info += "✓ mssqlclient.py is available\n"
    else:
        tools_info += "✗ mssqlclient.py not found\n"
    
    impacket_tools = ['mssqlclient.py', 'samrdump.py']
    
    for tool in impacket_tools:
        if check_tool(tool):
            logger.log('INFO', f"✓ {tool} is available")
        else:
            logger.log('INFO', f"✗ {tool} not found")
    
    save_dual_output(tools_info, f"{outdir}/impacket_tools.txt", "Impacket Tools Availability Check")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
MSSQL Enumeration Summary - {target}:{port}
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
    
    # Check xp_cmdshell
    xp_file = plain_dir / "xp_cmdshell_status.txt"
    if xp_file.exists():
        summary_text += f"""⚙️ xp_cmdshell Status:
{'-' * 70}
"""
        with open(xp_file) as f:
            content = f.read()
            if 'config_value     1' in content or 'run_value     1' in content:
                summary_text += "⚠️  xp_cmdshell is ENABLED!\n\n"
            else:
                summary_text += "✓ xp_cmdshell is disabled\n\n"
    
    summary_text += f"""Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'sqsh', 'mssql-cli', 'mssqlclient.py']
    for tool in tools:
        status = "✓ Available" if check_tool(tool) else "✗ Not found"
        summary_text += f"  {tool:20} {status}\n"
    
    summary_text += f"""
{'=' * 70}
Recommendations:
{'-' * 70}
  1. Disable xp_cmdshell if not needed
  2. Use strong passwords (min 12 characters)
  3. Disable sa account if not needed
  4. Enable SSL/TLS encryption
  5. Implement proper firewall rules
  6. Regular security updates
"""
    
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
    logger = Logger(f"{outdir}/mssql_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    creds = phase2_authentication_test(target, port, outdir, logger)
    
    if creds:
        username, password = creds
        phase3_database_enumeration(target, port, username, password, outdir, logger)
        phase4_privilege_check(target, port, username, password, outdir, logger)
    
    phase5_impacket_tools(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ MSSQL Enumeration Completed ✅{Colors.NC}")
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