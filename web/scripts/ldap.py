#!/usr/bin/env python3
"""
LDAP Enumeration Script - Enhanced Edition with Dual Output
Comprehensive LDAP/Active Directory reconnaissance
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
    print("║          LDAP Enumeration - Advanced Edition              ║")
    print("║          Active Directory Reconnaissance                   ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_anonymous_bind(target, port, outdir, logger):
    """Test anonymous LDAP bind"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Anonymous Bind Test{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Testing anonymous bind...")
    
    if check_tool('ldapsearch'):
        cmd = f"ldapsearch -x -h {target} -p {port} -b '' -s base 'objectclass=*'"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/anonymous_bind.txt", logger, timeout=30)
        
        if success and stdout:
            logger.log('SUCCESS', "Anonymous bind allowed!")
        else:
            logger.log('INFO', "Anonymous bind denied or failed")
    else:
        logger.log('WARNING', "ldapsearch not found")

def phase2_naming_context(target, port, outdir, logger):
    """Enumerate naming contexts"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Naming Context Discovery{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Discovering naming contexts...")
    
    if check_tool('ldapsearch'):
        cmd = f"ldapsearch -x -h {target} -p {port} -b '' -s base '(objectclass=*)' namingContexts"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/naming_contexts.txt", logger)
        
        if success and stdout:
            if "namingContexts:" in stdout:
                logger.log('SUCCESS', "Found naming contexts")
                return stdout
        else:
            logger.log('WARNING', "Could not enumerate naming contexts")
    
    return None

def phase3_user_enumeration(target, port, base_dn, outdir, logger):
    """Enumerate users"""
    print()
    print(f"{Colors.CYAN}[Phase 3] User Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not base_dn:
        logger.log('WARNING', "No base DN - trying common ones...")
        base_dns = ["dc=domain,dc=local", "dc=example,dc=com", "ou=users,dc=domain,dc=local"]
    else:
        import re
        base_dns = re.findall(r'namingContexts: (.+)', base_dn)
    
    if check_tool('ldapsearch'):
        for base in base_dns:
            logger.log('INFO', f"Enumerating users with base DN: {base}")
            
            cmd = f"ldapsearch -x -h {target} -p {port} -b '{base}' '(objectClass=person)' cn sAMAccountName mail"
            success, stdout, _ = run_and_save(cmd, f"{outdir}/users_{base.replace(',', '_')}.txt", 
                                             logger, timeout=180)
            
            if success and "numEntries:" in stdout:
                logger.log('SUCCESS', f"Found users with base DN: {base}")
                break
            else:
                logger.log('INFO', f"No users found with base DN: {base}")

def phase4_group_enumeration(target, port, base_dn, outdir, logger):
    """Enumerate groups"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Group Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not base_dn:
        logger.log('WARNING', "Skipping group enumeration (no base DN)")
        return
    
    import re
    base_dns = re.findall(r'namingContexts: (.+)', base_dn)
    
    if check_tool('ldapsearch'):
        for base in base_dns:
            logger.log('INFO', f"Enumerating groups with base DN: {base}")
            
            cmd = f"ldapsearch -x -h {target} -p {port} -b '{base}' '(objectClass=group)' cn member"
            success, stdout, _ = run_and_save(cmd, f"{outdir}/groups_{base.replace(',', '_')}.txt", 
                                             logger, timeout=180)
            
            if success and "numEntries:" in stdout:
                logger.log('SUCCESS', f"Found groups with base DN: {base}")
                break

def phase5_domain_info(target, port, outdir, logger):
    """Enumerate domain information"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Domain Information{Colors.NC}")
    print("=" * 60)
    
    if check_tool('ldapsearch'):
        logger.log('INFO', "Querying domain information...")
        
        cmd = f"ldapsearch -x -h {target} -p {port} -b '' -s base '(objectclass=*)' defaultNamingContext dnsHostName supportedLDAPVersion"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/domain_info.txt", logger)
        
        if success:
            logger.log('SUCCESS', "Domain information retrieved")

def phase6_nmap_scripts(target, port, outdir, logger):
    """Run Nmap LDAP scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Nmap LDAP Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap LDAP scripts...")
    
    scripts = ["ldap-rootdse", "ldap-search", "ldap-brute"]
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_ldap_scripts.txt", logger, timeout=300)
    
    logger.log('SUCCESS', "Nmap LDAP scripts completed")

def phase7_windapsearch(target, port, outdir, logger):
    """Run windapsearch if available"""
    print()
    print(f"{Colors.CYAN}[Phase 7] Windapsearch (if available){Colors.NC}")
    print("=" * 60)
    
    if not check_tool('windapsearch'):
        logger.log('INFO', "windapsearch not found - skipping")
        return
    
    logger.log('INFO', "Running windapsearch...")
    
    queries = [
        ("users", "-U"),
        ("groups", "-G"),
        ("computers", "-C"),
        ("privileged", "-PU")
    ]
    
    for name, flag in queries:
        logger.log('INFO', f"Querying {name}...")
        cmd = f"windapsearch {flag} -d {target} --dc-ip {target}"
        run_and_save(cmd, f"{outdir}/windapsearch_{name}.txt", logger, timeout=180)

def phase8_ldapdomaindump(target, outdir, logger):
    """Run ldapdomaindump if available"""
    print()
    print(f"{Colors.CYAN}[Phase 8] LDAPDomainDump (if available){Colors.NC}")
    print("=" * 60)
    
    if not check_tool('ldapdomaindump'):
        logger.log('INFO', "ldapdomaindump not found - skipping")
        return
    
    logger.log('INFO', "Running ldapdomaindump...")
    
    dump_dir = f"{outdir}/ldapdomaindump"
    Path(dump_dir).mkdir(exist_ok=True)
    
    cmd = f"ldapdomaindump -u '' -p '' ldap://{target} -o {dump_dir}"
    success, _, _ = run_and_save(cmd, f"{outdir}/ldapdomaindump_output.txt", logger, timeout=300)
    
    if success:
        logger.log('SUCCESS', "ldapdomaindump completed")
    else:
        logger.log('WARNING', "ldapdomaindump may require credentials")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
LDAP Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

Key Findings:
{'-' * 70}
"""
    
    # Check files
    plain_dir = Path(outdir) / "results" / "plain_text"
    if plain_dir.exists():
        if (plain_dir / "anonymous_bind.txt").exists():
            summary_text += "  ⚠️  Anonymous bind is allowed!\n"
        
        if (plain_dir / "naming_contexts.txt").exists():
            summary_text += "  ✓ Naming contexts discovered\n"
        
        user_files = list(plain_dir.glob("users_*.txt"))
        if user_files:
            summary_text += f"  ✓ User enumeration files: {len(user_files)}\n"
        
        group_files = list(plain_dir.glob("groups_*.txt"))
        if group_files:
            summary_text += f"  ✓ Group enumeration files: {len(group_files)}\n"
    
    summary_text += f"""
{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['ldapsearch', 'nmap', 'windapsearch', 'ldapdomaindump']
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
    logger = Logger(f"{outdir}/ldap_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_anonymous_bind(target, port, outdir, logger)
    base_dn = phase2_naming_context(target, port, outdir, logger)
    phase3_user_enumeration(target, port, base_dn, outdir, logger)
    phase4_group_enumeration(target, port, base_dn, outdir, logger)
    phase5_domain_info(target, port, outdir, logger)
    phase6_nmap_scripts(target, port, outdir, logger)
    phase7_windapsearch(target, port, outdir, logger)
    phase8_ldapdomaindump(target, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ LDAP Enumeration Completed ✅{Colors.NC}")
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