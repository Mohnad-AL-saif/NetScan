#!/usr/bin/env python3
"""
WinRM Enumeration Script - Enhanced Edition with Dual Output
Windows Remote Management Security Assessment
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

def run_command(cmd, logger, description=None, timeout=60):
    if description:
        logger.log('INFO', description)
    
    print(f"\n{'=' * 60}")
    print(f"{Colors.RED}{cmd}{Colors.NC}")
    print(f"{'=' * 60}\n")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=timeout)
        
        output = result.stdout if result.stdout else result.stderr
        if output:
            print(f"{Colors.GREEN}{output}{Colors.NC}")
        
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        logger.log('WARNING', f"Timeout after {timeout}s")
        return False, f"[!] Command timed out after {timeout}s\n"
    except Exception as e:
        logger.log('ERROR', f"Failed: {str(e)}")
        return False, f"[!] Error: {str(e)}\n"

def run_and_save(cmd, outfile, logger, description=None, timeout=60):
    """تنفيذ الأمر وحفظه تلقائياً في مجلدين"""
    success, output = run_command(cmd, logger, description, timeout)
    if outfile:
        save_dual_output(output, outfile, cmd)
    return success

def check_tool(tool):
    return shutil.which(tool) is not None

def banner():
    print(f"{Colors.PURPLE}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          WinRM Enumeration - Enhanced Edition             ║")
    print("║          Windows Remote Management Assessment              ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Phase 1: Nmap WinRM scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap WinRM Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap WinRM scripts...")
    run_and_save(f"nmap -p {port} -sV --script winrm* {target}",
                f"{outdir}/01_nmap_winrm_scripts.txt", logger, timeout=90)
    
    logger.log('SUCCESS', "Phase 1 completed")

def phase2_service_detection(target, port, outdir, logger):
    """Phase 2: Service detection and banner grabbing"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Service Detection{Colors.NC}")
    print("=" * 60)
    
    # Port-specific messages
    port_info = {
        '5985': 'WinRM HTTP',
        '5986': 'WinRM HTTPS'
    }
    
    logger.log('INFO', f"Port {port}: {port_info.get(port, 'WinRM')}")
    
    if check_tool('nmap'):
        logger.log('INFO', "Service version detection...")
        run_and_save(f"nmap -p {port} -sV {target}",
                    f"{outdir}/02_service_detection.txt", logger)
    
    # Test connection
    if port == '5986' and check_tool('openssl'):
        logger.log('INFO', "Testing HTTPS connection...")
        run_and_save(f"echo 'QUIT' | openssl s_client -connect {target}:{port} 2>&1",
                    f"{outdir}/03_ssl_connection.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Phase 2 completed")

def phase3_auth_test(target, port, outdir, logger):
    """Phase 3: Authentication testing"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Authentication Testing{Colors.NC}")
    print("=" * 60)
    
    # Test with common credentials (documenting only, not actually testing)
    auth_info = f"""WinRM Authentication Information
{'=' * 60}

WinRM requires valid Windows credentials.

Common testing approaches:
  1. evil-winrm -i {target} -u administrator -p 'password'
  2. netexec winrm {target} -u users.txt -p passwords.txt
  3. crackmapexec winrm {target} -u admin -p pass

Default credentials to try:
  - administrator:(blank)
  - administrator:password
  - administrator:Password123
  - administrator:P@ssw0rd
"""
    
    save_dual_output(auth_info, f"{outdir}/04_auth_test_info.txt", 
                    "WinRM Authentication Information")
    
    logger.log('INFO', "Authentication test info saved")
    
    # NetExec if available
    if check_tool('netexec'):
        logger.log('INFO', "Testing with NetExec...")
        run_and_save(f"netexec winrm {target}",
                    f"{outdir}/05_netexec_winrm.txt", logger, timeout=15)
    
    logger.log('SUCCESS', "Phase 3 completed")

def phase4_brute_force_info(target, port, outdir, logger):
    """Phase 4: Brute force information"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Brute Force Information{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Generating brute force examples...")
    
    bruteforce_info = f"""WinRM Brute Force Examples
{'=' * 60}

⚠️  WARNING: Brute forcing can lock accounts!

Tools:
  • evil-winrm -i {target} -u admin -p passwords.txt
  • netexec winrm {target} -u users.txt -p passwords.txt
  • hydra -L users.txt -P passwords.txt winrm://{target}
  • medusa -h {target} -U users.txt -P passwords.txt -M winrm

Best practices:
  - Use small targeted wordlists
  - Add delays between attempts
  - Monitor for account lockouts
  - Check password policy first
"""
    
    save_dual_output(bruteforce_info, f"{outdir}/06_brute_force_examples.txt", 
                    "Brute Force Examples")
    
    logger.log('SUCCESS', "Phase 4 completed")

def phase5_exploitation_info(target, port, outdir, logger):
    """Phase 5: Exploitation information"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Exploitation Information{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Generating exploitation examples...")
    
    exploit_info = f"""WinRM Exploitation Information
{'=' * 60}

If you obtain valid credentials:

1. evil-winrm (Recommended):
   evil-winrm -i {target} -u administrator -p 'Password123'
   evil-winrm -i {target} -u admin -H <NTLM_HASH>

2. PowerShell Remoting:
   $cred = Get-Credential
   Enter-PSSession -ComputerName {target} -Credential $cred

3. NetExec:
   netexec winrm {target} -u admin -p pass -x 'whoami'
   netexec winrm {target} -u admin -H <HASH> -x 'command'

4. Metasploit:
   use exploit/windows/winrm/winrm_script_exec
   set RHOSTS {target}
   set USERNAME admin
   set PASSWORD pass
   run
"""
    
    save_dual_output(exploit_info, f"{outdir}/07_exploitation_info.txt", 
                    "Exploitation Information")
    
    logger.log('SUCCESS', "Phase 5 completed")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    port_type = {
        '5985': 'WinRM HTTP (unencrypted)',
        '5986': 'WinRM HTTPS (encrypted)'
    }.get(port, f'WinRM on port {port}')
    
    summary_text = f"""{'=' * 70}
WinRM Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🔧 Service Information:
{'-' * 70}
Port: {port} ({port_type})
"""
    
    if port == '5985':
        summary_text += "⚠️  WARNING: Unencrypted WinRM (credentials sent in clear!)\n"
    
    summary_text += f"""
Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
🛡️  Security Recommendations:
{'-' * 70}
  1. Use WinRM HTTPS (port 5986) instead of HTTP
  2. Implement strong password policies
  3. Use certificate-based authentication
  4. Enable Network Level Authentication (NLA)
  5. Restrict WinRM access via firewall
  6. Use VPN for remote access
  7. Monitor WinRM logs regularly
  8. Disable WinRM if not needed
  9. Use least privilege accounts
 10. Enable audit logging

{'=' * 70}
🔓 Post-Exploitation:
{'-' * 70}
If credentials are obtained:
  • Use evil-winrm for interactive shell
  • Upload/download files
  • Execute PowerShell commands
  • Dump credentials with mimikatz
  • Lateral movement

{'=' * 70}
🔧 Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'netexec', 'evil-winrm', 'openssl']
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
    logger = Logger(f"{outdir}/winrm_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    if port == '5985':
        logger.log('WARNING', "WinRM HTTP - credentials sent unencrypted!")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    phase2_service_detection(target, port, outdir, logger)
    phase3_auth_test(target, port, outdir, logger)
    phase4_brute_force_info(target, port, outdir, logger)
    phase5_exploitation_info(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ WinRM Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.CYAN}💡 Each file contains the command at the top!{Colors.NC}")
    
    if port == '5985':
        print()
        print(f"{Colors.RED}⚠️  WARNING: HTTP WinRM is unencrypted!{Colors.NC}")
    
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