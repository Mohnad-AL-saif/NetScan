#!/usr/bin/env python3
"""
VNC Enumeration Script - Enhanced Edition with Dual Output
Virtual Network Computing Security Assessment
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
    print("║          VNC Enumeration - Enhanced Edition               ║")
    print("║          Remote Desktop Protocol Assessment                ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Phase 1: Nmap VNC scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap VNC Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap VNC scripts...")
    
    scripts = ['vnc-info', 'vnc-brute', 'vnc-title']
    script_list = ','.join(scripts)
    
    run_and_save(f"nmap -p {port} -sV --script {script_list} {target}",
                f"{outdir}/01_nmap_vnc_scripts.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Phase 1 completed")

def phase2_banner_grab(target, port, outdir, logger):
    """Phase 2: Banner grabbing"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Banner Grabbing{Colors.NC}")
    print("=" * 60)
    
    if check_tool('nc'):
        logger.log('INFO', "Grabbing VNC banner...")
        run_and_save(f"echo '' | nc -w 3 {target} {port}",
                    f"{outdir}/02_banner_nc.txt", logger, timeout=10)
    
    if check_tool('nmap'):
        logger.log('INFO', "Version detection...")
        run_and_save(f"nmap -p {port} -sV {target}",
                    f"{outdir}/03_version_detection.txt", logger)
    
    logger.log('SUCCESS', "Phase 2 completed")

def phase3_auth_check(target, port, outdir, logger):
    """Phase 3: Authentication check"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Authentication Check{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking authentication requirement...")
    
    # Common VNC ports
    port_info = {
        '5900': 'VNC Display :0',
        '5901': 'VNC Display :1',
        '5902': 'VNC Display :2',
        '5903': 'VNC Display :3'
    }
    
    auth_info = f"""VNC Authentication Information
{'=' * 60}

Port: {port}
Type: {port_info.get(port, 'VNC')}

VNC Authentication:
  • VNC uses password authentication (not username)
  • Max password length: 8 characters
  • Some VNC servers allow no password

Common VNC passwords to try:
  - (blank)
  - password
  - admin
  - vnc123
  - P@ssw0rd
  - 12345678
"""
    
    save_dual_output(auth_info, f"{outdir}/04_auth_info.txt", "VNC Authentication Information")
    
    logger.log('INFO', "Authentication info saved")
    logger.log('SUCCESS', "Phase 3 completed")

def phase4_brute_force(target, port, outdir, logger):
    """Phase 4: Brute force examples"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Brute Force Information{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Generating brute force examples...")
    
    bruteforce_info = f"""VNC Brute Force Examples
{'=' * 60}

⚠️  WARNING: VNC limits failed attempts - be careful!

Tools:
  1. Hydra:
     hydra -P passwords.txt vnc://{target}:{port}
     hydra -P /usr/share/wordlists/rockyou.txt vnc://{target}

  2. Medusa:
     medusa -h {target} -u root -P passwords.txt -M vnc

  3. Nmap:
     nmap --script vnc-brute -p {port} {target}

  4. vncpwd (decrypt VNC password from registry/files):
     vncpwd.exe <encrypted_password>

Best practices:
  - Use small targeted wordlists
  - VNC passwords are max 8 characters
  - Add delays between attempts
  - Some VNC servers have lockout mechanisms
"""
    
    save_dual_output(bruteforce_info, f"{outdir}/05_brute_force_examples.txt", 
                    "Brute Force Examples")
    
    logger.log('SUCCESS', "Phase 4 completed")

def phase5_metasploit(target, port, outdir, logger):
    """Phase 5: Metasploit information"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Metasploit Modules{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Generating Metasploit examples...")
    
    metasploit_info = f"""VNC Metasploit Modules
{'=' * 60}

1. VNC Authentication None Scanner:
   use auxiliary/scanner/vnc/vnc_none_auth
   set RHOSTS {target}
   set RPORT {port}
   run

2. VNC Login Scanner:
   use auxiliary/scanner/vnc/vnc_login
   set RHOSTS {target}
   set RPORT {port}
   set PASS_FILE /path/to/passwords.txt
   run

3. VNC Keyboard Injection (post-exploitation):
   use auxiliary/admin/vnc/vnc_keyboard
   set RHOSTS {target}
   set RPORT {port}
   set PASSWORD <password>
   set KEYS 'ipconfig'
   run
"""
    
    save_dual_output(metasploit_info, f"{outdir}/06_metasploit_info.txt", 
                    "Metasploit Modules")
    
    logger.log('SUCCESS', "Phase 5 completed")

def phase6_vulnerabilities(target, port, outdir, logger):
    """Phase 6: Known vulnerabilities"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Known Vulnerabilities{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Documenting known VNC vulnerabilities...")
    
    vuln_info = f"""Known VNC Vulnerabilities
{'=' * 60}

Common VNC Security Issues:

1. Authentication Bypass:
   • Some VNC servers allow no password
   • CVE-2006-2369 (RealVNC)
   • CVE-2015-5239 (QEMU VNC)

2. Weak Encryption:
   • VNC uses DES encryption (weak)
   • Traffic can be intercepted
   • Use VNC over SSH tunnel

3. Man-in-the-Middle:
   • VNC traffic is often unencrypted
   • Credentials can be captured

4. Denial of Service:
   • CVE-2011-0904 (VNC DoS)
   • Various buffer overflow issues

Recommendations:
  ✓ Always use VNC over SSH tunnel
  ✓ Use strong passwords (max 8 chars)
  ✓ Enable encryption if available
  ✓ Restrict access via firewall
  ✓ Consider VNC alternatives (RDP, TeamViewer)
"""
    
    save_dual_output(vuln_info, f"{outdir}/07_vulnerabilities.txt", 
                    "Known Vulnerabilities")
    
    logger.log('SUCCESS', "Phase 6 completed")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    port_info = {
        '5900': 'VNC Display :0 (default)',
        '5901': 'VNC Display :1',
        '5902': 'VNC Display :2',
        '5903': 'VNC Display :3'
    }.get(port, f'VNC on port {port}')
    
    summary_text = f"""{'=' * 70}
VNC Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🖥️  Service Information:
{'-' * 70}
Port: {port} ({port_info})
⚠️  VNC uses weak DES encryption
⚠️  Max password length: 8 characters

Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
🛡️  Security Recommendations:
{'-' * 70}
  1. ALWAYS use VNC over SSH tunnel
  2. Use strong passwords (8 characters max)
  3. Enable VNC encryption if available
  4. Restrict access via firewall
  5. Use VPN for remote access
  6. Consider using RDP instead
  7. Disable VNC if not needed
  8. Monitor VNC logs
  9. Keep VNC software updated
 10. Use display numbers > 0 to avoid :0

{'=' * 70}
🔐 SSH Tunneling (Recommended):
{'-' * 70}
ssh -L 5900:localhost:{port} user@{target}
vncviewer localhost:5900

{'=' * 70}
🔧 Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'nc', 'hydra', 'vncviewer']
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
    logger = Logger(f"{outdir}/vnc_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    logger.log('WARNING', "VNC uses weak encryption - SSH tunnel recommended!")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    phase2_banner_grab(target, port, outdir, logger)
    phase3_auth_check(target, port, outdir, logger)
    phase4_brute_force(target, port, outdir, logger)
    phase5_metasploit(target, port, outdir, logger)
    phase6_vulnerabilities(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ VNC Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.YELLOW}💡 Tip: Always use VNC over SSH tunnel!{Colors.NC}")
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