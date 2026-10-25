#!/usr/bin/env python3
"""
RDP Enumeration Script - Enhanced Edition with Dual Output
Remote Desktop Protocol Security Assessment
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
    print("║          RDP Enumeration - Enhanced Edition               ║")
    print("║          Remote Desktop Protocol Assessment                ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scripts(target, port, outdir, logger):
    """Run Nmap RDP scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap RDP Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap RDP enumeration scripts...")
    
    scripts = ["rdp-enum-encryption", "rdp-ntlm-info", "rdp-vuln-ms12-020"]
    script_list = ",".join(scripts)
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_rdp_scripts.txt", logger, timeout=180)
    
    logger.log('SUCCESS', "Nmap RDP scripts completed")

def phase2_rdp_scan(target, port, outdir, logger):
    """Additional RDP scanning"""
    print()
    print(f"{Colors.CYAN}[Phase 2] RDP Security Scan{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking for BlueKeep (CVE-2019-0708)...")
    
    if check_tool('nmap'):
        cmd = f"nmap -p {port} --script rdp-vuln-ms12-020 {target}"
        run_and_save(cmd, f"{outdir}/bluekeep_check.txt", logger, timeout=60)
    
    logger.log('INFO', "Checking RDP encryption level...")
    if check_tool('nmap'):
        cmd = f"nmap -p {port} --script rdp-enum-encryption {target}"
        run_and_save(cmd, f"{outdir}/encryption_check.txt", logger, timeout=60)

def phase3_netexec(target, port, outdir, logger):
    """NetExec RDP enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 3] NetExec Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('netexec'):
        logger.log('INFO', "NetExec not found - skipping")
        return
    
    logger.log('INFO', "Running NetExec RDP enumeration...")
    
    cmd = f"netexec rdp {target}"
    run_and_save(cmd, f"{outdir}/netexec_rdp.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "NetExec completed")

def phase4_user_enum(target, port, outdir, logger):
    """User enumeration (if possible)"""
    print()
    print(f"{Colors.CYAN}[Phase 4] User Enumeration{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Attempting user enumeration...")
    
    info_text = f"""User Enumeration Information
{'=' * 60}

Direct user enumeration on RDP requires valid credentials.
Consider using:
  - NetExec with username list
  - Hydra for brute force (careful!)
  - SMB enumeration on port 445 (if available)

Example commands:
  netexec rdp {target} -u users.txt -p '' --continue-on-success
  hydra -L users.txt -P passwords.txt rdp://{target}
"""
    
    save_dual_output(info_text, f"{outdir}/user_enum_info.txt", "User Enumeration Information")
    logger.log('INFO', "User enumeration info saved")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
RDP Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

Target Information:
{'-' * 70}
Target: {target}
Port: {port} (Remote Desktop Protocol)

"""
    
    # Check BlueKeep
    plain_dir = Path(outdir) / "results" / "plain_text"
    bluekeep_file = plain_dir / "bluekeep_check.txt"
    
    if bluekeep_file.exists():
        summary_text += f"""🔍 Vulnerability Check:
{'-' * 70}
BlueKeep (CVE-2019-0708) check completed
Review bluekeep_check.txt for details

"""
    
    summary_text += f"""Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Security Recommendations:
{'-' * 70}
  1. Enable Network Level Authentication (NLA)
  2. Use strong passwords (min 12 characters)
  3. Implement account lockout policies
  4. Use RDP Gateway for external access
  5. Enable firewall rules (allow specific IPs only)
  6. Keep Windows updated (patch BlueKeep!)
  7. Use MFA/2FA if possible
  8. Monitor RDP logs regularly
  9. Consider using VPN instead of direct RDP
 10. Disable RDP if not needed

{'=' * 70}
Known RDP Vulnerabilities:
{'-' * 70}
  • BlueKeep (CVE-2019-0708) - RCE, wormable
  • DejaBlue (CVE-2019-1181, CVE-2019-1182)
  • MS12-020 - DoS vulnerability
  • Always check for latest patches!

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'netexec']
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
    logger = Logger(f"{outdir}/rdp_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('WARNING', "RDP enumeration is limited without credentials")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_nmap_scripts(target, port, outdir, logger)
    phase2_rdp_scan(target, port, outdir, logger)
    phase3_netexec(target, port, outdir, logger)
    phase4_user_enum(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ RDP Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.YELLOW}💡 Tip: Check for BlueKeep vulnerability!{Colors.NC}")
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