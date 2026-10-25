#!/usr/bin/env python3
"""
SMTP Enumeration Script - Enhanced Edition with Dual Output
Comprehensive Email Server Security Assessment
كل أمر يُحفظ في رأس الملف - نسختان: ملون وعادي
"""

import sys
import subprocess
import os
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

def run_command(cmd, logger, description=None, timeout=30):
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

def run_and_save(cmd, outfile, logger, description=None, timeout=30):
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
    print("║          SMTP Enumeration - Enhanced Edition              ║")
    print("║          Email Server Security Assessment                  ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_reconnaissance(target, port, outdir, logger):
    """Phase 1: Reconnaissance"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Reconnaissance{Colors.NC}")
    print("=" * 60)
    
    # Service detection
    if check_tool('nmap'):
        logger.log('INFO', "Service detection with Nmap...")
        run_and_save(f"nmap -sV -p {port} {target}",
                    f"{outdir}/01_nmap_service.txt", logger)
    
    # Banner grabbing
    logger.log('INFO', "Banner grabbing...")
    if check_tool('nc'):
        run_and_save(f"echo 'QUIT' | nc -w 3 {target} {port}",
                    f"{outdir}/02_banner_nc.txt", logger, timeout=10)
        run_and_save(f"echo 'EHLO test' | nc -w 3 {target} {port}",
                    f"{outdir}/03_banner_ehlo.txt", logger, timeout=10)
    
    # TLS banners for submission/SMTPS
    if port in ["465", "587"] and check_tool('openssl'):
        logger.log('INFO', "Testing STARTTLS...")
        run_and_save(f"echo 'QUIT' | openssl s_client -starttls smtp -connect {target}:{port} 2>&1",
                    f"{outdir}/04_banner_starttls.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Phase 1 completed")

def phase2_command_enum(target, port, outdir, logger):
    """Phase 2: SMTP command enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 2] SMTP Command Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Enumerating SMTP commands...")
    run_and_save(f"nmap --script smtp-commands -p {port} {target}",
                f"{outdir}/05_smtp_commands.txt", logger)
    
    # Check for dangerous methods
    logger.log('INFO', "Checking for VRFY/EXPN/RCPT commands...")
    cmd = f"nmap --script smtp-commands -p {port} {target} | grep -Eo 'VRFY|EXPN|RCPT'"
    run_and_save(cmd, f"{outdir}/06_smtp_dangerous_methods.txt", logger)
    
    logger.log('SUCCESS', "Phase 2 completed")

def phase3_nse_scripts(target, port, outdir, logger):
    """Phase 3: Full SMTP NSE enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Nmap NSE Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running all SMTP NSE scripts...")
    run_and_save(f"nmap --script smtp-* -p {port} {target}",
                f"{outdir}/07_smtp_all_scripts.txt", logger, timeout=60)
    
    logger.log('INFO', "Extracting NTLM info...")
    run_and_save(f"nmap --script smtp-ntlm-info -p {port} {target}",
                f"{outdir}/08_smtp_ntlm_info.txt", logger)
    
    logger.log('SUCCESS', "Phase 3 completed")

def phase4_user_enum(target, port, outdir, logger):
    """Phase 4: User enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 4] User Enumeration{Colors.NC}")
    print("=" * 60)
    
    # Create users list if doesn't exist
    users_file = f"{outdir}/test_users.txt"
    if not Path(users_file).exists():
        with open(users_file, 'w') as f:
            f.write("\n".join(["root", "admin", "administrator", "postmaster", 
                              "webmaster", "test", "guest"]))
        logger.log('INFO', f"Created test users list: {users_file}")
    
    if check_tool('smtp-user-enum'):
        logger.log('INFO', "User enumeration with smtp-user-enum...")
        
        # VRFY method
        logger.log('INFO', "Testing VRFY method...")
        run_and_save(f"smtp-user-enum -M VRFY -U {users_file} -t {target} -p {port}",
                    f"{outdir}/09_user_enum_vrfy.txt", logger, timeout=30)
        
        # EXPN method
        logger.log('INFO', "Testing EXPN method...")
        run_and_save(f"smtp-user-enum -M EXPN -U {users_file} -t {target} -p {port}",
                    f"{outdir}/10_user_enum_expn.txt", logger, timeout=30)
        
        # RCPT method
        logger.log('INFO', "Testing RCPT method...")
        run_and_save(f"smtp-user-enum -M RCPT -U {users_file} -t {target} -p {port} -f test@test.com",
                    f"{outdir}/11_user_enum_rcpt.txt", logger, timeout=30)
    else:
        logger.log('WARNING', "smtp-user-enum not found")
    
    logger.log('SUCCESS', "Phase 4 completed")

def phase5_open_relay(target, port, outdir, logger):
    """Phase 5: Open relay testing"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Open Relay Testing{Colors.NC}")
    print("=" * 60)
    
    logger.log('WARNING', "Testing for open relay...")
    
    # Manual relay test
    if check_tool('nc'):
        relay_cmd = f"""bash -c '(
echo "EHLO test"
sleep 1
echo "MAIL FROM:<attacker@evil.com>"
sleep 1
echo "RCPT TO:<victim@gmail.com>"
sleep 1
echo "DATA"
sleep 1
echo "Subject: Open Relay Test"
echo "."
echo "QUIT"
) | nc {target} {port}'"""
        
        run_and_save(relay_cmd, f"{outdir}/12_open_relay_manual.txt", logger, timeout=15)
    
    # Nmap open relay check
    if check_tool('nmap'):
        logger.log('INFO', "Nmap open relay check...")
        run_and_save(f"nmap --script smtp-open-relay -p {port} {target}",
                    f"{outdir}/13_nmap_open_relay.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Phase 5 completed")

def phase6_auth_methods(target, port, outdir, logger):
    """Phase 6: Authentication methods"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Authentication Methods{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking AUTH methods...")
    
    if check_tool('nc'):
        run_and_save(f"echo 'EHLO test' | nc -w 3 {target} {port} | grep -i auth",
                    f"{outdir}/14_auth_methods.txt", logger, timeout=10)
    
    logger.log('INFO', "Note: For brute force, use Hydra (not automated)")
    
    bruteforce_info = f"""SMTP Brute Force Information
{'=' * 60}

⚠️  Brute forcing requires valid authentication

Example commands:
  hydra -l user -P passwords.txt smtp://{target}:{port}
  hydra -L users.txt -P passwords.txt smtp://{target}:{port}
  medusa -h {target} -u user -P passwords.txt -M smtp
"""
    
    save_dual_output(bruteforce_info, f"{outdir}/15_brute_force_info.txt", 
                    "Brute Force Information")
    
    logger.log('SUCCESS', "Phase 6 completed")

def phase7_email_testing(target, port, outdir, logger):
    """Phase 7: Email sending tests"""
    print()
    print(f"{Colors.CYAN}[Phase 7] Email Sending Tests{Colors.NC}")
    print("=" * 60)
    
    # SWAKS
    if check_tool('swaks'):
        logger.log('INFO', "Testing email delivery with SWAKS...")
        run_and_save(f"swaks --to test@{target} --from attacker@evil.com --server {target} --port {port}",
                    f"{outdir}/16_swaks_test.txt", logger, timeout=15)
    else:
        logger.log('INFO', "SWAKS not found")
    
    # sendemail
    if check_tool('sendemail'):
        logger.log('INFO', "Testing with sendemail...")
        cmd = f"sendemail -f attacker@evil.com -t test@{target} -s {target}:{port} -u 'Test Subject' -m 'Test Body'"
        run_and_save(cmd, f"{outdir}/17_sendemail_test.txt", logger, timeout=15)
    else:
        logger.log('INFO', "sendemail not found")
    
    logger.log('SUCCESS', "Phase 7 completed")

def phase8_vuln_scan(target, port, outdir, logger):
    """Phase 8: Vulnerability scanning"""
    print()
    print(f"{Colors.CYAN}[Phase 8] Vulnerability Scanning{Colors.NC}")
    print("=" * 60)
    
    if check_tool('nmap'):
        logger.log('INFO', "Scanning for SMTP vulnerabilities...")
        run_and_save(f"nmap --script smtp-vuln* -p {port} {target}",
                    f"{outdir}/18_smtp_vulns.txt", logger, timeout=60)
    
    logger.log('SUCCESS', "Phase 8 completed")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    port_type = {
        '25': 'SMTP (Standard)',
        '465': 'SMTPS (SSL/TLS)',
        '587': 'Submission (STARTTLS)'
    }.get(port, f'SMTP on port {port}')
    
    summary_text = f"""{'=' * 70}
SMTP Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

📧 Server Information:
{'-' * 70}
Port: {port} ({port_type})

🔍 Security Findings:
{'-' * 70}
"""
    
    # Check for issues
    plain_dir = Path(outdir) / "results" / "plain_text"
    
    # Check open relay
    relay_file = plain_dir / "13_nmap_open_relay.txt"
    if relay_file.exists():
        with open(relay_file) as f:
            content = f.read().lower()
            if 'vulnerable' in content or 'open' in content:
                summary_text += "⚠️  CRITICAL: Possible open relay detected!\n"
    
    # Check user enumeration
    user_file = plain_dir / "09_user_enum_vrfy.txt"
    if user_file.exists():
        with open(user_file) as f:
            content = f.read()
            if 'exists' in content.lower():
                summary_text += "⚠️  WARNING: User enumeration possible (VRFY)\n"
    
    summary_text += f"""
Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
🛡️  Recommendations:
{'-' * 70}
  1. Disable VRFY and EXPN commands
  2. Ensure relay is properly restricted
  3. Use STARTTLS or SMTPS
  4. Implement SPF, DKIM, DMARC
  5. Rate limiting for authentication
  6. Strong password policies
  7. Monitor for suspicious activity
  8. Regular security updates

{'=' * 70}
🔧 Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'nc', 'openssl', 'smtp-user-enum', 'swaks', 'sendemail']
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
    logger = Logger(f"{outdir}/smtp_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_reconnaissance(target, port, outdir, logger)
    phase2_command_enum(target, port, outdir, logger)
    phase3_nse_scripts(target, port, outdir, logger)
    phase4_user_enum(target, port, outdir, logger)
    phase5_open_relay(target, port, outdir, logger)
    phase6_auth_methods(target, port, outdir, logger)
    phase7_email_testing(target, port, outdir, logger)
    phase8_vuln_scan(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ SMTP Enumeration Completed ✅{Colors.NC}")
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