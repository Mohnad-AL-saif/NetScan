#!/usr/bin/env python3
"""
POP3 Enumeration Script - Enhanced Edition with Dual Output
Post Office Protocol v3 Security Assessment
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

def run_command(cmd, logger, description=None, timeout=60):
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

def run_and_save(cmd, outfile, logger, description=None, timeout=60):
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
    print("║          POP3 Enumeration - Enhanced Edition              ║")
    print("║          Mail Server Security Assessment                   ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_banner_grab(target, port, outdir, logger):
    """Grab POP3 banner"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Banner Grabbing{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Grabbing POP3 banner...")
    
    # Using nc
    if check_tool('nc'):
        cmd = f"echo 'USER test' | nc -w 3 {target} {port}"
        run_and_save(cmd, f"{outdir}/banner_nc.txt", logger, timeout=10)
        logger.log('SUCCESS', "Banner grabbed with netcat")
    
    # Using telnet
    if check_tool('telnet'):
        cmd = f"(sleep 2; echo 'QUIT') | telnet {target} {port} 2>&1"
        run_and_save(cmd, f"{outdir}/banner_telnet.txt", logger, timeout=10)
        logger.log('SUCCESS', "Banner grabbed with telnet")

def phase2_nmap_scripts(target, port, outdir, logger):
    """Run Nmap POP3 scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Nmap POP3 Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap POP3 scripts...")
    
    scripts = ["pop3-capabilities", "pop3-ntlm-info", "pop3-brute"]
    script_list = ",".join(scripts)
    
    cmd = f"nmap -p {port} -sV --script {script_list} {target}"
    run_and_save(cmd, f"{outdir}/nmap_pop3_scripts.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Nmap scripts completed")

def phase3_ssl_check(target, port, outdir, logger):
    """Check SSL/TLS support"""
    print()
    print(f"{Colors.CYAN}[Phase 3] SSL/TLS Check{Colors.NC}")
    print("=" * 60)
    
    if port == '995':
        logger.log('INFO', "Port 995 detected - POP3S (SSL/TLS)")
        
        if check_tool('openssl'):
            logger.log('INFO', "Testing SSL connection...")
            cmd = f"echo 'QUIT' | openssl s_client -connect {target}:{port} -quiet 2>&1"
            run_and_save(cmd, f"{outdir}/ssl_connection.txt", logger, timeout=10)
            logger.log('SUCCESS', "SSL connection test completed")
    else:
        logger.log('INFO', "Standard POP3 port - checking STLS support...")
        if check_tool('nc'):
            cmd = f"echo 'STLS' | nc -w 3 {target} {port}"
            run_and_save(cmd, f"{outdir}/stls_test.txt", logger, timeout=10)

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
POP3 Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

Port Information:
{'-' * 70}
Port: {port} ({'POP3S (SSL)' if port == '995' else 'POP3'})

Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Recommendations:
{'-' * 70}
  1. Use POP3S (port 995) instead of POP3
  2. Implement strong password policies
  3. Enable rate limiting
  4. Use fail2ban for brute force protection
  5. Consider using IMAP instead (more features)

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nc', 'nmap', 'openssl', 'telnet']
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
    logger = Logger(f"{outdir}/pop3_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_banner_grab(target, port, outdir, logger)
    phase2_nmap_scripts(target, port, outdir, logger)
    phase3_ssl_check(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ POP3 Enumeration Completed ✅{Colors.NC}")
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