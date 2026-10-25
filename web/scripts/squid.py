#!/usr/bin/env python3
"""
Squid Proxy Enumeration Script - Enhanced Edition with Dual Output
Proxy Server Assessment with Auto-Decision Logic
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
    BLUE = '\033[0;34m'
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
            'CRITICAL': f'{Colors.RED}[!!!]{Colors.NC}',
            'DECISION': f'{Colors.BLUE}[→]{Colors.NC}'
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

def file_contains(base_path, keywords):
    """Check if file contains keywords - works with dual output structure"""
    plain_path = Path(base_path).parent / "results" / "plain_text" / Path(base_path).name
    
    # Try plain text version first
    if plain_path.exists():
        try:
            with open(plain_path, 'r', errors='ignore') as f:
                data = f.read().lower()
                return any(k.lower() in data for k in keywords)
        except:
            pass
    
    # Fallback to original path
    try:
        with open(base_path, 'r', errors='ignore') as f:
            data = f.read().lower()
            return any(k.lower() in data for k in keywords)
    except:
        return False

def banner():
    print(f"{Colors.PURPLE}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          Squid Proxy Enumeration - Enhanced               ║")
    print("║          Proxy Server & Pivoting Assessment                ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_detection(target, port, outdir, logger):
    """Phase 1: Proxy detection"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Proxy Detection{Colors.NC}")
    print("=" * 60)
    
    if check_tool('nmap'):
        logger.log('INFO', "Detecting proxy with Nmap...")
        run_and_save(f"nmap -sV -p {port} --script http-open-proxy {target}",
                    f"{outdir}/01_nmap_http_open_proxy.txt", logger)
    
    logger.log('SUCCESS', "Phase 1 completed")

def phase2_banner_grab(target, port, outdir, logger):
    """Phase 2: Banner grabbing"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Banner Grabbing{Colors.NC}")
    print("=" * 60)
    
    if check_tool('nc'):
        logger.log('INFO', "Grabbing banner...")
        cmd = f"bash -c \"echo -e 'GET http://{target} HTTP/1.0\\n\\n' | nc {target} {port}\""
        run_and_save(cmd, f"{outdir}/02_nc_banner.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Phase 2 completed")

def phase3_http_test(target, port, outdir, logger):
    """Phase 3: HTTP connectivity test"""
    print()
    print(f"{Colors.CYAN}[Phase 3] HTTP Connectivity Test{Colors.NC}")
    print("=" * 60)
    
    if check_tool('curl'):
        logger.log('INFO', "Testing HTTP via proxy...")
        run_and_save(f"curl -x http://{target}:{port} http://{target} -m 8 -I",
                    f"{outdir}/03_curl_http_test.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Phase 3 completed")

def auto_decision(outdir, logger):
    """Auto-decision: What can we do with this proxy?"""
    print()
    print(f"{Colors.YELLOW}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.YELLOW}║  Auto-Decision: Evaluating Proxy Capabilities           ║{Colors.NC}")
    print(f"{Colors.YELLOW}╚{'═' * 58}╝{Colors.NC}")
    
    decision = "IGNORE"
    reasons = []
    
    # Check HTTP accessibility
    if file_contains(f"{outdir}/03_curl_http_test.txt", 
                    ['200', '301', '302', '401', '403']):
        decision = "PIVOT_HTTP"
        reasons.append("HTTP access via proxy works")
        logger.log('CRITICAL', "HTTP pivoting possible!")
    
    # Log decision
    logger.log('DECISION', f"Decision: {decision}")
    if reasons:
        for reason in reasons:
            logger.log('INFO', f"  • {reason}")
    
    # Save decision
    decision_text = f"""Decision: {decision}
Reasons:
"""
    for reason in reasons:
        decision_text += f"  - {reason}\n"
    
    save_dual_output(decision_text, f"{outdir}/04_auto_decision.txt", "Auto-Decision Analysis")
    
    return decision

def phase4_fast_scan(target, port, outdir, logger, script_dir):
    """Phase 4: Fast TCP pivot scan"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Fast TCP Pivot Scan{Colors.NC}")
    print("=" * 60)
    
    squid_fast = os.path.join(script_dir, "squid_fast_scan.py")
    
    if not Path(squid_fast).exists():
        logger.log('WARNING', f"squid_fast_scan.py not found at {squid_fast}")
        logger.log('INFO', "Skipping fast scan")
        return False
    
    logger.log('INFO', "Running fast pivot scan...")
    logger.log('WARNING', "This may take 1-2 minutes...")
    
    cmd = f"python3 \"{squid_fast}\" --target {target} --proxy {target}:{port} --threads 200 --timeout 0.3"
    
    success = run_and_save(cmd, f"{outdir}/05_squid_fast_scan.txt", logger, timeout=120)
    
    if success and file_contains(f"{outdir}/05_squid_fast_scan.txt", 
                                 ['Possible open port', 'open port']):
        logger.log('CRITICAL', "TCP pivoting confirmed - open ports detected!")
        return True
    
    logger.log('INFO', "No obvious TCP pivot opportunities")
    return False

def phase5_spose_scan(target, port, outdir, logger, script_dir):
    """Phase 5: Spose scanner (if available)"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Spose Scanner (Optional){Colors.NC}")
    print("=" * 60)
    
    spose = os.path.join(script_dir, "spose.py")
    
    if not Path(spose).exists():
        logger.log('INFO', "spose.py not found - skipping")
        return
    
    if not check_tool('python3'):
        logger.log('WARNING', "Python3 not found")
        return
    
    logger.log('INFO', "Running spose scanner...")
    
    cmd = f"python3 \"{spose}\" --proxy http://{target}:{port} --target {target}"
    
    run_and_save(cmd, f"{outdir}/06_spose_scan.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Spose scan completed")

def generate_summary(target, port, outdir, logger, decision, tcp_pivot):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
Squid Proxy Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🎯 Assessment Results:
{'-' * 70}
Decision: {decision}
"""
    
    if decision == "PIVOT_HTTP":
        summary_text += "⚠️  CRITICAL: HTTP pivoting is possible!\n"
    
    if tcp_pivot:
        summary_text += "⚠️  CRITICAL: TCP pivoting confirmed!\n"
    
    summary_text += f"""
🔍 Proxy Capabilities:
{'-' * 70}
"""
    
    if decision == "PIVOT_HTTP":
        summary_text += """✓ HTTP requests can be proxied
✓ Can reach internal networks
"""
    
    if tcp_pivot:
        summary_text += """✓ TCP CONNECT method works
✓ Can scan internal ports
"""
    
    if decision == "IGNORE":
        summary_text += "✗ No obvious pivoting opportunities\n"
    
    summary_text += f"""
Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
🔧 Exploitation Examples:
{'-' * 70}
"""
    
    if decision != "IGNORE":
        summary_text += f"""1. Manual HTTP requests:
   curl -x http://{target}:{port} http://internal-ip/

2. Port scanning:
   python3 spose.py --proxy http://{target}:{port} --target internal-ip

3. Nmap through proxy:
   proxychains nmap -sT internal-ip
   (Configure proxychains.conf with SOCKS)

4. Browser configuration:
   Set HTTP proxy: {target}:{port}
   Access internal resources
"""
    else:
        summary_text += "No exploitation opportunities identified\n"
    
    summary_text += f"""
{'=' * 70}
🛡️  Recommendations:
{'-' * 70}
  1. Restrict proxy access (ACLs)
  2. Require authentication
  3. Disable CONNECT method if not needed
  4. Log all proxy requests
  5. Use firewall rules
  6. Regular security audits

{'=' * 70}
🔧 Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'nc', 'curl', 'python3']
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
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    Path(outdir).mkdir(parents=True, exist_ok=True)
    logger = Logger(f"{outdir}/squid_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    logger.log('INFO', f"Script directory: {script_dir}")
    
    # Execute phases
    phase1_detection(target, port, outdir, logger)
    phase2_banner_grab(target, port, outdir, logger)
    phase3_http_test(target, port, outdir, logger)
    
    # Auto-decision
    decision = auto_decision(outdir, logger)
    
    # Additional scans
    tcp_pivot = phase4_fast_scan(target, port, outdir, logger, script_dir)
    phase5_spose_scan(target, port, outdir, logger, script_dir)
    
    # Update decision if TCP pivot found
    if tcp_pivot:
        decision = "PIVOT_TCP"
    
    # Generate summary
    generate_summary(target, port, outdir, logger, decision, tcp_pivot)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ Squid Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.CYAN}🎯 Decision: {decision}{Colors.NC}")
    print(f"{Colors.CYAN}💡 Each file contains the command at the top!{Colors.NC}")
    
    if decision != "IGNORE":
        print()
        print(f"{Colors.YELLOW}⚠️  Pivoting opportunities detected!{Colors.NC}")
        print(f"{Colors.YELLOW}Review {outdir}/SUMMARY.txt for exploitation examples{Colors.NC}")
    
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