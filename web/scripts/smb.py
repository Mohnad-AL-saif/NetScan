#!/usr/bin/env python3
"""
SMB Enumeration Script - Enhanced Edition with Dual Output
Comprehensive SMB/CIFS Security Assessment with Auto-Decision Logic
كل أمر يُحفظ في رأس الملف - نسختان: ملون وعادي
"""

import sys
import subprocess
import os
import time
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
                return any(k in data for k in keywords)
        except:
            pass
    
    # Fallback to original path
    try:
        with open(base_path, 'r', errors='ignore') as f:
            data = f.read().lower()
            return any(k in data for k in keywords)
    except:
        return False

def banner():
    print(f"{Colors.PURPLE}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          SMB Enumeration - Enhanced Edition               ║")
    print("║          Intelligent Multi-Stage Assessment                ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def stage1_quick_enum(target, smb_ports, outdir, logger):
    """Stage 1: Quick SMB enumeration (FAST)"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Stage 1: Quick SMB Enumeration (FAST)                   ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    logger.log('INFO', f"Using SMB ports: {smb_ports}")
    
    # Nmap basic enum
    if check_tool('nmap'):
        logger.log('INFO', "Running Nmap basic SMB enumeration...")
        cmd = f"nmap -p {smb_ports} -sV -sC --script smb-enum-shares,smb-enum-users,smb-os-discovery {target}"
        run_and_save(cmd, f"{outdir}/01_nmap_basic_enum.txt", logger, timeout=30)
    
    # NBT tools
    if check_tool('nmblookup'):
        logger.log('INFO', "Running nmblookup...")
        run_and_save(f"nmblookup -A {target}", f"{outdir}/02_nmblookup.txt", logger, timeout=10)
    
    if check_tool('nbtscan'):
        logger.log('INFO', "Running nbtscan...")
        run_and_save(f"nbtscan {target}", f"{outdir}/03_nbtscan.txt", logger, timeout=15)
    
    # NetExec basic
    if check_tool('netexec'):
        logger.log('INFO', "Running NetExec basic scan...")
        run_and_save(f"netexec smb {target}", f"{outdir}/04_netexec_basic.txt", logger, timeout=15)
        run_and_save(f"netexec smb {target} -u guest -p '' --shares", 
                    f"{outdir}/05_netexec_guest_shares.txt", logger, timeout=15)
    
    # SMBClient null/guest
    if check_tool('smbclient'):
        logger.log('INFO', "Testing SMB null/guest sessions...")
        run_and_save(f"smbclient -N -L //{target}/", f"{outdir}/06_smbclient_null_shares.txt", 
                    logger, timeout=15)
        run_and_save(f"smbclient -L //{target}/ -U guest%", 
                    f"{outdir}/07_smbclient_guest_shares.txt", logger, timeout=15)
    
    logger.log('SUCCESS', "Stage 1 completed")

def auto_decision(outdir, logger):
    """Auto-decision: Is SMB worth deeper enumeration?"""
    print()
    print(f"{Colors.YELLOW}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.YELLOW}║  Auto-Decision: Evaluating SMB Value                     ║{Colors.NC}")
    print(f"{Colors.YELLOW}╚{'═' * 58}╝{Colors.NC}")
    
    score = 0
    reasons = []
    
    # Check for accessible shares
    if file_contains(f"{outdir}/05_netexec_guest_shares.txt", ['read', 'write', 'rw']):
        score += 3
        reasons.append("Accessible SMB shares detected")
        logger.log('CRITICAL', "Found accessible SMB shares!")
    
    # Check SMB signing
    if file_contains(f"{outdir}/04_netexec_basic.txt", ['signing: false', 'signing:false']):
        score += 3
        reasons.append("SMB signing is disabled")
        logger.log('CRITICAL', "SMB signing disabled - relay attacks possible!")
    
    # Check for user enumeration
    if file_contains(f"{outdir}/01_nmap_basic_enum.txt", ['user', 'domain']):
        score += 2
        reasons.append("Users/domain information found")
        logger.log('SUCCESS', "User/domain enumeration successful")
    
    # Check OS fingerprint
    if file_contains(f"{outdir}/01_nmap_basic_enum.txt", ['windows', 'os']):
        score += 1
        reasons.append("OS fingerprinted successfully")
        logger.log('INFO', "OS fingerprint obtained")
    
    # Display results
    print()
    logger.log('DECISION', f"SMB Value Score: {score}/9")
    
    if reasons:
        for reason in reasons:
            logger.log('INFO', f"  • {reason}")
    
    if score < 3:
        logger.log('WARNING', "SMB appears low value")
        logger.log('WARNING', "Recommendation: Focus on other services (HTTP/RPC/etc)")
        return False
    
    logger.log('SUCCESS', f"SMB looks valuable (score: {score}/9)")
    logger.log('DECISION', "Proceeding with deeper enumeration...")
    return True

def stage2_standard_enum(target, outdir, logger):
    """Stage 2: Standard SMB enumeration (MEDIUM)"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Stage 2: Standard SMB Enumeration (MEDIUM)              ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    # SMBMap
    if check_tool('smbmap'):
        logger.log('INFO', "Running smbmap...")
        run_and_save(f"smbmap -H {target}", f"{outdir}/08_smbmap_null.txt", logger, timeout=20)
        run_and_save(f"smbmap -H {target} -u guest -p ''", 
                    f"{outdir}/09_smbmap_guest.txt", logger, timeout=20)
    
    # RPC Client enumeration
    if check_tool('rpcclient'):
        logger.log('INFO', "Running RPC client enumeration...")
        
        rpc_commands = {
            'srvinfo': 'Server information',
            'enumdomains': 'Domain enumeration',
            'enumdomusers': 'User enumeration',
            'netshareenumall': 'Share enumeration',
            'lsaquery': 'LSA query',
            'getdompwinfo': 'Password policy'
        }
        
        for i, (cmd_name, desc) in enumerate(rpc_commands.items(), start=10):
            logger.log('INFO', f"RPC: {desc}...")
            run_and_save(f"rpcclient -U '' {target} -c '{cmd_name}'",
                        f"{outdir}/{i:02d}_rpc_{cmd_name}.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Stage 2 completed")

def stage3_heavy_enum(target, smb_ports, outdir, logger):
    """Stage 3: Heavy enumeration (SLOW/NOISY)"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Stage 3: Heavy SMB Enumeration (SLOW/NOISY)             ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    if check_tool('nmap'):
        logger.log('INFO', "Running comprehensive Nmap SMB scripts...")
        cmd = f"nmap -p {smb_ports} --script smb-vuln* {target}"
        run_and_save(cmd, f"{outdir}/16_nmap_smb_vulns.txt", logger, timeout=60)
        
        logger.log('INFO', "Running additional SMB scripts...")
        cmd = f"nmap -p {smb_ports} --script smb-protocols,smb-security-mode,smb-enum-domains {target}"
        run_and_save(cmd, f"{outdir}/17_nmap_smb_additional.txt", logger, timeout=45)
    
    if check_tool('enum4linux'):
        logger.log('INFO', "Running enum4linux (may take time)...")
        run_and_save(f"enum4linux -a {target}", f"{outdir}/18_enum4linux.txt", logger, timeout=1200)
    
    if check_tool('enum4linux-ng'):
        logger.log('INFO', "Running enum4linux-ng...")
        run_and_save(f"enum4linux-ng -A {target}", f"{outdir}/19_enum4linux_ng.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Stage 3 completed")

def stage4_impacket(target, outdir, logger):
    """Stage 4: Impacket tools"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Stage 4: Impacket Enumeration                           ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    if check_tool('samrdump.py'):
        logger.log('INFO', "Running samrdump.py...")
        run_and_save(f"samrdump.py -no-pass {target}", 
                    f"{outdir}/21_impacket_samrdump.txt", logger, timeout=20)
    
    if check_tool('lookupsid.py'):
        logger.log('INFO', "Running lookupsid.py...")
        run_and_save(f"lookupsid.py -no-pass {target}", 
                    f"{outdir}/22_impacket_lookupsid.txt", logger, timeout=20)
    
    logger.log('SUCCESS', "Stage 4 completed")

def stage5_share_probing(target, outdir, logger):
    """Stage 5: Common share probing"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Stage 5: Common Share Probing                           ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    common_shares = ["Public", "Shared", "anonymous", "IPC$", "ADMIN$", "C$", 
                     "Users", "Share", "Data", "Backup"]
    
    if not check_tool('smbclient'):
        logger.log('WARNING', "smbclient not found")
        return
    
    logger.log('INFO', f"Probing {len(common_shares)} common shares...")
    
    found_shares = []
    for share in common_shares:
        cmd = f"smbclient //{target}/{share} -N -c 'ls' 2>&1"
        result = run_and_save(cmd, f"{outdir}/23_smbclient_ls_{share}.txt", 
                           logger, timeout=10)
        
        # Check if successful
        if result and not file_contains(f"{outdir}/23_smbclient_ls_{share}.txt", 
                                       ['failed', 'error', 'denied']):
            found_shares.append(share)
            logger.log('SUCCESS', f"Accessible share: {share}")
    
    if found_shares:
        logger.log('CRITICAL', f"Found {len(found_shares)} accessible share(s)!")
    
    logger.log('SUCCESS', "Stage 5 completed")

def generate_summary(target, port, outdir, logger, smb_value):
    """Generate comprehensive summary"""
    print()
    print(f"{Colors.CYAN}╔{'═' * 58}╗{Colors.NC}")
    print(f"{Colors.CYAN}║  Generating Summary Report                               ║{Colors.NC}")
    print(f"{Colors.CYAN}╚{'═' * 58}╝{Colors.NC}")
    
    summary_text = f"""{'=' * 70}
SMB Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🎯 SMB Value Assessment:
{'-' * 70}
Value Status: {'HIGH VALUE ⚠️' if smb_value else 'Low Value'}
Enumeration Depth: {'Full (5 stages)' if smb_value else 'Basic (1 stage only)'}

🔍 Key Findings:
{'-' * 70}
"""
    
    findings = []
    
    # Check accessible shares
    if file_contains(f"{outdir}/05_netexec_guest_shares.txt", ['read', 'write']):
        findings.append("⚠️  CRITICAL: Accessible SMB shares found")
    
    # Check SMB signing
    if file_contains(f"{outdir}/04_netexec_basic.txt", ['signing: false']):
        findings.append("⚠️  CRITICAL: SMB signing disabled (relay attacks possible)")
    
    # Check for vulnerabilities
    vuln_file = Path(outdir) / "results" / "plain_text" / "16_nmap_smb_vulns.txt"
    if vuln_file.exists():
        if file_contains(f"{outdir}/16_nmap_smb_vulns.txt", ['vulnerable', 'likely vulnerable']):
            findings.append("⚠️  WARNING: Potential SMB vulnerabilities detected")
    
    if findings:
        for finding in findings:
            summary_text += f"{finding}\n"
    else:
        summary_text += "✓ No critical issues detected in quick scan\n"
    
    summary_text += f"""
📋 Enumeration Stages:
{'-' * 70}
✓ Stage 1: Quick enumeration (FAST)
"""
    
    if smb_value:
        summary_text += """✓ Stage 2: Standard enumeration (MEDIUM)
✓ Stage 3: Heavy enumeration (SLOW/NOISY)
✓ Stage 4: Impacket tools
✓ Stage 5: Share probing
"""
    else:
        summary_text += "✗ Stages 2-5: Skipped (low SMB value)\n"
    
    summary_text += f"""
Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
🛡️  Security Recommendations:
{'-' * 70}
  1. Enable SMB signing (mandatory if possible)
  2. Disable SMBv1 protocol
  3. Restrict guest access
  4. Use strong passwords
  5. Implement network segmentation
  6. Regular security updates
  7. Monitor SMB traffic
  8. Use firewall rules

{'=' * 70}
🔧 Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'netexec', 'smbclient', 'smbmap', 'rpcclient', 
            'nmblookup', 'nbtscan', 'samrdump.py', 'lookupsid.py']
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
    
    # Determine SMB ports
    if port in ["139", "445"]:
        smb_ports = port
    else:
        smb_ports = "139,445"
    
    # Setup
    Path(outdir).mkdir(parents=True, exist_ok=True)
    logger = Logger(f"{outdir}/smb_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}")
    logger.log('INFO', f"SMB Ports: {smb_ports}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Stage 1: Quick enumeration (always run)
    stage1_quick_enum(target, smb_ports, outdir, logger)
    
    # Auto-decision: Continue or stop?
    smb_value = auto_decision(outdir, logger)
    
    if smb_value:
        # Continue with deeper enumeration
        stage2_standard_enum(target, outdir, logger)
        stage3_heavy_enum(target, smb_ports, outdir, logger)
        stage4_impacket(target, outdir, logger)
        stage5_share_probing(target, outdir, logger)
    else:
        logger.log('INFO', "Skipping stages 2-5 due to low SMB value")
    
    # Generate summary
    generate_summary(target, port, outdir, logger, smb_value)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ SMB Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    print(f"{Colors.CYAN}💡 Each file contains the command at the top!{Colors.NC}")
    
    if smb_value:
        print()
        print(f"{Colors.YELLOW}⚠️  High-value SMB target - Review all findings!{Colors.NC}")
    
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