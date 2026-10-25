#!/usr/bin/env python3
"""
NFS Enumeration Script - Enhanced Edition with Dual Output
Comprehensive NFS/Network File System reconnaissance and exploitation
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
    print("║          NFS Enumeration - Enhanced Edition               ║")
    print("║          Network File System Security Assessment           ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_nmap_scan(target, port, outdir, logger):
    """Basic Nmap reconnaissance"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Nmap Reconnaissance{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap service detection...")
    
    cmd = f"nmap -p 111,2049 -sV -sC {target}"
    run_and_save(cmd, f"{outdir}/nmap_basic.txt", logger, timeout=60)
    
    logger.log('SUCCESS', "Nmap scan completed")

def phase2_rpc_enumeration(target, outdir, logger):
    """RPC service enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 2] RPC Service Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('rpcinfo'):
        logger.log('WARNING', "rpcinfo not found")
        return
    
    logger.log('INFO', "Enumerating RPC services...")
    
    cmd = f"rpcinfo -p {target}"
    run_and_save(cmd, f"{outdir}/rpcinfo.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "RPC enumeration completed")

def phase3_nfs_enumeration(target, outdir, logger):
    """NFS-specific enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 3] NFS Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found, skipping NSE scripts")
    else:
        logger.log('INFO', "Running Nmap NFS scripts...")
        
        cmd = f"nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount {target}"
        run_and_save(cmd, f"{outdir}/nmap_nfs_scripts.txt", logger, timeout=90)
        
        logger.log('SUCCESS', "Nmap NFS scripts completed")

def phase4_showmount(target, outdir, logger):
    """Show mounted exports"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Export Discovery{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('showmount'):
        logger.log('WARNING', "showmount not found")
        return []
    
    logger.log('INFO', "Discovering NFS exports...")
    
    cmd = f"showmount -e {target}"
    success, stdout, _ = run_and_save(cmd, f"{outdir}/showmount_exports.txt", logger, timeout=30)
    
    if not success:
        logger.log('WARNING', "showmount failed or no exports found")
        return []
    
    # Parse exports
    exports = []
    
    if stdout:
        for line in stdout.split('\n'):
            if line.strip().startswith("/"):
                share = line.split()[0]
                exports.append(share)
                logger.log('SUCCESS', f"Found export: {share}")
    
    return exports

def phase5_netexec(target, outdir, logger):
    """NetExec NFS enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 5] NetExec Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('netexec'):
        logger.log('INFO', "NetExec not found - skipping")
        return
    
    logger.log('INFO', "Running NetExec NFS enumeration...")
    
    cmd = f"netexec nfs {target} --shares"
    run_and_save(cmd, f"{outdir}/netexec_shares.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "NetExec completed")

def phase6_mount_and_explore(target, exports, outdir, logger, mount_base):
    """Mount exports and explore"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Mount & Exploration{Colors.NC}")
    print("=" * 60)
    
    if not exports:
        logger.log('WARNING', "No exports to mount")
        return []
    
    if not check_tool('mount'):
        logger.log('WARNING', "mount command not found")
        return []
    
    loot_found = []
    
    for share in exports:
        safe_name = share.replace("/", "_").strip("_")
        mount_point = os.path.join(mount_base, safe_name)
        
        logger.log('INFO', f"Mounting: {share}")
        
        try:
            os.makedirs(mount_point, exist_ok=True)
            
            # Mount
            mount_cmd = f"mount -t nfs -o vers=3,soft,nolock,proto=tcp,timeo=5,retrans=1 {target}:{share} {mount_point}"
            
            result = subprocess.run(
                mount_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.log('SUCCESS', f"Mounted: {mount_point}")
                
                # Save mount info
                mount_info = f"Share: {share}\nMount point: {mount_point}\nStatus: SUCCESS\n"
                save_dual_output(mount_info, f"{outdir}/mount_{safe_name}.txt", mount_cmd)
                
                time.sleep(1)
                
                # List files
                logger.log('INFO', "Listing files...")
                cmd = f"ls -la {mount_point}"
                run_and_save(cmd, f"{outdir}/{safe_name}_ls_la.txt", logger, timeout=10)
                
                cmd = f"ls -ln {mount_point}"
                run_and_save(cmd, f"{outdir}/{safe_name}_ls_ln.txt", logger, timeout=10)
                
                # Search for sensitive files
                logger.log('INFO', "Searching for sensitive files...")
                
                sensitive_files = {
                    'ssh_keys': ['authorized_keys', 'id_rsa', 'id_ed25519'],
                    'passwd_shadow': ['passwd', 'shadow'],
                    'cron': ['cron*'],
                    'backups': ['*backup*', '*.bak', '*.sql', '*.zip']
                }
                
                for category, patterns in sensitive_files.items():
                    pattern_str = ' -o '.join([f"-name '{p}'" for p in patterns])
                    cmd = f"find {mount_point} {pattern_str} 2>/dev/null"
                    
                    success, stdout, _ = run_command(cmd, logger, timeout=30)
                    
                    if success and stdout.strip():
                        save_dual_output(stdout, f"{outdir}/{safe_name}_{category}.txt", cmd)
                        
                        files = stdout.strip().split('\n')
                        logger.log('CRITICAL', f"Found {len(files)} {category} file(s)!")
                        loot_found.extend(files)
                
                # Unmount
                logger.log('INFO', "Unmounting...")
                cmd = f"umount {mount_point}"
                subprocess.run(cmd, shell=True, timeout=10)
                
            else:
                logger.log('ERROR', f"Failed to mount: {share}")
                
        except Exception as e:
            logger.log('ERROR', f"Mount error for {share}: {str(e)}")
    
    return loot_found

def generate_summary(target, port, exports, loot_found, outdir, logger, mount_base):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
NFS Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

📂 NFS Exports:
{'-' * 70}
"""
    
    if exports:
        summary_text += f"Found {len(exports)} export(s):\n"
        for export in exports:
            summary_text += f"  • {export}\n"
    else:
        summary_text += "No exports found\n"
    summary_text += "\n"
    
    # Loot found
    if loot_found:
        summary_text += f"""🔑 Sensitive Files Found:
{'-' * 70}
⚠️  Found {len(loot_found)} sensitive file(s)!
Check individual category files for details:
  • *_ssh_keys.txt
  • *_passwd_shadow.txt
  • *_cron.txt
  • *_backups.txt

"""
    
    # Mount base
    summary_text += f"""📁 Mount Information:
{'-' * 70}
Mount base: {mount_base}

Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Recommendations:
{'-' * 70}
  1. Restrict NFS exports to specific hosts/networks
  2. Use proper permissions (no_root_squash is dangerous)
  3. Enable Kerberos authentication (sec=krb5)
  4. Use NFSv4 for better security
  5. Implement firewall rules
  6. Regular security audits
  7. Monitor access logs

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['nmap', 'rpcinfo', 'showmount', 'mount', 'netexec']
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
    
    mount_base = "/tmp/nfs_mount_auto"
    
    # Setup
    Path(outdir).mkdir(parents=True, exist_ok=True)
    Path(mount_base).mkdir(parents=True, exist_ok=True)
    
    logger = Logger(f"{outdir}/nfs_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    logger.log('INFO', f"Mount base: {mount_base}")
    
    # Execute phases
    phase1_nmap_scan(target, port, outdir, logger)
    phase2_rpc_enumeration(target, outdir, logger)
    phase3_nfs_enumeration(target, outdir, logger)
    exports = phase4_showmount(target, outdir, logger)
    phase5_netexec(target, outdir, logger)
    loot_found = phase6_mount_and_explore(target, exports, outdir, logger, mount_base)
    
    # Generate summary
    generate_summary(target, port, exports, loot_found, outdir, logger, mount_base)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ NFS Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print(f"{Colors.CYAN}🗂️  Mount base: {mount_base}{Colors.NC}")
    
    if loot_found:
        print()
        print(f"{Colors.RED}🔑 CRITICAL: {len(loot_found)} sensitive file(s) found!{Colors.NC}")
        print(f"{Colors.RED}Check *_ssh_keys.txt, *_passwd_shadow.txt, etc.{Colors.NC}")
    
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