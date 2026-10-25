#!/usr/bin/env python3
"""
SNMP Enumeration Script - Enhanced Edition
Comprehensive SNMP Security Assessment
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

def run_command(cmd, outfile, logger, description=None, timeout=60):
    if description:
        logger.log('INFO', description)
    
    # Print command in red
    print(f"\n{'=' * 60}")
    print(f"{Colors.RED}{cmd}{Colors.NC}")
    print(f"{'=' * 60}\n")
    
    try:
        with open(outfile, 'w') as f:
            result = subprocess.run(cmd, shell=True, stdout=f,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        
        # Print output in green
        with open(outfile, 'r') as f:
            output = f.read()
            if output:
                print(f"{Colors.GREEN}{output}{Colors.NC}")
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.log('WARNING', f"Timeout after {timeout}s")
        return False
    except Exception as e:
        logger.log('ERROR', f"Failed: {str(e)}")
        return False

def check_tool(tool):
    return shutil.which(tool) is not None

def banner():
    print(f"{Colors.PURPLE}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          SNMP Enumeration - Enhanced Edition              ║")
    print("║          Network Management Protocol Assessment            ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_service_check(target, port, outdir, logger):
    """Phase 1: SNMP service check"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Service Detection{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Checking SNMP service...")
    run_command(f"nmap -sU -p {port} -sV {target}",
               f"{outdir}/01_nmap_service.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Phase 1 completed")

def phase2_community_brute(target, port, outdir, logger):
    """Phase 2: Community string brute force"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Community String Brute Force{Colors.NC}")
    print("=" * 60)
    
    # Check for wordlist
    wordlists = [
        "/usr/share/seclists/Discovery/SNMP/snmp.txt",
        "/usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt",
        "/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt"
    ]
    
    community_list = None
    for wl in wordlists:
        if Path(wl).exists():
            community_list = wl
            break
    
    if not community_list:
        logger.log('WARNING', "No SNMP wordlist found, creating basic list...")
        community_list = f"{outdir}/snmp_communities.txt"
        with open(community_list, 'w') as f:
            f.write("\n".join(["public", "private", "community", "manager", 
                              "read", "write", "admin", "secret"]))
    
    logger.log('INFO', f"Using wordlist: {community_list}")
    
    # onesixtyone
    if check_tool('onesixtyone'):
        logger.log('INFO', "Running onesixtyone brute force...")
        run_command(f"onesixtyone -c {community_list} {target}",
                   f"{outdir}/02_onesixtyone_brute.txt", logger, timeout=60)
    else:
        logger.log('WARNING', "onesixtyone not found")
    
    # Nmap SNMP brute
    if check_tool('nmap'):
        logger.log('INFO', "Running Nmap SNMP brute...")
        cmd = (f"nmap -sU -p {port} --script snmp-brute "
               f"--script-args snmp-brute.communitiesdb={community_list} {target}")
        run_command(cmd, f"{outdir}/03_nmap_snmp_brute.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Phase 2 completed")

def phase3_basic_enum(target, port, outdir, logger):
    """Phase 3: Basic enumeration with 'public'"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Basic Enumeration (public){Colors.NC}")
    print("=" * 60)
    
    if not check_tool('snmpwalk'):
        logger.log('WARNING', "snmpwalk not found")
        return
    
    logger.log('INFO', "Full SNMPwalk with 'public'...")
    run_command(f"snmpwalk -v2c -c public {target}",
               f"{outdir}/04_snmpwalk_public_full.txt", logger, timeout=120)
    
    if check_tool('snmpbulkwalk'):
        logger.log('INFO', "SNMPbulkwalk with 'public'...")
        run_command(f"snmpbulkwalk -v2c -c public {target}",
                   f"{outdir}/05_snmpbulkwalk_public.txt", logger, timeout=120)
    
    if check_tool('snmp-check'):
        logger.log('INFO', "Running snmp-check...")
        run_command(f"snmp-check {target} -c public",
                   f"{outdir}/06_snmp_check_public.txt", logger, timeout=90)
    
    logger.log('SUCCESS', "Phase 3 completed")

def phase4_high_value_oids(target, outdir, logger):
    """Phase 4: High-value OID enumeration"""
    print()
    print(f"{Colors.CYAN}[Phase 4] High-Value OID Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('snmpwalk'):
        logger.log('WARNING', "snmpwalk not found")
        return
    
    logger.log('INFO', "Extracting high-value OIDs...")
    
    oids = {
        'system_info': ('1.3.6.1.2.1.1', 'System information'),
        'hostname': ('1.3.6.1.2.1.1.5', 'Hostname'),
        'users_windows': ('1.3.6.1.4.1.77.1.2.25', 'Windows users'),
        'processes': ('1.3.6.1.2.1.25.4.2.1.2', 'Running processes'),
        'process_paths': ('1.3.6.1.2.1.25.4.2.1.4', 'Process paths'),
        'tcp_ports': ('1.3.6.1.2.1.6.13.1.3', 'Open TCP ports'),
        'udp_ports': ('1.3.6.1.2.1.7.5.1.2', 'Open UDP ports'),
        'installed_software': ('1.3.6.1.2.1.25.6.3.1.2', 'Installed software'),
        'storage_info': ('1.3.6.1.2.1.25.2.3.1.4', 'Storage information'),
        'network_interfaces': ('1.3.6.1.2.1.2.2.1.2', 'Network interfaces'),
        'routing_table': ('1.3.6.1.2.1.4.21.1.1', 'Routing table')
    }
    
    for name, (oid, desc) in oids.items():
        logger.log('INFO', f"Querying: {desc}...")
        run_command(f"snmpwalk -v1 -c public {target} {oid}",
                   f"{outdir}/07_oid_{name}.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Phase 4 completed")

def phase5_extend_mib(target, outdir, logger):
    """Phase 5: Extend-MIB check (RCE vector)"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Extend-MIB Check (RCE Vector){Colors.NC}")
    print("=" * 60)
    
    if not check_tool('snmpwalk'):
        logger.log('WARNING', "snmpwalk not found")
        return
    
    logger.log('WARNING', "Checking for NET-SNMP-EXTEND-MIB (potential RCE)...")
    
    cmd = f"snmpwalk -v2c -c public {target} NET-SNMP-EXTEND-MIB::nsExtendObjects"
    success = run_command(cmd, f"{outdir}/08_extend_mib_check.txt", logger, timeout=30)
    
    if success:
        # Check if anything was found
        with open(f"{outdir}/08_extend_mib_check.txt") as f:
            content = f.read()
            if content.strip() and 'No Such' not in content:
                logger.log('CRITICAL', "Extend-MIB objects found - RCE may be possible!")
    
    logger.log('SUCCESS', "Phase 5 completed")

def phase6_nmap_nse(target, port, outdir, logger):
    """Phase 6: Comprehensive Nmap NSE scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 6] Nmap NSE Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running all SNMP NSE scripts...")
    run_command(f"nmap -sU -p {port} --script snmp-* {target}",
               f"{outdir}/09_nmap_snmp_all.txt", logger, timeout=180)
    
    logger.log('INFO', "Running targeted SNMP scripts...")
    scripts = "snmp-info,snmp-netstat,snmp-processes,snmp-win32-shares,snmp-win32-services"
    run_command(f"nmap -sU -p {port} --script {scripts} {target}",
               f"{outdir}/10_nmap_snmp_targeted.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Phase 6 completed")

def phase7_ipv6_check(target, port, outdir, logger):
    """Phase 7: IPv6 SNMP check"""
    print()
    print(f"{Colors.CYAN}[Phase 7] IPv6 SNMP Check{Colors.NC}")
    print("=" * 60)
    
    logger.log('INFO', "Checking for IPv6 SNMP...")
    
    if check_tool('snmpwalk'):
        # IPv6 interfaces
        run_command(f"snmpwalk -v2c -c public {target} 1.3.6.1.2.1.55",
                   f"{outdir}/11_ipv6_interfaces.txt", logger, timeout=30)
    
    if check_tool('nmap'):
        # IPv6 Nmap scan
        run_command(f"nmap -6 -sU -p {port} --script snmp-info {target}",
                   f"{outdir}/12_ipv6_nmap.txt", logger, timeout=30)
    
    logger.log('SUCCESS', "Phase 7 completed")

def generate_summary(target, port, outdir, logger):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_file = f"{outdir}/SUMMARY.txt"
    
    with open(summary_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write(f"SNMP Enumeration Summary - {target}:{port}\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("=" * 70 + "\n\n")
        
        # Check for findings
        f.write("🔍 Key Findings:\n")
        f.write("-" * 70 + "\n")
        
        findings = []
        
        # Check community strings
        if Path(f"{outdir}/02_onesixtyone_brute.txt").exists():
            with open(f"{outdir}/02_onesixtyone_brute.txt") as comm_file:
                content = comm_file.read()
                if 'public' in content.lower():
                    findings.append("✓ Community string 'public' is valid")
                if 'private' in content.lower():
                    findings.append("⚠️  CRITICAL: Community string 'private' is valid (write access!)")
        
        # Check for Extend-MIB
        if Path(f"{outdir}/08_extend_mib_check.txt").exists():
            with open(f"{outdir}/08_extend_mib_check.txt") as ext_file:
                content = ext_file.read()
                if content.strip() and 'No Such' not in content:
                    findings.append("⚠️  CRITICAL: NET-SNMP-EXTEND-MIB found (RCE vector!)")
        
        # Check for processes
        if Path(f"{outdir}/07_oid_processes.txt").exists():
            with open(f"{outdir}/07_oid_processes.txt") as proc_file:
                lines = [l for l in proc_file.readlines() if l.strip()]
                if len(lines) > 5:
                    findings.append(f"✓ Enumerated {len(lines)} running processes")
        
        # Check for users
        if Path(f"{outdir}/07_oid_users_windows.txt").exists():
            with open(f"{outdir}/07_oid_users_windows.txt") as user_file:
                lines = [l for l in user_file.readlines() if l.strip()]
                if len(lines) > 0:
                    findings.append(f"✓ Enumerated {len(lines)} Windows users")
        
        if findings:
            for finding in findings:
                f.write(f"{finding}\n")
        else:
            f.write("No significant findings\n")
        
        f.write("\n")
        
        # High-value OIDs
        f.write("📊 Information Extracted:\n")
        f.write("-" * 70 + "\n")
        f.write("OIDs queried:\n")
        f.write("  • System information (1.3.6.1.2.1.1)\n")
        f.write("  • Running processes (1.3.6.1.2.1.25.4.2.1.2)\n")
        f.write("  • Open TCP/UDP ports\n")
        f.write("  • Installed software\n")
        f.write("  • Storage information\n")
        f.write("  • Network interfaces\n")
        f.write("  • Routing table\n")
        f.write("\n")
        
        # Output files
        f.write("📂 Output Files:\n")
        f.write("-" * 70 + "\n")
        for file in sorted(Path(outdir).glob("*.txt")):
            if file.is_file():
                size = file.stat().st_size
                f.write(f"  {file.name:45} ({size:,} bytes)\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("🛡️  Recommendations:\n")
        f.write("-" * 70 + "\n")
        f.write("  1. Change default community strings\n")
        f.write("  2. Use SNMPv3 with authentication\n")
        f.write("  3. Restrict SNMP access via ACLs\n")
        f.write("  4. Disable SNMP if not needed\n")
        f.write("  5. Use firewall rules (port 161 UDP)\n")
        f.write("  6. Monitor SNMP traffic\n")
        f.write("  7. Disable write access (private)\n")
        f.write("  8. Review Extend-MIB configurations\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("🔧 Tools Used:\n")
        f.write("-" * 70 + "\n")
        
        tools = ['nmap', 'snmpwalk', 'snmpbulkwalk', 'snmp-check', 'onesixtyone']
        for tool in tools:
            status = "✓ Available" if check_tool(tool) else "✗ Not found"
            f.write(f"  {tool:20} {status}\n")
    
    logger.log('SUCCESS', f"Summary saved: {summary_file}")
    
    with open(summary_file) as f:
        print()
        print(f.read())

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <IP> <PORT> <PROTO> <OUTDIR>")
        sys.exit(1)
    
    target, port, proto, outdir = sys.argv[1:]
    
    Path(outdir).mkdir(parents=True, exist_ok=True)
    logger = Logger(f"{outdir}/snmp_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Protocol: {proto.upper()}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    phase1_service_check(target, port, outdir, logger)
    phase2_community_brute(target, port, outdir, logger)
    phase3_basic_enum(target, port, outdir, logger)
    phase4_high_value_oids(target, outdir, logger)
    phase5_extend_mib(target, outdir, logger)
    phase6_nmap_nse(target, port, outdir, logger)
    phase7_ipv6_check(target, port, outdir, logger)
    
    # Generate summary
    generate_summary(target, port, outdir, logger)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ SNMP Enumeration Completed Successfully ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Results: {outdir}{Colors.NC}")
    print(f"{Colors.CYAN}📋 Summary: {outdir}/SUMMARY.txt{Colors.NC}")
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