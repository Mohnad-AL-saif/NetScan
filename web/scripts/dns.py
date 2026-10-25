# #!/usr/bin/env python3
# """
# DNS Enumeration Script - Enhanced Edition
# Comprehensive DNS reconnaissance and analysis
# """

# import sys
# import subprocess
# import shutil
# from pathlib import Path
# from datetime import datetime

# # Colors
# class Colors:
#     RED = '\033[0;31m'
#     GREEN = '\033[0;32m'
#     YELLOW = '\033[1;33m'
#     CYAN = '\033[0;36m'
#     NC = '\033[0m'

# class Logger:
#     def __init__(self, log_file):
#         self.log_file = log_file
        
#     def log(self, level, message):
#         timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#         colors = {
#             'INFO': f'{Colors.CYAN}[*]{Colors.NC}',
#             'SUCCESS': f'{Colors.GREEN}[✓]{Colors.NC}',
#             'ERROR': f'{Colors.RED}[✗]{Colors.NC}',
#             'WARNING': f'{Colors.YELLOW}[!]{Colors.NC}'
#         }
#         print(f"{colors.get(level, '')} {message}")
#         with open(self.log_file, 'a') as f:
#             f.write(f"[{timestamp}] [{level}] {message}\n")

# def run_command(cmd, logger, description=None, timeout=120):
#     if description:
#         logger.log('INFO', description)
    
#     # Print command in red
#     print(f"\n{'=' * 60}")
#     print(f"{Colors.RED}{cmd}{Colors.NC}")
#     print(f"{'=' * 60}\n")
    
#     try:
#         result = subprocess.run(cmd, shell=True, capture_output=True, 
#                               text=True, timeout=timeout)
        
#         # Print output in green
#         if result.stdout:
#             print(f"{Colors.GREEN}{result.stdout}{Colors.NC}")
        
#         return result.returncode == 0, result.stdout, result.stderr
#     except subprocess.TimeoutExpired:
#         logger.log('WARNING', f"Timeout: {cmd}")
#         return False, "", "Timeout"
#     except Exception as e:
#         logger.log('ERROR', f"Failed: {str(e)}")
#         return False, "", str(e)

# def check_tool(tool):
#     return shutil.which(tool) is not None

# def banner():
#     print(f"{Colors.CYAN}")
#     print("╔════════════════════════════════════════════════════════════╗")
#     print("║          DNS Enumeration - Advanced Edition               ║")
#     print("║          Comprehensive DNS Reconnaissance                  ║")
#     print("╚════════════════════════════════════════════════════════════╝")
#     print(f"{Colors.NC}")

# def phase1_zone_transfer(target, outdir, logger):
#     """Attempt DNS zone transfer"""
#     print()
#     print(f"{Colors.CYAN}[Phase 1] DNS Zone Transfer Test{Colors.NC}")
#     print("=" * 60)
    
#     # Get nameservers first
#     logger.log('INFO', "Discovering nameservers...")
#     cmd = f"dig +short NS {target}"
#     success, stdout, _ = run_command(cmd, logger)
    
#     nameservers = []
#     if success and stdout:
#         nameservers = [ns.strip().rstrip('.') for ns in stdout.split('\n') if ns.strip()]
#         logger.log('SUCCESS', f"Found {len(nameservers)} nameservers")
        
#         with open(f"{outdir}/nameservers.txt", 'w') as f:
#             for ns in nameservers:
#                 f.write(f"{ns}\n")
    
#     # Try zone transfer on each nameserver
#     zone_transfer_success = False
#     for ns in nameservers:
#         logger.log('INFO', f"Attempting zone transfer from {ns}...")
#         cmd = f"dig @{ns} {target} AXFR"
#         success, stdout, _ = run_command(cmd, logger)
        
#         if success and "XFR size" in stdout:
#             logger.log('SUCCESS', f"Zone transfer successful from {ns}!")
#             zone_transfer_success = True
#             with open(f"{outdir}/zone_transfer_{ns}.txt", 'w') as f:
#                 f.write(stdout)
#         else:
#             logger.log('INFO', f"Zone transfer denied by {ns}")
    
#     if zone_transfer_success:
#         logger.log('SUCCESS', "Zone transfer completed")
#     else:
#         logger.log('INFO', "Zone transfer not allowed (expected)")

# def phase2_record_enumeration(target, outdir, logger):
#     """Enumerate DNS records"""
#     print()
#     print(f"{Colors.CYAN}[Phase 2] DNS Record Enumeration{Colors.NC}")
#     print("=" * 60)
    
#     record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
    
#     all_records = {}
    
#     for record_type in record_types:
#         logger.log('INFO', f"Querying {record_type} records...")
#         cmd = f"dig +short {target} {record_type}"
#         success, stdout, _ = run_command(cmd, logger)
        
#         if success and stdout.strip():
#             records = [r.strip() for r in stdout.split('\n') if r.strip()]
#             all_records[record_type] = records
#             logger.log('SUCCESS', f"Found {len(records)} {record_type} record(s)")
            
#             with open(f"{outdir}/records_{record_type}.txt", 'w') as f:
#                 for record in records:
#                     f.write(f"{record}\n")
#         else:
#             logger.log('INFO', f"No {record_type} records found")
    
#     # Save all records summary
#     with open(f"{outdir}/all_records.txt", 'w') as f:
#         for record_type, records in all_records.items():
#             f.write(f"\n[{record_type} Records]\n")
#             f.write("-" * 40 + "\n")
#             for record in records:
#                 f.write(f"{record}\n")
    
#     return all_records

# def phase3_subdomain_bruteforce(target, outdir, logger):
#     """Subdomain brute force"""
#     print()
#     print(f"{Colors.CYAN}[Phase 3] Subdomain Brute Force{Colors.NC}")
#     print("=" * 60)
    
#     # Check for wordlist
#     wordlists = [
#         "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
#         "/usr/share/wordlists/dnsmap.txt",
#         "/usr/share/amass/wordlists/subdomains.lst"
#     ]
    
#     wordlist = None
#     for wl in wordlists:
#         if Path(wl).exists():
#             wordlist = wl
#             break
    
#     if not wordlist:
#         logger.log('WARNING', "No wordlist found for subdomain brute force")
#         return
    
#     logger.log('INFO', f"Using wordlist: {Path(wordlist).name}")
    
#     # dnsenum
#     if check_tool('dnsenum'):
#         logger.log('INFO', "Running dnsenum...")
#         cmd = f"dnsenum --enum -f {wordlist} {target} -o {outdir}/dnsenum.txt"
#         run_command(cmd, logger, timeout=300)
#         logger.log('SUCCESS', "dnsenum completed")
    
#     # dnsrecon
#     if check_tool('dnsrecon'):
#         logger.log('INFO', "Running dnsrecon...")
#         cmd = f"dnsrecon -d {target} -D {wordlist} -t brt -c {outdir}/dnsrecon.csv"
#         run_command(cmd, logger, timeout=300)
#         logger.log('SUCCESS', "dnsrecon completed")
    
#     # fierce (if available)
#     if check_tool('fierce'):
#         logger.log('INFO', "Running fierce...")
#         cmd = f"fierce --domain {target} --subdomain-file {wordlist} > {outdir}/fierce.txt"
#         run_command(cmd, logger, timeout=300)
#         logger.log('SUCCESS', "fierce completed")

# def phase4_nmap_scripts(target, port, outdir, logger):
#     """Run Nmap DNS scripts"""
#     print()
#     print(f"{Colors.CYAN}[Phase 4] Nmap DNS Scripts{Colors.NC}")
#     print("=" * 60)
    
#     if not check_tool('nmap'):
#         logger.log('WARNING', "Nmap not found")
#         return
    
#     logger.log('INFO', "Running Nmap DNS scripts...")
    
#     scripts = [
#         "dns-zone-transfer",
#         "dns-recursion",
#         "dns-cache-snoop",
#         "dns-nsid",
#         "dns-service-discovery",
#         "dns-brute"
#     ]
    
#     script_list = ",".join(scripts)
#     cmd = f"nmap -p {port} -sU -sV --script {script_list} {target} -oN {outdir}/nmap_dns_scripts.txt"
#     run_command(cmd, logger, timeout=300)
    
#     logger.log('SUCCESS', "Nmap DNS scripts completed")

# def phase5_reverse_dns(target, outdir, logger):
#     """Reverse DNS lookups"""
#     print()
#     print(f"{Colors.CYAN}[Phase 5] Reverse DNS Lookups{Colors.NC}")
#     print("=" * 60)
    
#     # Get IPs from A records
#     logger.log('INFO', "Performing reverse DNS lookups...")
#     cmd = f"dig +short {target} A"
#     success, stdout, _ = run_command(cmd, logger)
    
#     if success and stdout:
#         ips = [ip.strip() for ip in stdout.split('\n') if ip.strip()]
        
#         reverse_results = []
#         for ip in ips:
#             cmd = f"dig +short -x {ip}"
#             success, stdout, _ = run_command(cmd, logger)
#             if success and stdout:
#                 ptr = stdout.strip()
#                 logger.log('SUCCESS', f"{ip} → {ptr}")
#                 reverse_results.append(f"{ip} → {ptr}")
        
#         if reverse_results:
#             with open(f"{outdir}/reverse_dns.txt", 'w') as f:
#                 for result in reverse_results:
#                     f.write(f"{result}\n")

# def phase6_dnssec(target, outdir, logger):
#     """Check DNSSEC"""
#     print()
#     print(f"{Colors.CYAN}[Phase 6] DNSSEC Analysis{Colors.NC}")
#     print("=" * 60)
    
#     logger.log('INFO', "Checking DNSSEC status...")
    
#     # Check for DNSKEY records
#     cmd = f"dig +dnssec {target} DNSKEY"
#     success, stdout, _ = run_command(cmd, logger)
    
#     if success:
#         with open(f"{outdir}/dnssec.txt", 'w') as f:
#             f.write(stdout)
        
#         if "RRSIG" in stdout:
#             logger.log('SUCCESS', "DNSSEC is enabled")
#         else:
#             logger.log('INFO', "DNSSEC is not enabled")

# def phase7_additional_tools(target, outdir, logger):
#     """Run additional DNS tools"""
#     print()
#     print(f"{Colors.CYAN}[Phase 7] Additional DNS Tools{Colors.NC}")
#     print("=" * 60)
    
#     # host command
#     logger.log('INFO', "Running host command...")
#     cmd = f"host -a {target}"
#     success, stdout, _ = run_command(cmd, logger)
#     if success:
#         with open(f"{outdir}/host_output.txt", 'w') as f:
#             f.write(stdout)
    
#     # nslookup
#     logger.log('INFO', "Running nslookup...")
#     cmd = f"nslookup {target}"
#     success, stdout, _ = run_command(cmd, logger)
#     if success:
#         with open(f"{outdir}/nslookup_output.txt", 'w') as f:
#             f.write(stdout)
    
#     # whois
#     if check_tool('whois'):
#         logger.log('INFO', "Running whois...")
#         cmd = f"whois {target}"
#         success, stdout, _ = run_command(cmd, logger, timeout=60)
#         if success:
#             with open(f"{outdir}/whois.txt", 'w') as f:
#                 f.write(stdout)

# def generate_summary(target, port, outdir, logger):
#     """Generate summary report"""
#     print()
#     print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
#     print("=" * 60)
    
#     summary_file = f"{outdir}/SUMMARY.txt"
    
#     with open(summary_file, 'w') as f:
#         f.write("=" * 70 + "\n")
#         f.write(f"DNS Enumeration Summary - {target}:{port}\n")
#         f.write(f"Generated: {datetime.now()}\n")
#         f.write("=" * 70 + "\n\n")
        
#         # List output files
#         f.write("Output Files:\n")
#         f.write("-" * 70 + "\n")
#         for file in sorted(Path(outdir).glob("*.txt")):
#             if file.is_file():
#                 size = file.stat().st_size
#                 f.write(f"  {file.name:40} ({size:,} bytes)\n")
        
#         f.write("\n" + "=" * 70 + "\n")
#         f.write("Key Findings:\n")
#         f.write("-" * 70 + "\n")
        
#         # Check for important findings
#         if Path(f"{outdir}/zone_transfer_*.txt").exists():
#             f.write("  ⚠️  Zone transfer was successful!\n")
        
#         if Path(f"{outdir}/nameservers.txt").exists():
#             with open(f"{outdir}/nameservers.txt") as ns_file:
#                 ns_count = sum(1 for _ in ns_file)
#                 f.write(f"  ✓  Found {ns_count} nameserver(s)\n")
        
#         # Count record types
#         for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
#             record_file = Path(f"{outdir}/records_{record_type}.txt")
#             if record_file.exists():
#                 with open(record_file) as rf:
#                     count = sum(1 for _ in rf)
#                     f.write(f"  ✓  {record_type} records: {count}\n")
    
#     logger.log('SUCCESS', f"Summary saved to: {summary_file}")
    
#     # Display summary
#     with open(summary_file) as f:
#         print()
#         print(f.read())

# def main():
#     if len(sys.argv) != 5:
#         print(f"Usage: {sys.argv[0]} <IP> <PORT> <PROTO> <OUTDIR>")
#         sys.exit(1)
    
#     target = sys.argv[1]
#     port = sys.argv[2]
#     proto = sys.argv[3]
#     outdir = sys.argv[4]
    
#     # Setup
#     Path(outdir).mkdir(parents=True, exist_ok=True)
#     log_file = f"{outdir}/dns_enum.log"
#     logger = Logger(log_file)
    
#     banner()
    
#     logger.log('INFO', f"Target: {target}:{port}")
#     logger.log('INFO', f"Output: {outdir}")
    
#     # Execute phases
#     phase1_zone_transfer(target, outdir, logger)
#     phase2_record_enumeration(target, outdir, logger)
#     phase3_subdomain_bruteforce(target, outdir, logger)
#     phase4_nmap_scripts(target, port, outdir, logger)
#     phase5_reverse_dns(target, outdir, logger)
#     phase6_dnssec(target, outdir, logger)
#     phase7_additional_tools(target, outdir, logger)
    
#     # Generate summary
#     generate_summary(target, port, outdir, logger)
    
#     # Final message
#     print()
#     print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
#     print(f"{Colors.GREEN}✅ DNS Enumeration Completed Successfully ✅{Colors.NC}")
#     print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
#     print()
#     print(f"{Colors.CYAN}📁 Results: {outdir}{Colors.NC}")
#     print(f"{Colors.CYAN}📋 Summary: {outdir}/SUMMARY.txt{Colors.NC}")
#     print()

# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print(f"\n{Colors.RED}[!] Interrupted by user{Colors.NC}")
#         sys.exit(130)
#     except Exception as e:
#         print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.NC}")
#         import traceback
#         traceback.print_exc()
#         sys.exit(1)