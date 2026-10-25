#!/usr/bin/env python3
"""
Redis Enumeration Script - Enhanced Edition with Dual Output
Comprehensive Redis Database reconnaissance and security assessment
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
    print("║          Redis Enumeration - Enhanced Edition             ║")
    print("║          In-Memory Database Security Assessment            ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

def phase1_connection_test(target, port, outdir, logger):
    """Test Redis connection"""
    print()
    print(f"{Colors.CYAN}[Phase 1] Connection & Authentication Test{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('redis-cli'):
        logger.log('WARNING', "redis-cli not found")
        return False
    
    logger.log('INFO', "Testing anonymous connection...")
    
    cmd = f"redis-cli -h {target} -p {port} PING"
    success, stdout, _ = run_and_save(cmd, f"{outdir}/ping_test.txt", logger, timeout=5)
    
    if success and "PONG" in stdout:
        logger.log('CRITICAL', "Anonymous access is ENABLED!")
        
        status_text = "✓ Anonymous connection successful\n⚠️  WARNING: No authentication required!"
        save_dual_output(status_text, f"{outdir}/connection_status.txt", "Connection Status Check")
        
        return True
    else:
        logger.log('INFO', "Authentication required")
        return False

def phase2_info_gathering(target, port, outdir, logger, has_access):
    """Gather Redis information"""
    print()
    print(f"{Colors.CYAN}[Phase 2] Information Gathering{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping info gathering (no access)")
        return
    
    logger.log('INFO', "Retrieving Redis INFO...")
    
    # Get full INFO
    cmd = f"redis-cli -h {target} -p {port} INFO"
    run_and_save(cmd, f"{outdir}/info_all.txt", logger)
    
    # Get specific sections
    sections = ['server', 'clients', 'memory', 'persistence', 'stats', 'replication', 'cpu', 'keyspace']
    
    for section in sections:
        logger.log('INFO', f"Getting INFO {section}...")
        cmd = f"redis-cli -h {target} -p {port} INFO {section}"
        run_and_save(cmd, f"{outdir}/info_{section}.txt", logger, timeout=10)
    
    logger.log('SUCCESS', "Information gathering completed")

def phase3_config_dump(target, port, outdir, logger, has_access):
    """Dump Redis configuration"""
    print()
    print(f"{Colors.CYAN}[Phase 3] Configuration Dump{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping config dump (no access)")
        return
    
    logger.log('INFO', "Retrieving Redis configuration...")
    
    # Get all config
    cmd = f"redis-cli -h {target} -p {port} CONFIG GET '*'"
    run_and_save(cmd, f"{outdir}/config_all.txt", logger)
    
    # Check dangerous configs
    logger.log('INFO', "Checking security configurations...")
    
    security_issues = []
    
    dangerous_configs = ['protected-mode', 'requirepass', 'dir', 'dbfilename']
    
    for config_key in dangerous_configs:
        cmd = f"redis-cli -h {target} -p {port} CONFIG GET {config_key}"
        success, stdout, _ = run_and_save(cmd, f"{outdir}/config_{config_key}.txt", logger, timeout=5)
        
        if success and stdout:
            # Check for issues
            if config_key == 'requirepass' and stdout.count('\n') <= 2:
                security_issues.append("No password set (requirepass)")
                logger.log('CRITICAL', "No password configured!")
            
            if config_key == 'protected-mode' and 'no' in stdout:
                security_issues.append("Protected mode is disabled")
                logger.log('WARNING', "Protected mode disabled!")
    
    # Save security issues
    if security_issues:
        issues_text = "\n".join([f"⚠️  {issue}" for issue in security_issues])
        save_dual_output(issues_text, f"{outdir}/security_issues.txt", "Security Issues Check")

def phase4_key_enumeration(target, port, outdir, logger, has_access):
    """Enumerate Redis keys"""
    print()
    print(f"{Colors.CYAN}[Phase 4] Key Enumeration{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping key enumeration (no access)")
        return
    
    logger.log('INFO', "Enumerating keys...")
    
    # Get database info
    cmd = f"redis-cli -h {target} -p {port} INFO keyspace"
    run_and_save(cmd, f"{outdir}/keyspace.txt", logger, timeout=10)
    
    # Try to get keys (limit to 100 for safety)
    logger.log('INFO', "Sampling keys (limit 100)...")
    cmd = f"redis-cli -h {target} -p {port} --scan --pattern '*' | head -100"
    run_and_save(cmd, f"{outdir}/keys_sample.txt", logger, timeout=30)
    
    # Get some key values (first 10)
    logger.log('INFO', "Sampling key values...")
    
    success, stdout, _ = run_command(
        f"redis-cli -h {target} -p {port} --scan --pattern '*' | head -10",
        logger, timeout=10
    )
    
    if success and stdout:
        keys = stdout.strip().split('\n')
        values_text = ""
        
        for key in keys[:10]:
            if key.strip():
                cmd = f"redis-cli -h {target} -p {port} GET {key}"
                val_success, val_stdout, _ = run_command(cmd, logger, timeout=5)
                if val_success:
                    values_text += f"[{key}]\n{val_stdout}\n\n"
        
        if values_text:
            save_dual_output(values_text, f"{outdir}/key_values_sample.txt", "Key Values Sample")
            logger.log('SUCCESS', f"Sampled {len(keys)} keys")

def phase5_nmap_scripts(target, port, outdir, logger):
    """Run Nmap Redis scripts"""
    print()
    print(f"{Colors.CYAN}[Phase 5] Nmap Redis Scripts{Colors.NC}")
    print("=" * 60)
    
    if not check_tool('nmap'):
        logger.log('WARNING', "Nmap not found")
        return
    
    logger.log('INFO', "Running Nmap Redis scripts...")
    
    cmd = f"nmap -p {port} -sV --script redis-* {target}"
    run_and_save(cmd, f"{outdir}/nmap_redis_scripts.txt", logger, timeout=120)
    
    logger.log('SUCCESS', "Nmap scripts completed")

def phase6_rce_check(target, port, outdir, logger, has_access):
    """Check for RCE possibilities"""
    print()
    print(f"{Colors.CYAN}[Phase 6] RCE Vector Check{Colors.NC}")
    print("=" * 60)
    
    if not has_access:
        logger.log('WARNING', "Skipping RCE check (no access)")
        return
    
    logger.log('INFO', "Checking RCE vectors...")
    
    cmd = f"redis-cli -h {target} -p {port} CONFIG GET dir"
    success, stdout, _ = run_command(cmd, logger, timeout=5)
    
    if success and stdout:
        logger.log('WARNING', "CONFIG SET may be possible!")
        
        rce_text = f"""Potential RCE Vectors:
{'=' * 60}

⚠️  CONFIG SET is available
   This can be used for:
   - Webshell upload (if web dir is writable)
   - Cron job injection
   - SSH key injection

⚠️  Unauthorized data modification
⚠️  Data exfiltration
"""
        save_dual_output(rce_text, f"{outdir}/rce_vectors.txt", "RCE Vector Check")

def generate_summary(target, port, outdir, logger, has_access):
    """Generate summary report"""
    print()
    print(f"{Colors.CYAN}[Generating Summary]{Colors.NC}")
    print("=" * 60)
    
    summary_text = f"""{'=' * 70}
Redis Enumeration Summary - {target}:{port}
Generated: {datetime.now()}
{'=' * 70}

🔐 Access Status:
{'-' * 70}
"""
    
    if has_access:
        summary_text += "⚠️  Anonymous access is ENABLED (CRITICAL!)\n"
    else:
        summary_text += "✓ Authentication required\n"
    summary_text += "\n"
    
    # Security issues
    plain_dir = Path(outdir) / "results" / "plain_text"
    sec_file = plain_dir / "security_issues.txt"
    
    if sec_file.exists():
        summary_text += f"""⚠️  Security Issues:
{'-' * 70}
"""
        with open(sec_file) as f:
            content = f.read()
            if "OUTPUT:" in content:
                output = content.split("OUTPUT:")[1].strip()
                summary_text += output[:300] + "\n\n"
    
    # RCE vectors
    rce_file = plain_dir / "rce_vectors.txt"
    if rce_file.exists():
        summary_text += f"""🚨 RCE Vectors:
{'-' * 70}
RCE may be possible! Check rce_vectors.txt for details

"""
    
    summary_text += f"""Output Directories:
{'-' * 70}
  results/colors/      ← Colored outputs (cat file | less -R)
  results/plain_text/  ← Plain text outputs

{'=' * 70}
Recommendations:
{'-' * 70}
  1. Enable authentication (requirepass)
  2. Enable protected mode
  3. Bind to localhost only (bind 127.0.0.1)
  4. Disable dangerous commands (rename-command)
  5. Use firewall rules
  6. Enable SSL/TLS (Redis 6+)
  7. Regular backups
  8. Monitor for suspicious activity

{'=' * 70}
Tools Used:
{'-' * 70}
"""
    
    tools = ['redis-cli', 'nmap']
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
    logger = Logger(f"{outdir}/redis_enum.log")
    
    banner()
    
    logger.log('INFO', f"Target: {target}:{port}")
    logger.log('INFO', f"Output: {outdir}")
    
    # Execute phases
    has_access = phase1_connection_test(target, port, outdir, logger)
    phase2_info_gathering(target, port, outdir, logger, has_access)
    phase3_config_dump(target, port, outdir, logger, has_access)
    phase4_key_enumeration(target, port, outdir, logger, has_access)
    phase5_nmap_scripts(target, port, outdir, logger)
    phase6_rce_check(target, port, outdir, logger, has_access)
    
    # Generate summary
    generate_summary(target, port, outdir, logger, has_access)
    
    # Final message
    print()
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅ Redis Enumeration Completed ✅{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print()
    print(f"{Colors.CYAN}📁 Main Directory: {outdir}{Colors.NC}")
    print()
    print(f"{Colors.YELLOW}📂 Output Directories:{Colors.NC}")
    print(f"   {outdir}/results/colors/      ← Colored outputs (cat file | less -R)")
    print(f"   {outdir}/results/plain_text/  ← Plain text outputs")
    print()
    
    if has_access:
        print(f"{Colors.RED}⚠️  WARNING: Anonymous access detected!{Colors.NC}")
        print(f"{Colors.RED}⚠️  Check security_issues.txt and rce_vectors.txt{Colors.NC}")
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