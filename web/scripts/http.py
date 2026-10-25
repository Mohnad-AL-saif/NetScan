#!/usr/bin/env python3
"""
HTTP/Web Reconnaissance Script - Deep Scan Edition
Integrates Web Recon Warrior tools with Auto Enum framework

Usage: python3 http.py <IP> <PORT> <PROTO> <OUTDIR>
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
import json
import re

# ─────────────────────────────────────────────
#  Colors
# ─────────────────────────────────────────────
class Colors:
    RED    = '\033[0;31m'
    GREEN  = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE   = '\033[0;34m'
    CYAN   = '\033[0;36m'
    PURPLE = '\033[0;35m'
    NC     = '\033[0m'

# ─────────────────────────────────────────────
#  Logger
# ─────────────────────────────────────────────
class Logger:
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, level, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        icons = {
            'INFO':    f'{Colors.CYAN}[*]{Colors.NC}',
            'SUCCESS': f'{Colors.GREEN}[✓]{Colors.NC}',
            'ERROR':   f'{Colors.RED}[✗]{Colors.NC}',
            'WARNING': f'{Colors.YELLOW}[!]{Colors.NC}',
            'PHASE':   f'{Colors.PURPLE}[►]{Colors.NC}',
        }
        print(f"{icons.get(level, '')} {message}")
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")

# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def check_tool(name):
    return shutil.which(name) is not None

def save_dual_output(content, base_path, cmd):
    path       = Path(base_path)
    parent     = path.parent
    filename   = path.name
    colors_dir = parent / "results" / "colors"
    plain_dir  = parent / "results" / "plain_text"
    colors_dir.mkdir(parents=True, exist_ok=True)
    plain_dir.mkdir(parents=True, exist_ok=True)

    header_plain = ("=" * 70 + "\nCOMMAND:\n" + "=" * 70 + f"\n{cmd}\n" +
                    "=" * 70 + "\n\nOUTPUT:\n" + "=" * 70 + "\n")
    with open(plain_dir / filename, 'w', encoding='utf-8') as f:
        f.write(header_plain)
        f.write(content if content else "[No output]")
        f.write("\n")

    R, Y, G, NC = '\033[0;31m', '\033[1;33m', '\033[0;32m', '\033[0m'
    header_color = (f"{R}{'=' * 70}{NC}\n{R}COMMAND:{NC}\n{R}{'=' * 70}{NC}\n"
                    f"{R}{cmd}{NC}\n{R}{'=' * 70}{NC}\n\n{Y}OUTPUT:{NC}\n"
                    f"{G}{'=' * 70}{NC}\n")
    with open(colors_dir / filename, 'w', encoding='utf-8') as f:
        f.write(header_color)
        f.write(f"{G}{content if content else '[No output]'}{NC}\n")

def run_command(cmd, logger, description=None, timeout=300):
    if description:
        logger.log('INFO', description)
    print(f"\n{'=' * 60}\n{Colors.RED}{cmd}{Colors.NC}\n{'=' * 60}\n")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        if result.stdout:
            print(f"{Colors.GREEN}{result.stdout}{Colors.NC}")
        if result.stderr and result.returncode != 0:
            print(f"{Colors.YELLOW}{result.stderr[:500]}{Colors.NC}")
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logger.log('WARNING', f"Timeout: {cmd[:80]}")
        return False, "", "Timeout"
    except Exception as e:
        logger.log('ERROR', f"Failed: {e}")
        return False, "", str(e)

def run_and_save(cmd, outfile, logger, description=None, timeout=300):
    success, stdout, stderr = run_command(cmd, logger, description, timeout)
    if outfile:
        save_dual_output(stdout if stdout else stderr, outfile, cmd)
    return success, stdout, stderr

def find_wordlist(preference="medium"):
    """Return best available wordlist"""
    lists_medium = [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ]
    lists_common = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    candidates = lists_medium if preference == "medium" else lists_common
    candidates += lists_medium + lists_common  # fallback chain
    for wl in candidates:
        if Path(wl).exists():
            return wl
    return None

def banner():
    print(f"{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        HTTP/Web Reconnaissance  ─  Deep Scan Edition        ║")
    print("║              Automated Web Application Enumeration          ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")

# ─────────────────────────────────────────────
#  Phase 1 – Basic Enumeration
# ─────────────────────────────────────────────
def phase1_basic_enumeration(target, port, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 1] Basic HTTP Enumeration{Colors.NC}\n{'=' * 60}")

    protocol = 'https' if port in ['443', '8443'] else 'http'
    url = f"{protocol}://{target}:{port}"
    logger.log('INFO', f"Target URL: {url}")

    # ── Nmap service + HTTP scripts (with -Pn to avoid ping block) ──
    if check_tool('nmap'):
        scripts = (
            "http-enum,http-headers,http-methods,http-title,http-robots.txt,"
            "http-auth-finder,http-config-backup,http-cors,http-csrf,"
            "http-dombased-xss,http-errors,http-fileupload-exploiter,"
            "http-form-brute,http-generator,http-git,http-grep,"
            "http-internal-ip-disclosure,http-methods,http-open-redirect,"
            "http-php-version,http-put,http-robots.txt,http-security-headers,"
            "http-shellshock,http-sitemap-generator,http-slowloris-check,"
            "http-sql-injection,http-stored-xss,http-svn-enum,"
            "http-trace,http-traceroute,http-userdir-enum,http-vhosts,"
            "http-wordpress-enum,http-xssed,banner"
        )
        cmd = (f"nmap -sV -sC -p {port} -T4 -Pn "
               f"--script '{scripts}' "
               f"-oN {outdir}/nmap_http_deep.txt {target}")
        run_and_save(cmd, f"{outdir}/nmap_http_deep.txt", logger,
                     "Running Nmap deep HTTP scripts (-Pn)...", timeout=300)

    # ── WhatWeb ──
    if check_tool('whatweb'):
        cmd = f"whatweb -a 4 --color=never -v {url}"
        run_and_save(cmd, f"{outdir}/whatweb.txt", logger,
                     "Running WhatWeb (aggression 4)...", timeout=90)

    # ── curl headers (follow redirects, show chain) ──
    cmd = f"curl -skIL --max-redirs 10 {url}"
    run_and_save(cmd, f"{outdir}/headers.txt", logger,
                 "Grabbing HTTP headers (following redirects)...", timeout=30)

    # ── curl full body ──
    cmd = f"curl -skL --max-redirs 10 {url}"
    run_and_save(cmd, f"{outdir}/response.html", logger, timeout=30)

    # ── robots.txt & sitemap ──
    for path in ['robots.txt', 'sitemap.xml', '.well-known/security.txt',
                 'crossdomain.xml', 'clientaccesspolicy.xml']:
        cmd = f"curl -sk {url}/{path}"
        run_and_save(cmd, f"{outdir}/{path.replace('/', '_')}.txt",
                     logger, f"Fetching {path}...", timeout=20)

    # ── Nikto ──
    if check_tool('nikto'):
        cmd = f"nikto -h {url} -maxtime 10m -Format txt -Tuning 123456789abc"
        run_and_save(cmd, f"{outdir}/nikto.txt", logger,
                     "Running Nikto (all tuning options, 10 min max)...", timeout=660)

    return url

# ─────────────────────────────────────────────
#  Phase 2 – Directory & File Fuzzing
# ─────────────────────────────────────────────
def phase2_directory_fuzzing(url, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 2] Directory & File Fuzzing{Colors.NC}\n{'=' * 60}")

    wordlist_med    = find_wordlist("medium")
    wordlist_common = find_wordlist("common")
    wordlist        = wordlist_med or wordlist_common

    if not wordlist:
        logger.log('WARNING', "No wordlist found – skipping directory fuzzing")
        return

    ext = "php,html,txt,bak,old,zip,tar,gz,sql,xml,json,js,asp,aspx,jsp,cfg,conf,log,env"

    # ── GoBuster (dirs + files) ──
    if check_tool('gobuster'):
        cmd = (f"gobuster dir -u {url} -w {wordlist} "
               f"-x {ext} "
               f"-t 30 -q -e -k --no-error "
               f"-o {outdir}/gobuster_dirs.txt")
        run_and_save(cmd, f"{outdir}/gobuster_dirs.txt", logger,
                     f"GoBuster dirs+files with {Path(wordlist).name}...", timeout=900)

        # Second pass: backup/sensitive files
        backup_wl = "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
        if Path(backup_wl).exists():
            cmd = (f"gobuster dir -u {url} -w {backup_wl} "
                   f"-t 30 -q -e -k --no-error "
                   f"-o {outdir}/gobuster_files.txt")
            run_and_save(cmd, f"{outdir}/gobuster_files.txt", logger,
                         "GoBuster raft-medium-files pass...", timeout=600)

    # ── ffuf (fast, recursive) ──
    if check_tool('ffuf'):
        cmd = (f"ffuf -u {url}/FUZZ -w {wordlist} "
               f"-e .{ext.replace(',', ',.')} "
               f"-mc all -fc 404,400 -t 30 -s "
               f"-o {outdir}/ffuf.json -of json")
        run_and_save(cmd, f"{outdir}/ffuf.txt", logger,
                     "ffuf fuzzing (json output)...", timeout=900)

        # Recursive pass if ffuf supports it
        cmd = (f"ffuf -u {url}/FUZZ -w {wordlist} "
               f"-recursion -recursion-depth 3 "
               f"-mc 200,201,204,301,302,307,401,403 "
               f"-t 20 -s -o {outdir}/ffuf_recursive.json -of json")
        run_and_save(cmd, f"{outdir}/ffuf_recursive.txt", logger,
                     "ffuf recursive scan (depth 3)...", timeout=1200)

    # ── Feroxbuster ──
    if check_tool('feroxbuster'):
        cmd = (f"feroxbuster -u {url} -w {wordlist} "
               f"-x {ext} "
               f"-t 30 -d 3 -k -q "
               f"--auto-tune "
               f"-o {outdir}/feroxbuster.txt")
        run_and_save(cmd, f"{outdir}/feroxbuster.txt", logger,
                     "Feroxbuster (depth 3, auto-tune)...", timeout=1200)

# ─────────────────────────────────────────────
#  Phase 3 – CMS Detection & Deep Scan
# ─────────────────────────────────────────────
def phase3_cms_detection(url, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 3] CMS Detection & Deep Scan{Colors.NC}\n{'=' * 60}")

    # ── Detect CMS from whatweb output ──
    cms_detected = None
    whatweb_file = Path(f"{outdir}/whatweb.txt")
    if whatweb_file.exists():
        content = whatweb_file.read_text(errors='ignore').lower()
        if 'wordpress' in content:
            cms_detected = 'wordpress'
        elif 'joomla' in content:
            cms_detected = 'joomla'
        elif 'drupal' in content:
            cms_detected = 'drupal'

    # Fallback: check response HTML
    if not cms_detected:
        html_file = Path(f"{outdir}/response.html")
        if html_file.exists():
            content = html_file.read_text(errors='ignore').lower()
            if 'wp-content' in content or 'wp-includes' in content:
                cms_detected = 'wordpress'
            elif 'joomla' in content:
                cms_detected = 'joomla'
            elif 'drupal' in content or 'drupal.js' in content:
                cms_detected = 'drupal'

    logger.log('INFO', f"CMS detected: {cms_detected or 'Unknown / None'}")

    # ── WordPress ──
    if cms_detected == 'wordpress':
        if check_tool('wpscan'):
            wpscan_api = os.environ.get('WPSCAN_API', '')
            api_flag   = f"--api-token {wpscan_api}" if wpscan_api else ""
            cmd = (f"wpscan --url {url} "
                   f"--enumerate ap,at,cb,dbe,u,tt "
                   f"--plugins-detection aggressive "
                   f"--themes-detection aggressive "
                   f"{api_flag} "
                   f"-o {outdir}/wpscan.txt --format cli-no-colour")
            run_and_save(cmd, f"{outdir}/wpscan.txt", logger,
                         "WPScan (aggressive, enumerate all)...", timeout=600)
        else:
            logger.log('WARNING', "wpscan not found – install: gem install wpscan")

        # WordPress XML-RPC check
        cmd = f"curl -sk -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' {url}/xmlrpc.php"
        run_and_save(cmd, f"{outdir}/wp_xmlrpc.txt", logger,
                     "Checking WordPress XML-RPC...", timeout=20)

    # ── Joomla ──
    elif cms_detected == 'joomla':
        if check_tool('joomscan'):
            cmd = f"joomscan -u {url} -ec --random-agent"
            run_and_save(cmd, f"{outdir}/joomscan.txt", logger,
                         "JoomScan enumeration...", timeout=300)
        else:
            logger.log('WARNING', "joomscan not found")

    # ── Drupal ──
    elif cms_detected == 'drupal':
        if check_tool('droopescan'):
            cmd = f"droopescan scan drupal -u {url} -t 10"
            run_and_save(cmd, f"{outdir}/droopescan.txt", logger,
                         "DroopeScan (Drupal)...", timeout=300)
        else:
            logger.log('WARNING', "droopescan not found")

    # ── Generic: check common admin panels ──
    admin_paths = [
        'admin', 'administrator', 'admin.php', 'admin/login',
        'wp-admin', 'wp-login.php',
        'login', 'login.php', 'signin',
        'manager', 'panel', 'dashboard',
        'phpmyadmin', 'pma', 'dbadmin',
        'cpanel', 'webmail', 'roundcube',
        'console', 'shell.php', 'cmd.php',
        '.git/HEAD', '.env', '.htaccess',
        'config.php', 'configuration.php',
        'backup', 'backup.zip', 'db.sql',
        'README.md', 'CHANGELOG.md', 'composer.json',
        'package.json', 'webpack.config.js',
        'api', 'api/v1', 'api/v2', 'swagger', 'swagger-ui',
        'graphql', 'actuator', 'server-status', 'server-info',
    ]
    logger.log('INFO', "Checking common sensitive paths...")
    found_paths = []
    for p in admin_paths:
        result = subprocess.run(
            f"curl -sk -o /dev/null -w '%{{http_code}}' {url}/{p}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        code = result.stdout.strip()
        if code and code not in ['404', '000']:
            found_paths.append(f"[{code}] {url}/{p}")
            logger.log('SUCCESS', f"Found: [{code}] {url}/{p}")

    if found_paths:
        with open(f"{outdir}/sensitive_paths.txt", 'w') as f:
            f.write("\n".join(found_paths) + "\n")

    return cms_detected

# ─────────────────────────────────────────────
#  Phase 4 – Vulnerability Scanning
# ─────────────────────────────────────────────
# def phase4_vulnerability_scanning(url, outdir, logger):
#     print(f"\n{Colors.CYAN}[Phase 4] Vulnerability Scanning{Colors.NC}\n{'=' * 60}")

#     # ── Nuclei (critical → info) ──
#     if check_tool('nuclei'):
#         logger.log('INFO', "Updating Nuclei templates...")
#         run_command("nuclei -update-templates -silent", logger, timeout=120)

#         cmd = (f"nuclei -u {url} "
#                f"-severity critical,high,medium,low,info "
#                f"-tags cve,exposure,misconfig,takeover,tech,default-login,panel "
#                f"-silent -o {outdir}/nuclei-results.txt")
#         run_and_save(cmd, f"{outdir}/nuclei-results.txt", logger,
#                      "Nuclei (all severities + CVE tags)...", timeout=1200)

#         # Extra: nuclei on discovered paths
#         gobuster_out = Path(f"{outdir}/gobuster_dirs.txt")
#         if gobuster_out.exists():
#             # Extract discovered URLs
#             urls_tmp = f"{outdir}/.nuclei_urls.txt"
#             run_command(
#                 f"grep -oP 'http[^ ]+' {gobuster_out} | sort -u > {urls_tmp}",
#                 logger, timeout=10
#             )
#             if Path(urls_tmp).exists() and Path(urls_tmp).stat().st_size > 0:
#                 cmd = (f"nuclei -l {urls_tmp} "
#                        f"-severity critical,high,medium "
#                        f"-silent -o {outdir}/nuclei-paths.txt")
#                 run_and_save(cmd, f"{outdir}/nuclei-paths.txt", logger,
#                              "Nuclei on discovered paths...", timeout=600)
#     else:
#         logger.log('WARNING', "nuclei not found – install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

#     # ── SQLMap on forms (passive discovery) ──
#     if check_tool('sqlmap'):
#         cmd = (f"sqlmap -u {url} --forms --crawl=3 --level=3 --risk=2 "
#                f"--batch --random-agent --output-dir={outdir}/sqlmap "
#                f"--answers='quit=N' 2>&1 | head -100")
#         run_and_save(cmd, f"{outdir}/sqlmap.txt", logger,
#                      "SQLMap crawl & form injection...", timeout=600)

# ─────────────────────────────────────────────
#  Phase 5 – Subdomain Enumeration
# ─────────────────────────────────────────────
def phase5_subdomain_enumeration(target, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 5] Subdomain Enumeration{Colors.NC}\n{'=' * 60}")

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        logger.log('INFO', "Target is IP – skipping subdomain enumeration")
        return None

    subdomains = set()
    tmp = Path(f"{outdir}/.tmp_subs")
    tmp.mkdir(exist_ok=True)

    tools = {
        'subfinder':  f"subfinder -d {target} -silent -all -o {tmp}/subfinder.txt",
        'assetfinder': f"assetfinder -subs-only {target}",
        'amass':      f"amass enum -passive -d {target} -silent -o {tmp}/amass.txt",
        'findomain':  f"findomain -t {target} -u {tmp}/findomain.txt 2>/dev/null",
    }

    for tool, cmd in tools.items():
        if not check_tool(tool):
            continue
        logger.log('INFO', f"Running {tool}...")
        success, stdout, _ = run_command(cmd, logger, timeout=300)
        # stdout-based tools
        if stdout:
            subdomains.update(l.strip() for l in stdout.split('\n') if l.strip())
        # file-based tools
        for name in ['subfinder', 'amass', 'findomain']:
            fp = tmp / f"{name}.txt"
            if fp.exists():
                subdomains.update(l.strip() for l in fp.read_text().split('\n') if l.strip())

    shutil.rmtree(tmp, ignore_errors=True)

    if subdomains:
        out_file = f"{outdir}/subdomains.txt"
        Path(out_file).write_text("\n".join(sorted(subdomains)) + "\n")
        logger.log('SUCCESS', f"Found {len(subdomains)} unique subdomains → {out_file}")
        return out_file

    logger.log('WARNING', "No subdomains found")
    return None

# ─────────────────────────────────────────────
#  Phase 6 – HTTP Probing on Subdomains
# ─────────────────────────────────────────────
def phase6_http_probing(subdomains_file, outdir, logger):
    if not subdomains_file or not Path(subdomains_file).exists():
        return None
    print(f"\n{Colors.CYAN}[Phase 6] HTTP Probing on Subdomains{Colors.NC}\n{'=' * 60}")

    if check_tool('httpx'):
        httpx_out = f"{outdir}/httpx-subdomains.json"
        cmd = (f"httpx -l {subdomains_file} "
               f"-sc -title -tech-detect -ip -cdn -json "
               f"-silent -o {httpx_out}")
        run_command(cmd, logger, "httpx probing subdomains...", timeout=600)

        live_file = f"{outdir}/live-urls.txt"
        run_command(f"jq -r '.url' {httpx_out} 2>/dev/null | sort -u > {live_file}",
                    logger, timeout=10)
        if Path(live_file).exists():
            count = sum(1 for _ in open(live_file))
            logger.log('SUCCESS', f"Found {count} live HTTP services")
            return live_file
    return None

# ─────────────────────────────────────────────
#  Phase 7 – WAF / CDN Detection
# ─────────────────────────────────────────────
def phase7_waf_detection(url, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 7] WAF / CDN Detection{Colors.NC}\n{'=' * 60}")
    if check_tool('wafw00f'):
        cmd = f"wafw00f -a {url}"
        run_and_save(cmd, f"{outdir}/waf-detection.txt", logger,
                     "wafw00f (detect all WAFs)...", timeout=60)
    else:
        logger.log('WARNING', "wafw00f not found")

# ─────────────────────────────────────────────
#  Phase 8 – SSL/TLS Analysis
# ─────────────────────────────────────────────
def phase8_ssl_analysis(target, port, outdir, logger):
    if port not in ['443', '8443']:
        return
    print(f"\n{Colors.CYAN}[Phase 8] SSL/TLS Analysis{Colors.NC}\n{'=' * 60}")

    if check_tool('sslscan'):
        cmd = f"sslscan --show-certificate {target}:{port}"
        run_and_save(cmd, f"{outdir}/sslscan.txt", logger,
                     "SSLScan (full certificate info)...", timeout=120)

    if check_tool('testssl.sh'):
        cmd = f"testssl.sh --severity LOW {target}:{port}"
        run_and_save(cmd, f"{outdir}/testssl.txt", logger,
                     "testssl.sh (severity LOW+)...", timeout=300)

    # openssl quick check
    cmd = (f"echo | openssl s_client -connect {target}:{port} "
           f"-showcerts 2>/dev/null | openssl x509 -noout -text 2>/dev/null")
    run_and_save(cmd, f"{outdir}/openssl_cert.txt", logger,
                 "OpenSSL certificate details...", timeout=20)

# ─────────────────────────────────────────────
#  Phase 9 – Wayback & JS Analysis
# ─────────────────────────────────────────────
def phase9_wayback_js(target, url, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 9] Wayback Machine & JS Analysis{Colors.NC}\n{'=' * 60}")

    # waybackurls
    if check_tool('waybackurls'):
        wayback_file = f"{outdir}/waybackurls.txt"
        run_command(f"waybackurls {target} | sort -u > {wayback_file}",
                    logger, "Fetching Wayback URLs...", timeout=180)
        if Path(wayback_file).exists():
            count = sum(1 for _ in open(wayback_file))
            logger.log('SUCCESS', f"Wayback: {count} historical URLs")

            # Extract parameters
            run_command(
                f"grep -oP '[?&][a-zA-Z0-9_]+=' {wayback_file} | "
                f"sort -u > {outdir}/wayback_params.txt",
                logger, timeout=10
            )

    # gau
    if check_tool('gau'):
        run_command(f"gau {target} | sort -u > {outdir}/gau-urls.txt",
                    logger, "gau (GetAllUrls)...", timeout=180)

    # JavaScript file discovery & secrets hunting
    if check_tool('gospider'):
        cmd = (f"gospider -s {url} -d 3 -t 10 -q "
               f"-o {outdir}/gospider/ 2>&1")
        run_and_save(cmd, f"{outdir}/gospider.txt", logger,
                     "GoSpider crawling (depth 3)...", timeout=300)

    # Extract JS files from response and scan with LinkFinder / grep
    html_file = Path(f"{outdir}/response.html")
    if html_file.exists():
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']',
                             html_file.read_text(errors='ignore'))
        if js_urls:
            logger.log('INFO', f"Found {len(js_urls)} JS files – checking for secrets...")
            with open(f"{outdir}/js_files.txt", 'w') as jf:
                for js in js_urls:
                    full = js if js.startswith('http') else f"{url}/{js.lstrip('/')}"
                    jf.write(full + "\n")
            # Simple secret patterns in JS
            secrets_file = f"{outdir}/js_secrets.txt"
            run_command(
                f"xargs -a {outdir}/js_files.txt -I{{}} "
                f"curl -sk {{}} | grep -iE "
                f"'(api_key|apikey|secret|password|passwd|token|auth|bearer|aws_|s3_bucket)' "
                f"> {secrets_file} 2>/dev/null",
                logger, "Scanning JS files for secrets...", timeout=120
            )

# ─────────────────────────────────────────────
#  Phase 10 – Screenshot
# ─────────────────────────────────────────────
def phase10_screenshot(url, outdir, logger):
    print(f"\n{Colors.CYAN}[Phase 10] Screenshot Capture{Colors.NC}\n{'=' * 60}")
    ss_dir = Path(f"{outdir}/screenshots")
    ss_dir.mkdir(exist_ok=True)

    if check_tool('eyewitness'):
        cmd = f"eyewitness --web --single {url} -d {ss_dir} --no-prompt 2>&1"
        run_command(cmd, logger, "EyeWitness screenshot...", timeout=120)
    elif check_tool('gowitness'):
        cmd = f"gowitness single {url} --screenshot-path {ss_dir} 2>&1"
        run_command(cmd, logger, "GoWitness screenshot...", timeout=120)
    else:
        # Fallback: cutycapt or wkhtmltoimage
        if check_tool('cutycapt'):
            cmd = f"cutycapt --url={url} --out={ss_dir}/screenshot.png 2>&1"
            run_command(cmd, logger, "CutyCapt screenshot...", timeout=60)
        else:
            logger.log('WARNING', "No screenshot tool found (eyewitness/gowitness/cutycapt)")

# ─────────────────────────────────────────────
#  Summary Report
# ─────────────────────────────────────────────
def generate_summary(target, port, outdir, logger, cms=None):
    print(f"\n{Colors.CYAN}[Generating Summary Report]{Colors.NC}\n{'=' * 60}")
    summary = Path(f"{outdir}/SUMMARY.txt")

    lines = [
        "=" * 70,
        f"HTTP/Web Deep Enumeration Summary – {target}:{port}",
        f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"CMS       : {cms or 'Unknown / Not detected'}",
        "=" * 70, "",
        "Output Files:",
        "-" * 70,
    ]

    for f in sorted(Path(outdir).rglob("*")):
        if f.is_file() and f.suffix in ['.txt', '.html', '.json', '.xml']:
            rel = f.relative_to(outdir)
            lines.append(f"  {str(rel):50} ({f.stat().st_size:,} bytes)")

    lines += ["", "=" * 70, "Tool Availability:", "-" * 70]
    all_tools = [
        'nmap', 'curl', 'whatweb', 'nikto',
        'gobuster', 'feroxbuster', 'ffuf',
        'wpscan', 'joomscan', 'droopescan',
        # 'sqlmap',
        'subfinder', 'assetfinder', 'amass', 'findomain',
        'httpx', 'wafw00f',
        'sslscan', 'testssl.sh',
        'waybackurls', 'gau', 'gospider',
        'eyewitness', 'gowitness',
        # 'nuclei',
    ]

    for t in all_tools:
        status = "✓ Available" if check_tool(t) else "✗ Not found"
        lines.append(f"  {t:25} {status}")

    report = "\n".join(lines) + "\n"
    summary.write_text(report)
    logger.log('SUCCESS', f"Summary saved → {summary}")
    print(f"\n{report}")

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <IP/HOST> <PORT> <PROTO> <OUTDIR>")
        sys.exit(1)

    target, port, proto, outdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    Path(outdir).mkdir(parents=True, exist_ok=True)
    logger = Logger(f"{outdir}/http_enum.log")

    banner()
    logger.log('INFO', f"Target  : {target}:{port}")
    logger.log('INFO', f"Protocol: {proto}")
    logger.log('INFO', f"Output  : {outdir}")
    logger.log('INFO', f"Started : {datetime.now()}")

    start = datetime.now()

    url     = phase1_basic_enumeration(target, port, outdir, logger)
    phase2_directory_fuzzing(url, outdir, logger)
    cms     = phase3_cms_detection(url, outdir, logger)
    # phase4_vulnerability_scanning(url, outdir, logger)
    subs    = phase5_subdomain_enumeration(target, outdir, logger)
    phase6_http_probing(subs, outdir, logger)
    phase7_waf_detection(url, outdir, logger)
    phase8_ssl_analysis(target, port, outdir, logger)
    phase9_wayback_js(target, url, outdir, logger)
    phase10_screenshot(url, outdir, logger)
    generate_summary(target, port, outdir, logger, cms)

    elapsed = datetime.now() - start
    print(f"\n{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"{Colors.GREEN}✅  Deep HTTP Enumeration Completed  ✅{Colors.NC}")
    print(f"{Colors.GREEN}    Total time: {elapsed}{Colors.NC}")
    print(f"{Colors.GREEN}{'=' * 60}{Colors.NC}")
    print(f"\n{Colors.CYAN}📁 Output : {outdir}{Colors.NC}")
    print(f"{Colors.CYAN}📋 Summary: {outdir}/SUMMARY.txt{Colors.NC}")
    print(f"\n{Colors.YELLOW}📂 Organised output:{Colors.NC}")
    print(f"   {outdir}/results/colors/     ← cat file | less -R")
    print(f"   {outdir}/results/plain_text/ ← plain text\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)