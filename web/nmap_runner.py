import os
import subprocess
import re
import xml.etree.ElementTree as ET
import shlex


# ── Scripts to run per service (safe, info-gathering, vuln detection) ──
SERVICE_SCRIPTS = {
    'ssh': {
        'scripts': 'ssh-hostkey,ssh2-enum-algos,sshv1',
        'description': 'SSH key fingerprint, algorithms, SSHv1 check',
    },
    'http': {
        'scripts': (
            'http-title,http-headers,http-methods,http-server-header,'
            'http-robots.txt,http-favicon,http-generator,http-security-headers,'
            'http-cors,http-cookie-flags,http-enum,http-git,http-config-backup,'
            'http-default-accounts,http-webdav-scan,http-auth,'
            'http-php-version,http-devframework,http-internal-ip-disclosure,'
            'http-trace,http-open-redirect,http-shellshock,'
            'http-vuln-cve2017-5638,http-vuln-cve2017-5689,'
            'http-vuln-cve2015-1635,http-vuln-cve2014-3704,'
            'http-vuln-cve2012-1823,http-waf-detect,'
            'http-wordpress-enum,http-drupal-enum'
        ),
        'description': 'HTTP headers, dirs, vulns, CMS detection',
    },
    'ssl': {
        'scripts': (
            'ssl-cert,ssl-enum-ciphers,ssl-date,ssl-dh-params,'
            'ssl-heartbleed,ssl-poodle,ssl-ccs-injection,'
            'ssl-known-key,ssl-cert-intaddr,sslv2,sslv2-drown'
        ),
        'description': 'SSL/TLS cert, ciphers, Heartbleed, POODLE, DROWN',
    },
    'mysql': {
        'scripts': (
            'mysql-info,mysql-empty-password,mysql-enum,'
            'mysql-databases,mysql-users,mysql-variables,'
            'mysql-vuln-cve2012-2122,mysql-audit'
        ),
        'description': 'MySQL version, empty password, users, databases, vulns',
    },
    'mongodb': {
        'scripts': 'mongodb-info,mongodb-databases',
        'description': 'MongoDB version, database listing (no-auth check)',
    },
    'redis': {
        'scripts': 'redis-info',
        'description': 'Redis version, memory, config (no-auth check)',
    },
    'ftp': {
        'scripts': (
            'ftp-anon,ftp-syst,ftp-bounce,'
            'ftp-proftpd-backdoor,ftp-vsftpd-backdoor,'
            'ftp-vuln-cve2010-4221'
        ),
        'description': 'FTP anonymous login, backdoors, vulns',
    },
    'smtp': {
        'scripts': (
            'smtp-commands,smtp-enum-users,smtp-open-relay,'
            'smtp-strangeport,smtp-vuln-cve2010-4344,'
            'smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764'
        ),
        'description': 'SMTP commands, relay, user enum, vulns',
    },
    'smb': {
        'scripts': (
            'smb-os-discovery,smb-protocols,smb-security-mode,'
            'smb-enum-shares,smb-enum-users,smb-enum-sessions,'
            'smb-enum-domains,smb-enum-services,'
            'smb-vuln-ms17-010,smb-vuln-ms08-067,'
            'smb-vuln-ms10-054,smb-vuln-ms10-061,'
            'smb-vuln-conficker,smb-double-pulsar-backdoor,'
            'smb-vuln-cve-2017-7494,smb-vuln-webexec'
        ),
        'description': 'SMB OS, shares, users, EternalBlue, MS08-067',
    },
    'dns': {
        'scripts': (
            'dns-nsid,dns-recursion,dns-zone-transfer,'
            'dns-cache-snoop,dns-random-srcport,dns-random-txid,'
            'dns-srv-enum,dns-service-discovery'
        ),
        'description': 'DNS zone transfer, recursion, cache snoop',
    },
    'snmp': {
        'scripts': (
            'snmp-info,snmp-sysdescr,snmp-interfaces,'
            'snmp-netstat,snmp-processes,'
            'snmp-win32-services,snmp-win32-shares,snmp-win32-software'
        ),
        'description': 'SNMP system info, interfaces, processes',
    },
    'ldap': {
        'scripts': 'ldap-rootdse,ldap-search',
        'description': 'LDAP root DSE, anonymous search',
    },
    'nfs': {
        'scripts': 'nfs-showmount,nfs-ls,nfs-statfs',
        'description': 'NFS exports, file listing, disk stats',
    },
    'rdp': {
        'scripts': 'rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020',
        'description': 'RDP encryption, NTLM info, BlueKeep-style vuln',
    },
    'vnc': {
        'scripts': 'vnc-info,vnc-title,realvnc-auth-bypass',
        'description': 'VNC version, title, auth bypass check',
    },
    'memcached': {
        'scripts': 'memcached-info',
        'description': 'Memcached system info (unauthenticated)',
    },
    'docker': {
        'scripts': 'docker-version',
        'description': 'Docker daemon version',
    },
    'imap': {
        'scripts': 'imap-capabilities,imap-ntlm-info',
        'description': 'IMAP capabilities, NTLM info',
    },
    'pop3': {
        'scripts': 'pop3-capabilities,pop3-ntlm-info',
        'description': 'POP3 capabilities, NTLM info',
    },
    'mqtt': {
        'scripts': 'mqtt-subscribe',
        'description': 'MQTT message sniffing',
    },
    'amqp': {
        'scripts': 'amqp-info',
        'description': 'AMQP (RabbitMQ) server info',
    },
    'couchdb': {
        'scripts': 'couchdb-databases,couchdb-stats',
        'description': 'CouchDB databases listing, stats',
    },
    'rpcbind': {
        'scripts': 'rpcinfo',
        'description': 'RPC registered programs',
    },
}

PORT_TO_SERVICE = {
    22: 'ssh',
    21: 'ftp',
    25: 'smtp', 465: 'smtp', 587: 'smtp',
    53: 'dns',
    80: 'http', 443: 'http', 8080: 'http', 8443: 'http', 8000: 'http', 3000: 'http', 3001: 'http',
    110: 'pop3', 995: 'pop3',
    143: 'imap', 993: 'imap',
    111: 'rpcbind',
    139: 'smb', 445: 'smb',
    161: 'snmp', 162: 'snmp',
    389: 'ldap', 636: 'ldap',
    1433: 'mysql', 3306: 'mysql',
    1883: 'mqtt', 8883: 'mqtt',
    2049: 'nfs',
    3389: 'rdp',
    5432: 'mysql',
    5672: 'amqp', 5671: 'amqp',
    5900: 'vnc', 5901: 'vnc',
    6379: 'redis',
    11211: 'memcached',
    27017: 'mongodb', 27018: 'mongodb', 27019: 'mongodb',
    2375: 'docker', 2376: 'docker',
    5984: 'couchdb',
}


def get_scan_env():
    env = os.environ.copy()
    env['GIT_SSH_COMMAND'] = 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    env['ANSIBLE_HOST_KEY_CHECKING'] = 'False'
    return env


def clean_banner(banner):
    if not banner:
        return banner
    banner = re.sub(r'^syn-ack\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    banner = re.sub(r'^conn-refused\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    banner = re.sub(r'^reset\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    return banner.strip()


def _keyscan_targets(target):
    for t in target.replace(',', ' ').split():
        t = t.strip()
        if t:
            try:
                subprocess.run(
                    f'ssh-keyscan -T 3 {shlex.quote(t)} >> ~/.ssh/known_hosts 2>/dev/null',
                    shell=True, timeout=5, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass


def run_phase1_streaming(target, tcp_args, callback=None, controller=None):
    """Phase 1: Fast TCP port discovery with real-time callback."""
    _keyscan_targets(target)
    cmd = f'sudo nmap {tcp_args} {target}'
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, env=get_scan_env()
    )
    if controller:
        controller.register_nmap(proc.pid)

    open_ports = []
    current_ip = target.split(',')[0].split()[0].strip()

    for line in proc.stdout:
        if controller and controller.should_stop():
            proc.terminate()
            break

        ip_match = re.match(r'^Nmap scan report for (\S+)', line)
        if ip_match:
            found_ip = ip_match.group(1)
            ip_in_parens = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', found_ip)
            if ip_in_parens:
                current_ip = ip_in_parens.group(1)
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', found_ip):
                current_ip = found_ip
            continue

        match = re.match(r'^(\d+)/(\w+)\s+open\s+(\S*)', line)
        if match:
            port_data = {
                'port': int(match.group(1)),
                'protocol': match.group(2),
                'state': 'open',
                'service': match.group(3) or '',
                'banner': '',
                'ip': current_ip,
                'phase': 1
            }
            open_ports.append(port_data)
            if callback:
                callback(port_data)

    proc.wait()
    return open_ports, cmd


def run_phase2(target, ports_list, controller=None):
    """Phase 2: TCP version detection on discovered ports."""
    if not ports_list:
        return [], '', ''

    if 22 in ports_list:
        _keyscan_targets(target)

    ports_csv = ','.join(str(p) for p in ports_list)
    cmd = f'sudo nmap -p{ports_csv} -sV --script "default and not (ssh-auth-methods or ssh-brute or ssh-run or ssh-publickey-acceptance)" --min-rate 5000 -n -Pn -oX - {target}'

    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE, text=True, env=get_scan_env()
    )
    if controller:
        controller.register_nmap(proc.pid)

    stdout, stderr = proc.communicate(input='yes\n' * 20, timeout=600)

    import datetime
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'scan_outputs')
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_target = target.replace(' ', '_').replace(',', '_').replace('/', '-')[:50]

    with open(os.path.join(output_dir, f'scan_{safe_target}_{timestamp}.xml'), 'w') as f:
        f.write(stdout)

    if stderr.strip():
        with open(os.path.join(output_dir, f'scan_{safe_target}_{timestamp}_stderr.txt'), 'w') as f:
            f.write(stderr)

    return parse_nmap_xml(stdout, target), cmd, stdout


def run_udp_phase1(target, udp_args, controller=None):
    """Phase 3: UDP port discovery."""
    cmd = f'sudo nmap {udp_args} {target}'
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, text=True, env=get_scan_env()
    )
    if controller:
        controller.register_nmap(proc.pid)

    open_ports = []
    current_ip = target.split(',')[0].split()[0].strip()

    for line in proc.stdout:
        if controller and controller.should_stop():
            proc.terminate()
            break

        ip_match = re.match(r'^Nmap scan report for (\S+)', line)
        if ip_match:
            found_ip = ip_match.group(1)
            ip_in_parens = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', found_ip)
            if ip_in_parens:
                current_ip = ip_in_parens.group(1)
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', found_ip):
                current_ip = found_ip
            continue

        match = re.match(r'^(\d+)/(\w+)\s+open\s+(\S*)', line)
        if match:
            open_ports.append({
                'port': int(match.group(1)),
                'protocol': match.group(2),
                'state': 'open',
                'service': match.group(3) or '',
                'banner': '',
                'ip': current_ip,
                'phase': 3
            })

    proc.wait()
    return open_ports, cmd


def run_udp_phase2(target, udp_ports, controller=None):
    """Phase 4: UDP version detection."""
    if not udp_ports:
        return [], '', ''

    ports_csv = ','.join(str(p) for p in udp_ports)
    cmd = f'sudo nmap -sUV -p{ports_csv} --min-rate 3000 -n -Pn -oX - {target}'

    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE, text=True, env=get_scan_env()
    )
    if controller:
        controller.register_nmap(proc.pid)

    stdout, stderr = proc.communicate(input='yes\n' * 20, timeout=600)
    return parse_nmap_xml(stdout, target, default_protocol='udp'), cmd, stdout


def run_service_scripts(target, services_found):
    """Phase 2.5: Run targeted NSE scripts per service type."""
    import datetime

    service_groups = {}
    for svc in services_found:
        port = svc.get('port', 0)
        service_name = (svc.get('service') or '').lower()

        stype = None
        for key in SERVICE_SCRIPTS:
            if key in service_name:
                stype = key
                break
        if not stype:
            banner = (svc.get('banner') or '').lower()
            for key in ['mongodb', 'redis', 'mysql', 'docker', 'memcached', 'couchdb', 'amqp', 'mqtt']:
                if key in banner:
                    stype = key
                    break
        if not stype and ('ssl' in service_name or 'https' in service_name):
            stype = 'ssl'
        if not stype:
            stype = PORT_TO_SERVICE.get(port)

        if stype and stype in SERVICE_SCRIPTS:
            if stype not in service_groups:
                service_groups[stype] = set()
            service_groups[stype].add(port)

    all_script_results = {}
    all_commands_run = []
    raw_outputs = {}

    for stype, ports in service_groups.items():
        scripts = SERVICE_SCRIPTS[stype]['scripts']
        ports_csv = ','.join(str(p) for p in sorted(ports))

        cmd = f'sudo nmap -p{ports_csv} --script "{scripts}" -n -Pn -oX - {target}'
        all_commands_run.append(cmd)

        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                stdin=subprocess.PIPE, text=True, env=get_scan_env()
            )
            stdout, stderr = proc.communicate(input='yes\n' * 10, timeout=300)
            script_results = parse_script_xml(stdout)
            all_script_results.update(script_results)
            raw_outputs[stype] = stdout
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass

    try:
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'scan_outputs')
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace(' ', '_').replace(',', '_').replace('/', '-')[:50]
        log_path = os.path.join(output_dir, f'scripts_{safe_target}_{timestamp}.txt')
        with open(log_path, 'w') as f:
            f.write("# Script scan commands run:\n")
            for c in all_commands_run:
                f.write(f"{c}\n")
            f.write("\n# Results:\n")
            for key, val in all_script_results.items():
                f.write(f"\n## {key}\n{val}\n")
    except Exception:
        pass

    return all_script_results, raw_outputs


def parse_script_xml(xml_str):
    """Parse nmap XML output and extract script results."""
    results = {}
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return results

    for host in root.findall('.//host'):
        ip = ''
        addr = host.find('address')
        if addr is not None:
            ip = addr.get('addr', '')

        for port_el in host.findall('.//port'):
            port_id = port_el.get('portid', '')
            for script in port_el.findall('script'):
                script_id = script.get('id', '')
                output = script.get('output', '')
                key = f"{ip}:{port_id}/{script_id}"
                results[key] = output

        for script in host.findall('.//hostscript/script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            key = f"{ip}/host/{script_id}"
            results[key] = output

    return results


def parse_nmap_xml(xml_string, default_ip='', default_protocol='tcp'):
    """Parse nmap XML output into structured results."""
    results = []
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return results

    for host in root.findall('.//host'):
        addr_el = host.find('.//address[@addrtype="ipv4"]')
        ip = addr_el.get('addr') if addr_el is not None else default_ip

        for port_el in host.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue

            port = int(port_el.get('portid'))
            protocol = port_el.get('protocol', default_protocol)
            service_el = port_el.find('service')
            service = service_el.get('name', '') if service_el is not None else ''
            product = service_el.get('product', '') if service_el is not None else ''
            version = service_el.get('version', '') if service_el is not None else ''
            banner = clean_banner(f"{product} {version}".strip())

            scripts = []
            for script_el in port_el.findall('.//script'):
                scripts.append({
                    'id': script_el.get('id', ''),
                    'output': script_el.get('output', '')
                })

            results.append({
                'ip': ip,
                'port': port,
                'protocol': protocol,
                'state': 'open',
                'service': service,
                'banner': banner,
                'scripts': scripts,
                'phase': 2
            })

    return results


# ═══ Phase 5: Deep Enumeration — script-based ═══

ENUM_SCRIPTS = {
    'ssh': 'scripts/ssh.py',
    'ftp': 'scripts/ftp.py',
    'http': 'scripts/http.py',
    'https': 'scripts/http.py',
    'smb': 'scripts/smb.py',
    'mysql': 'scripts/mysql.py',
    'mssql': 'scripts/mssql.py',
    'redis': 'scripts/redis.py',
    'rdp': 'scripts/rdp.py',
    'snmp': 'scripts/snmp.py',
    'ldap': 'scripts/ldap.py',
    'smtp': 'scripts/smtp.py',
    'vnc': 'scripts/vnc.py',
    'nfs': 'scripts/nfs.py',
    'winrm': 'scripts/winrm.py',
    'pop3': 'scripts/pop3.py',
    'imap': 'scripts/imap.py',
    'squid': 'scripts/squid.py',
    'mongodb': 'scripts/mongodb.py',
    'generic': 'scripts/generic.py',
}

ENUM_PORT_TO_SERVICE = {
    21: 'ftp', 22: 'ssh', 25: 'smtp',
    80: 'http', 110: 'pop3', 111: 'nfs', 139: 'smb', 143: 'imap',
    389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtp', 587: 'smtp',
    636: 'ldap', 993: 'imap', 995: 'pop3',
    1433: 'mssql', 2049: 'nfs', 3128: 'squid', 3306: 'mysql',
    3389: 'rdp',
    5900: 'vnc', 5901: 'vnc', 5902: 'vnc', 5903: 'vnc',
    5985: 'winrm', 5986: 'winrm', 6379: 'redis',
    8080: 'http', 8443: 'https', 8000: 'http', 8888: 'http',
    27017: 'mongodb', 27018: 'mongodb', 27019: 'mongodb',
    161: 'snmp',
}


def run_deep_enumeration(ip, port, proto, service_name, scan_id, update_progress=None):
    """Run the enumeration script for a discovered service.
    Returns list of parsed findings dicts and combined raw output.
    """
    script_key = None
    if service_name:
        svc_lower = service_name.lower()
        for key in ENUM_SCRIPTS:
            if key in svc_lower:
                script_key = key
                break
    if not script_key:
        script_key = ENUM_PORT_TO_SERVICE.get(port)
    if not script_key or script_key not in ENUM_SCRIPTS:
        script_key = 'generic'

    script_path = ENUM_SCRIPTS.get(script_key, 'scripts/generic.py')
    full_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_path)
    if not os.path.exists(full_script_path):
        return [], ''

    outdir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'scan_outputs', str(scan_id), f'{ip}_{port}_{proto}_{script_key}'
    )
    os.makedirs(outdir, exist_ok=True)

    if update_progress:
        update_progress(f"Deep enum: {script_key} on {ip}:{port}")

    try:
        result = subprocess.run(
            ['python3', '-I', full_script_path, ip, str(port), proto, outdir],
            capture_output=True, text=True, timeout=600,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        combined_output = (result.stdout or '') + '\n' + (result.stderr or '')
        findings = parse_script_output(combined_output, outdir, script_key, ip, port, proto)

        if update_progress:
            update_progress(f"Deep enum done: {script_key} on {ip}:{port} — {len(findings)} findings")

        return findings, combined_output.strip()

    except subprocess.TimeoutExpired:
        if update_progress:
            update_progress(f"Deep enum timeout: {script_key} on {ip}:{port}")
        return [], ''
    except Exception as e:
        if update_progress:
            update_progress(f"Deep enum error: {script_key} on {ip}:{port}: {e}")
        return [], ''


def parse_script_output(output, outdir, script_key, ip, port, proto):
    """Parse script output for findings by detecting markers and reading output files."""
    findings = []
    if not output:
        return findings

    for line in output.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        clean = re.sub(r'\033\[[0-9;]*m', '', stripped)

        severity = None
        classification = None
        upper = clean.upper()

        if any(kw in upper for kw in ['VULNERABLE', 'CRITICAL', '[!!!]', 'RCE', 'EXPLOIT']):
            severity = 'Critical'
            classification = 'vulnerable'
        elif any(kw in upper for kw in ['WARNING', '[!]', 'WEAK', 'DEPRECATED', 'ANONYMOUS ACCESS', 'NO AUTH', 'DEFAULT CRED']):
            severity = 'High'
            classification = 'vulnerable'
        elif any(kw in upper for kw in ['[+]', 'SUCCESS', 'FOUND', 'ENABLED', 'ACCESSIBLE']):
            severity = 'Medium'
            classification = 'info'
        elif any(kw in upper for kw in ['[-]', 'DENIED', 'REFUSED', 'FAILED', 'CLOSED', 'FILTERED']):
            severity = 'Low'
            classification = 'safe'

        if severity:
            title = clean[:120]
            for prefix in ['[*] ', '[+] ', '[-] ', '[!] ', '[!!!] ', '[\\u2713] ', '[\\u2717] ']:
                if title.startswith(prefix):
                    title = title[len(prefix):]
                    break

            findings.append({
                'finding_id': f'DEEP-{script_key.upper()}-{len(findings)+1}',
                'finding_name': f'[{script_key.upper()}] {title}',
                'severity': severity,
                'cvss': {'Critical': 9.8, 'High': 7.5, 'Medium': 5.3, 'Low': 3.7}.get(severity, 0),
                'category': f'deep_enum_{script_key}',
                'vulnerable': 1 if classification == 'vulnerable' else 0,
                'detail': clean[:500],
                'command': f'{script_key}.py enumeration',
                'ip': ip,
                'port': port,
                'cve': '',
                'status': classification or 'info',
            })

    results_plain = os.path.join(outdir, 'results', 'plain_text')
    if os.path.isdir(results_plain):
        for fname in sorted(os.listdir(results_plain)):
            fpath = os.path.join(results_plain, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(20000)
                cmd_match = re.search(r'COMMAND:\n={50,}\n(.+?)\n', content)
                command_used = cmd_match.group(1) if cmd_match else fname
                output_match = re.search(r'OUTPUT:\n={50,}\n(.+)', content, re.DOTALL)
                raw_output = output_match.group(1) if output_match else content

                findings.append({
                    'finding_id': f'DEEP-{script_key.upper()}-FILE-{len(findings)+1}',
                    'finding_name': f'[{script_key.upper()}] {fname.replace(".txt", "").replace("_", " ").title()}',
                    'severity': 'Info',
                    'cvss': 0,
                    'category': f'deep_enum_{script_key}',
                    'vulnerable': 0,
                    'detail': raw_output[:500],
                    'command': command_used[:300],
                    'ip': ip,
                    'port': port,
                    'cve': '',
                    'status': 'info',
                })
            except Exception:
                pass

    return findings
