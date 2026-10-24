"""
command_generator.py — Generate recommended security commands based on scan results.
Place in: ~/Port_scanner_project/web/command_generator.py (same dir as app.py)
"""
import os
import re
import json


def make_non_interactive(cmd):
    if any(tool in cmd for tool in ['ssh ', 'scp ', 'sftp ', 'ssh-audit']):
        if '-o StrictHostKeyChecking' not in cmd:
            parts = cmd.split(' ', 1)
            cmd = f'{parts[0]} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {parts[1]}'

    if 'nmap' in cmd and 'ssh' in cmd and '--script-args' not in cmd:
        cmd += ' --script-args ssh.timeout=5'

    if 'curl ' in cmd and '--max-time' not in cmd:
        cmd = cmd.replace('curl ', 'curl --max-time 10 -s -k ', 1)

    if 'openssl s_client' in cmd:
        if 'echo' not in cmd:
            cmd = f'echo | {cmd}'
        if '-connect' in cmd and '2>/dev/null' not in cmd:
            cmd += ' 2>/dev/null'

    return cmd

# Path to findings database
FINDINGS_PATH = os.path.join(os.path.dirname(__file__), '..', 'findings', 'port_findings.json')

# Map nmap service names → finding service names
SERVICE_ALIASES = {
    'ssh': ['ssh', 'openssh'],
    'http': ['http', 'https', 'http-proxy', 'http-alt', 'nginx', 'apache', 'tomcat', 'web', 'additional'],
    'ssl/http': ['http', 'https', 'ssl', 'tls', 'nginx', 'apache', 'tomcat', 'web', 'additional'],
    'ssl/https': ['http', 'https', 'ssl', 'tls'],
    'https': ['http', 'https', 'ssl', 'tls'],
    'mysql': ['mysql', 'mariadb'],
    'mongodb': ['mongodb', 'mongo'],
    'redis': ['redis'],
    'postgresql': ['postgresql', 'postgres'],
    'mssql': ['mssql', 'ms-sql', 'microsoft sql'],
    'ftp': ['ftp', 'ftps'],
    'smtp': ['smtp', 'smtps', 'submission'],
    'dns': ['dns', 'domain'],
    'ldap': ['ldap', 'ldaps', 'ad global catalog', 'ad web services'],
    'smb': ['smb', 'microsoft-ds', 'netbios'],
    'rdp': ['rdp', 'ms-wbt-server'],
    'vnc': ['vnc'],
    'telnet': ['telnet'],
    'snmp': ['snmp'],
    'rpcbind': ['rpcbind', 'rpc', 'sunrpc', 'portmapper'],
    'nfs': ['nfs', 'nfsd'],
    'imap': ['imap', 'imaps'],
    'pop3': ['pop3', 'pop3s'],
    'socks': ['socks', 'socks5'],
    'elasticsearch': ['elasticsearch', 'amazon opensearch', 'opensearch'],
    'etcd': ['etcd', 'etcd-client', 'etcd-server'],
    'grpc': ['grpc', 'grpc-web'],
    'rtsp': ['rtsp'],
    'jetdirect': ['jetdirect', 'printer'],
    'ssl/etcd-client?': ['etcd', 'ssl', 'tls'],
    'ssl/etcd-server?': ['etcd', 'ssl', 'tls'],
    'ssl/unknown': ['ssl', 'tls'],
    'ssl/rtsp': ['rtsp', 'ssl', 'tls'],
}

# Port → known services for non-standard ports
PORT_SERVICE_MAP = {
    6443: ['kubernetes', 'k8s api', 'http', 'https', 'ssl', 'tls'],
    10250: ['kubelet', 'kubernetes', 'http', 'https', 'ssl', 'tls'],
    10260: ['kubelet', 'kubernetes'],
    2379: ['etcd', 'ssl', 'tls'],
    2380: ['etcd', 'ssl', 'tls'],
    2381: ['etcd', 'http'],
    9345: ['kubernetes', 'rancher', 'http', 'https', 'ssl', 'tls'],
    9100: ['node exporter', 'prometheus', 'jetdirect'],
    5473: ['calico typha', 'ssl', 'tls'],
    30901: ['grpc'],
    30902: ['http'],
    31031: ['opensearch', 'elasticsearch', 'amazon opensearch', 'http', 'https', 'ssl', 'tls'],
    31032: ['ssl', 'tls'],
    31042: ['mysql', 'mariadb'],
    31061: ['mongodb', 'mongo'],
    31062: ['mongodb', 'mongo'],
    31063: ['mongodb', 'mongo'],
    31081: ['rtsp', 'ssl', 'tls'],
    31002: ['nginx', 'http'],
    31003: ['tomcat', 'http', 'apache tomcat'],
    31501: ['nginx', 'http'],
    31701: ['tomcat', 'http', 'apache tomcat'],
    31801: ['tomcat', 'http', 'apache tomcat', 'ssl', 'tls'],
}

CATEGORY_NAMES = {
    'http_headers': 'HTTP Security Headers',
    'http_exposure': 'HTTP Exposure & Sensitive Files',
    'ssl_tls': 'SSL/TLS Analysis',
    'ssh_config': 'SSH Security',
    'authentication': 'Authentication & Default Credentials',
    'smb': 'SMB / Windows',
    'active_directory': 'Active Directory / LDAP',
    'database': 'Database Security',
    'nosql': 'NoSQL Databases',
    'injection': 'Injection Attacks',
    'info_disclosure': 'Information Disclosure',
    'admin_exposure': 'Admin Panels & Dashboards',
    'dns': 'DNS Security',
    'email': 'Email (SMTP)',
    'ftp': 'FTP Security',
    'rdp': 'Remote Desktop',
    'vnc': 'VNC',
    'container': 'Containers / Kubernetes',
    'cms': 'CMS Detection',
    'web_app': 'Web Application',
    'cors': 'CORS / Cross-Domain',
    'session_mgmt': 'Session Management',
    'path_traversal': 'Path Traversal',
    'telnet': 'Telnet',
    'snmp': 'SNMP',
    'ntp': 'NTP',
    'ics_scada': 'ICS / SCADA',
    'misc': 'Other Checks',
}


def load_findings():
    """Load findings database from JSON file."""
    try:
        with open(FINDINGS_PATH, 'r') as f:
            data = json.load(f)
        return data.get('findings', [])
    except Exception as e:
        print(f"[!] Error loading findings: {e}")
        return []


def get_service_aliases(nmap_service):
    """Get all possible finding service names for a given nmap service name."""
    svc = (nmap_service or '').lower().strip()
    # Direct alias match
    if svc in SERVICE_ALIASES:
        return SERVICE_ALIASES[svc]
    # Strip ssl/ prefix and try again
    if svc.startswith('ssl/'):
        base = svc[4:].rstrip('?')
        aliases = SERVICE_ALIASES.get(base, [base])
        return aliases + ['ssl', 'tls']
    # Strip trailing ? (nmap uncertainty)
    if svc.endswith('?'):
        base = svc.rstrip('?')
        return SERVICE_ALIASES.get(base, [base])
    return [svc]


def get_findings_for_service(findings_db, port, nmap_service, banner=''):
    """Find all matching findings for a given port + service combo."""
    matched = []
    aliases = get_service_aliases(nmap_service)
    port_services = PORT_SERVICE_MAP.get(port, [])
    all_services = set(a.lower() for a in aliases + port_services)

    for finding in findings_db:
        finding_ports = finding.get('port', [])
        finding_svc = (finding.get('service', '') or '').lower()

        # Match by port number
        port_match = port in finding_ports
        # Match by service name
        svc_match = finding_svc in all_services

        if port_match or svc_match:
            matched.append(finding)

    return matched


def generate_commands_for_scan(scan_id, get_db_func):
    """
    Generate recommended commands based on discovered services.
    Returns (commands_list, grouped_dict).
    """
    findings_db = load_findings()
    if not findings_db:
        return [], {}

    conn = get_db_func()
    results = conn.execute(
        'SELECT * FROM scan_results WHERE scan_id=? ORDER BY ip, port',
        (scan_id,)
    ).fetchall()
    conn.close()

    # Deduplicate by (ip, port, service)
    seen_svc = set()
    unique_services = []
    for r in results:
        key = (r['ip'], r['port'], r['service'] or '')
        if key not in seen_svc:
            seen_svc.add(key)
            unique_services.append(dict(r))

    commands = []
    cmd_id = 0
    seen_cmds = set()

    for svc in unique_services:
        ip = svc['ip']
        port = svc['port']
        service = svc.get('service', '') or ''
        banner = svc.get('banner', '') or ''

        matched = get_findings_for_service(findings_db, port, service, banner)

        for finding in matched:
            check = finding.get('check', {})
            raw_cmd = check.get('command', '')
            if not raw_cmd:
                continue

            cmd = make_non_interactive(raw_cmd.replace('{target}', ip).replace('{port}', str(port)))

            # Deduplicate identical commands
            cmd_key = cmd
            if cmd_key in seen_cmds:
                continue
            seen_cmds.add(cmd_key)

            cmd_id += 1
            commands.append({
                'id': cmd_id,
                'finding_id': finding.get('id', ''),
                'tool': cmd.split()[0] if cmd.split() else '',
                'description': finding.get('name', ''),
                'port': port,
                'ip': ip,
                'service': service,
                'command': cmd,
                'category': finding.get('category', 'misc'),
                'severity': finding.get('severity', 'Info'),
                'cvss': finding.get('cvss', 0),
                'check_type': check.get('type', ''),
                'match': check.get('match', ''),
                'no_match': check.get('no_match', ''),
                'header': check.get('header', ''),
            })

    # Group by category
    grouped = {}
    for cmd in commands:
        cat = CATEGORY_NAMES.get(cmd['category'], cmd['category'].replace('_', ' ').title())
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(cmd)

    return commands, grouped


def analyze_command_output(output, cmd_info, scan_id, save_finding_func):
    """
    Analyze command output against the finding's match/no_match pattern.
    Returns list of detected findings.
    """
    findings_detected = []
    check_type = cmd_info.get('check_type', '')
    match_pattern = cmd_info.get('match', '')
    no_match_pattern = cmd_info.get('no_match', '')
    header_name = cmd_info.get('header', '')

    vulnerable = False
    detail = ''

    if check_type in ('command_match', 'nmap_script', 'banner_match'):
        if match_pattern and re.search(re.escape(match_pattern), output, re.IGNORECASE):
            vulnerable = True
            for line in output.splitlines():
                if match_pattern.lower() in line.lower():
                    detail = line.strip()[:500]
                    break

    elif check_type == 'command_no_match':
        if no_match_pattern and not re.search(re.escape(no_match_pattern), output, re.IGNORECASE):
            vulnerable = True
            detail = f'Expected "{no_match_pattern}" not found in output'

    elif check_type == 'http_header_missing':
        if header_name and header_name.lower() not in output.lower():
            vulnerable = True
            detail = f'Header "{header_name}" is missing'

    elif check_type == 'http_header_value':
        if header_name and match_pattern:
            for line in output.splitlines():
                if header_name.lower() in line.lower():
                    if re.search(re.escape(match_pattern), line, re.IGNORECASE):
                        vulnerable = True
                        detail = line.strip()[:500]
                    break

    elif check_type == 'http_get_match':
        if match_pattern and re.search(re.escape(match_pattern), output, re.IGNORECASE):
            vulnerable = True
            for line in output.splitlines():
                if match_pattern.lower() in line.lower():
                    detail = line.strip()[:500]
                    break

    elif check_type == 'http_get_status':
        if match_pattern and match_pattern in output:
            vulnerable = True
            detail = f'Status code {match_pattern} detected'

    elif check_type == 'ssl_check':
        if match_pattern and re.search(re.escape(match_pattern), output, re.IGNORECASE):
            vulnerable = True
            for line in output.splitlines():
                if match_pattern.lower() in line.lower():
                    detail = line.strip()[:500]
                    break
        elif no_match_pattern and not re.search(re.escape(no_match_pattern), output, re.IGNORECASE):
            vulnerable = True
            detail = f'Expected "{no_match_pattern}" not found'

    if vulnerable:
        finding = {
            'ip': cmd_info.get('ip', ''),
            'port': cmd_info.get('port', 0),
            'finding_id': cmd_info.get('finding_id', ''),
            'finding_name': cmd_info.get('description', ''),
            'severity': cmd_info.get('severity', 'Info'),
            'cvss': cmd_info.get('cvss', 0),
            'cve': '',
            'vulnerable': True,
            'detail': detail or 'Vulnerability detected in uploaded output',
            'command': cmd_info.get('command', ''),
            'category': cmd_info.get('category', 'misc'),
        }
        save_finding_func(scan_id, finding)
        findings_detected.append(finding)

    return findings_detected
