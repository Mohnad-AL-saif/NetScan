import subprocess
import json
import re
import os


def load_findings(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), '..', 'findings', 'port_findings.json')
    with open(path) as f:
        return json.load(f)['findings']


SERVICE_ALIASES = {
    'ssh': ['ssh', 'openssh', 'libssh'],
    'http': ['http', 'https', 'http-proxy', 'http-alt', 'ssl/http', 'https-alt'],
    'https': ['http', 'https', 'ssl/http', 'https-alt'],
    'http-proxy': ['http', 'http-proxy'],
    'http-alt': ['http', 'http-alt'],
    'ssl': ['ssl', 'https', 'ssl/http', 'imaps', 'pop3s', 'smtps', 'ldaps'],
    'ftp': ['ftp', 'ftp-data', 'ftps'],
    'microsoft-ds': ['smb', 'microsoft-ds', 'cifs'],
    'netbios-ssn': ['smb', 'netbios-ssn'],
    'mysql': ['mysql', 'mariadb'],
    'postgresql': ['postgresql', 'postgres'],
    'ms-sql-s': ['mssql', 'ms-sql-s', 'ms-sql'],
    'oracle-tns': ['oracle', 'oracle-tns'],
    'smtp': ['smtp', 'smtps', 'submission'],
    'submission': ['smtp', 'submission'],
    'pop3': ['pop3', 'pop3s'],
    'imap': ['imap', 'imaps'],
    'ms-wbt-server': ['rdp', 'ms-wbt-server'],
    'vnc': ['vnc', 'vnc-http'],
    'telnet': ['telnet'],
    'ldap': ['ldap', 'ldaps'],
    'ldaps': ['ldap', 'ldaps'],
    'kerberos-sec': ['kerberos', 'kerberos-sec'],
    'redis': ['redis'],
    'mongodb': ['mongodb', 'mongod'],
    'couchdb': ['couchdb'],
    'cassandra': ['cassandra'],
    'elasticsearch': ['elasticsearch'],
    'domain': ['dns', 'domain'],
    'dns': ['dns', 'domain'],
    'snmp': ['snmp'],
    'ntp': ['ntp'],
    'rpcbind': ['rpcbind', 'nfs'],
    'nfs': ['nfs', 'nfs_acl'],
    'docker': ['docker'],
    'kubernetes': ['kubernetes', 'kubectl'],
    'ajp13': ['ajp', 'ajp13'],
}


def _service_matches(nmap_service, finding_service):
    aliases = SERVICE_ALIASES.get(nmap_service, [])
    if finding_service in aliases:
        return True
    for key, vals in SERVICE_ALIASES.items():
        if finding_service in vals and nmap_service in vals:
            return True
    if len(finding_service) >= 3 and len(nmap_service) >= 3:
        if finding_service in nmap_service or nmap_service in finding_service:
            return True
    return False


def get_findings_for_port(findings, port, service=''):
    matched = []
    service_lower = service.lower().strip() if service else ''
    for f in findings:
        if port in f.get('port', []):
            matched.append(f)
            continue
        if service_lower and f.get('service', ''):
            finding_service = f['service'].lower().strip()
            if finding_service == service_lower:
                matched.append(f)
                continue
            if _service_matches(service_lower, finding_service):
                matched.append(f)
                continue
    return matched


def is_false_positive(finding, output, check_type):
    """
    Detect false positives BEFORE marking as vulnerable.
    Returns True if this is a false positive (should NOT be marked vulnerable).
    """
    if not output:
        return False

    output_lower = output.lower()

    spa_markers = [
        '/_next/static/', '/_next/data/', '__next',
        '/static/js/bundle', 'react-root', 'root-app',
        '/static/js/main.', 'webpackjsonp',
        'ng-app', 'ng-version',
        'nuxt', '__nuxt',
        'gatsby',
        'svelte',
        'data-vue-app', 'vue-app',
    ]

    path_based_categories = ['http_exposure', 'http_api']
    is_html = '<html' in output_lower or '<!doctype html' in output_lower

    if finding.get('category') in path_based_categories and is_html:
        if any(marker in output_lower for marker in spa_markers):
            return True

        finding_id = finding.get('finding_name', finding.get('name', '')).lower()

        if 'phpmyadmin' in finding_id:
            if 'phpmyadmin' not in output_lower.replace('phpmyadmin exposed', ''):
                return True

        if 'swagger' in finding_id or 'openapi' in finding_id:
            if 'swagger-ui' not in output_lower and 'openapi' not in output_lower:
                return True

        if 'adminer' in finding_id:
            if 'adminer' not in output_lower or 'login-form' not in output_lower:
                return True

        if '.env' in finding_id:
            return True

        if '.git' in finding_id:
            if 'ref: refs/' not in output_lower:
                return True

        if 'actuator' in finding_id:
            return True

        if 'phpinfo' in finding_id:
            if 'php version' not in output_lower:
                return True

        if 'server-status' in finding_id or 'server-info' in finding_id:
            if 'apache' not in output_lower:
                return True

        if 'xmlrpc' in finding_id:
            if 'xml-rpc' not in output_lower and 'xmlrpc' not in output_lower:
                return True

        if 'security.txt' in finding_id or 'well-known' in finding_id:
            return True

        if 'robots.txt' in finding_id:
            if 'user-agent:' not in output_lower and 'disallow:' not in output_lower:
                return True

        if 'graphql' in finding_id:
            if '__schema' not in output_lower or '<html' in output_lower:
                return True

    if check_type == 'http_get_status':
        if is_html and any(marker in output_lower for marker in spa_markers):
            return True

    if 'null' in finding.get('name', '').lower() and 'cipher' in finding.get('name', '').lower():
        if 'cipher is' in output_lower:
            cipher_match = re.search(r'cipher is\s+(\S+)', output, re.IGNORECASE)
            if cipher_match:
                negotiated = cipher_match.group(1).upper()
                if 'NULL' not in negotiated and '(NONE)' not in negotiated:
                    return True
        elif 'no cipher' in output_lower or 'handshake failure' in output_lower or 'ssl alert' in output_lower:
            return True

    if 'x-powered-by' in finding.get('name', '').lower() and 'disclosure' in finding.get('name', '').lower():
        if 'x-powered-by' not in output_lower:
            return True

    return False


def run_finding_check(finding, target_ip, port):
    check = finding['check']
    cmd = check['command'].replace('{target}', target_ip).replace('{port}', str(port))

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return (False, 'Timeout', cmd)
    except Exception as e:
        return (False, str(e), cmd)

    check_type = check['type']
    vulnerable = False

    if check_type == 'http_header_missing':
        header = check['header'].lower()
        lines = output.lower().splitlines()
        found = any(line.startswith(header + ':') or line.startswith(header + ' :') for line in lines)
        vulnerable = not found

    elif check_type == 'http_header_value':
        header = check['header'].lower()
        match_pattern = check.get('match', check.get('value', '.'))
        for line in output.splitlines():
            if line.lower().startswith(header + ':'):
                header_val = line.split(':', 1)[1].strip()
                if re.search(match_pattern, header_val, re.IGNORECASE):
                    vulnerable = True
                    break

    elif check_type == 'http_get_match':
        vulnerable = check['match'].lower() in output.lower()

    elif check_type == 'http_get_status':
        vulnerable = ('HTTP/1.1 200' in output or 'HTTP/1.0 200' in output or 'HTTP/2 200' in output)

    elif check_type == 'command_match':
        vulnerable = check['match'].lower() in output.lower()

    elif check_type == 'command_no_match':
        found = check['no_match'].lower() in output.lower()
        vulnerable = not found

    elif check_type == 'ssl_check':
        match_str = check.get('match', '').lower()
        no_match_str = check.get('no_match', '').lower()
        if match_str:
            vulnerable = match_str in output.lower()
        elif no_match_str:
            vulnerable = no_match_str not in output.lower()

    elif check_type == 'banner_match':
        vulnerable = check['match'].lower() in output.lower()

    elif check_type == 'nmap_script':
        match_str = check.get('match', '').lower()
        if match_str:
            vulnerable = match_str in output.lower()

    if vulnerable and is_false_positive(finding, output, check_type):
        vulnerable = False
        output = '[Filtered: false positive] ' + output[:200]

    return (vulnerable, output[:500], cmd)


def run_checks_for_port(port_result, findings_db):
    """Run all applicable findings for a single discovered port."""
    port = port_result['port']
    ip = port_result['ip']
    service = port_result.get('service', '')
    applicable = get_findings_for_port(findings_db, port, service)
    results = []
    for finding in applicable:
        vulnerable, detail, cmd = run_finding_check(finding, ip, port)
        results.append({
            'ip': ip, 'port': port,
            'finding_id': finding['id'], 'finding_name': finding['name'],
            'severity': finding['severity'], 'cvss': finding.get('cvss', 0),
            'cve': finding.get('cve'), 'vulnerable': vulnerable,
            'detail': detail, 'category': finding.get('category', 'misc'),
            'command': cmd
        })
    return results


def run_all_checks(nmap_results, findings_db, progress_callback=None):
    results = []
    total_checks = 0
    completed_checks = 0

    for service in nmap_results:
        port_findings = get_findings_for_port(findings_db, service['port'], service.get('service', ''))
        total_checks += len(port_findings)

    for service in nmap_results:
        port_findings = get_findings_for_port(findings_db, service['port'], service.get('service', ''))
        for finding in port_findings:
            vulnerable, detail, cmd = run_finding_check(finding, service['ip'], service['port'])
            results.append({
                'ip': service['ip'],
                'port': service['port'],
                'finding_id': finding['id'],
                'finding_name': finding['name'],
                'severity': finding['severity'],
                'cvss': finding.get('cvss', 0),
                'cve': finding.get('cve'),
                'vulnerable': vulnerable,
                'detail': detail,
                'command': cmd,
                'category': finding.get('category', 'misc')
            })
            completed_checks += 1
            if progress_callback:
                progress_callback(completed_checks, total_checks)

    return results
