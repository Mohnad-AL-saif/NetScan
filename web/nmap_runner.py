import os
import subprocess
import re
import xml.etree.ElementTree as ET
import shlex


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
        return [], ''

    if 22 in ports_list:
        _keyscan_targets(target)

    ports_csv = ','.join(str(p) for p in ports_list)
    cmd = f'sudo nmap -p{ports_csv} -sV --script "default and not (ssh-* or auth-* or brute or *login*)" --script-args ssh.timeout=5,userdb=/dev/null,passdb=/dev/null --min-rate 5000 -n -Pn -oX - {target}'

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

    return parse_nmap_xml(stdout, target), cmd


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
        return [], ''

    ports_csv = ','.join(str(p) for p in udp_ports)
    cmd = f'sudo nmap -sUV -p{ports_csv} --min-rate 3000 -n -Pn -oX - {target}'

    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE, text=True, env=get_scan_env()
    )
    if controller:
        controller.register_nmap(proc.pid)

    stdout, stderr = proc.communicate(input='yes\n' * 20, timeout=600)
    return parse_nmap_xml(stdout, target, default_protocol='udp'), cmd


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
