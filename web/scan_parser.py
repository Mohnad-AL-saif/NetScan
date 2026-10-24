import re
import xml.etree.ElementTree as ET


def clean_banner(banner):
    if not banner:
        return banner
    banner = re.sub(r'^syn-ack\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    banner = re.sub(r'^conn-refused\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    banner = re.sub(r'^reset\s+ttl\s+\d+\s*', '', banner, flags=re.IGNORECASE)
    return banner.strip()


def parse_scan_input(content, default_ip):
    content = content.strip()

    if content.startswith('<?xml') or '<nmaprun' in content[:500]:
        services = parse_nmap_xml(content, default_ip)
        if services:
            return services

    services = parse_nmap_text(content, default_ip)
    if services:
        return services

    services = parse_nmap_greppable(content, default_ip)
    if services:
        return services

    return parse_simple_list(content, default_ip)


def parse_nmap_xml(content, default_ip):
    services = []
    try:
        root = ET.fromstring(content)
        for host in root.findall('.//host'):
            addr_el = host.find('address[@addrtype="ipv4"]')
            ip = addr_el.get('addr') if addr_el is not None else default_ip

            for port_el in host.findall('.//port'):
                state_el = port_el.find('state')
                if state_el is not None and state_el.get('state') != 'open':
                    continue

                port_id = int(port_el.get('portid', 0))
                protocol = port_el.get('protocol', 'tcp')

                svc_el = port_el.find('service')
                service_name = ''
                version = ''
                banner = ''
                if svc_el is not None:
                    service_name = svc_el.get('name', '')
                    product = svc_el.get('product', '')
                    ver = svc_el.get('version', '')
                    extra = svc_el.get('extrainfo', '')
                    banner = ' '.join(filter(None, [product, ver, extra])).strip()
                    version = ver

                services.append({
                    'ip': ip, 'port': port_id, 'protocol': protocol,
                    'service': service_name, 'version': version, 'banner': banner,
                })
    except ET.ParseError:
        pass
    return services


def parse_nmap_text(content, default_ip):
    """Parse nmap text output, tracking per-host IP correctly for multi-host scans."""
    services = []
    current_ip = default_ip

    for line in content.splitlines():
        # Track which host nmap is reporting
        ip_match = re.match(r'^Nmap scan report for (\S+)', line)
        if ip_match:
            found_ip = ip_match.group(1)
            # Handle "Nmap scan report for hostname (1.2.3.4)"
            ip_in_parens = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            if ip_in_parens:
                current_ip = ip_in_parens.group(1)
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', found_ip):
                current_ip = found_ip
            else:
                current_ip = found_ip  # hostname without IP
            continue

        # Match port lines
        m = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$', line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            banner = clean_banner(m.group(4).strip() if m.group(4) else '')
            version = ''
            ver_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
            if ver_match:
                version = ver_match.group(1)

            services.append({
                'ip': current_ip, 'port': port, 'protocol': proto,
                'service': service, 'version': version, 'banner': banner,
            })

    return services


def parse_nmap_greppable(content, default_ip):
    services = []
    for line in content.splitlines():
        if not line.startswith('Host:'):
            continue
        host_match = re.match(r'Host:\s+(\S+)', line)
        ip = host_match.group(1) if host_match else default_ip

        ports_match = re.search(r'Ports:\s+(.*)', line)
        if not ports_match:
            continue

        for port_entry in ports_match.group(1).split(','):
            parts = port_entry.strip().split('/')
            if len(parts) >= 5 and parts[1] == 'open':
                port = int(parts[0])
                proto = parts[2] if parts[2] else 'tcp'
                service = parts[4] if len(parts) > 4 else ''
                banner = clean_banner(parts[6] if len(parts) > 6 else '')
                version = ''
                ver_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
                if ver_match:
                    version = ver_match.group(1)

                services.append({
                    'ip': ip, 'port': port, 'protocol': proto,
                    'service': service, 'version': version, 'banner': banner,
                })
    return services


def parse_simple_list(content, default_ip):
    services = []
    seen = set()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        m = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)(?:/(tcp|udp))?$', line)
        if m:
            ip, port, proto = m.group(1), int(m.group(2)), m.group(3) or 'tcp'
            key = (ip, port, proto)
            if key not in seen:
                seen.add(key)
                services.append({'ip': ip, 'port': port, 'protocol': proto, 'service': '', 'version': '', 'banner': ''})
            continue

        m = re.match(r'^(\d+)(?:/(tcp|udp))?$', line)
        if m:
            port, proto = int(m.group(1)), m.group(2) or 'tcp'
            key = (default_ip, port, proto)
            if key not in seen:
                seen.add(key)
                services.append({'ip': default_ip, 'port': port, 'protocol': proto, 'service': '', 'version': '', 'banner': ''})
            continue

        if re.match(r'^[\d,\s]+$', line):
            for p in re.findall(r'\d+', line):
                port = int(p)
                key = (default_ip, port, 'tcp')
                if key not in seen:
                    seen.add(key)
                    services.append({'ip': default_ip, 'port': port, 'protocol': 'tcp', 'service': '', 'version': '', 'banner': ''})

    return services
