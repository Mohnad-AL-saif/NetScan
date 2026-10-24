import requests
import re
import json
import os
from datetime import datetime, timedelta

CACHE_FILE = os.path.join(os.path.dirname(__file__), '..', 'findings', 'version_cache.json')
VERSIONS_FILE = os.path.join(os.path.dirname(__file__), '..', 'findings', 'latest_versions.json')
CACHE_TTL_HOURS = 24

SERVICE_ALIASES = {
    'apache httpd': 'apache', 'httpd': 'apache', 'apache tomcat': 'tomcat',
    'apache': 'apache',
    'nginx': 'nginx',
    'openssh': 'openssh',
    'openssl': 'openssl',
    'mariadb': 'mariadb',
    'mysql': 'mysql',
    'postgresql': 'postgresql', 'postgres': 'postgresql',
    'mongodb': 'mongodb', 'mongod': 'mongodb',
    'redis': 'redis',
    'elasticsearch': 'elasticsearch',
    'rabbitmq': 'rabbitmq',
    'tomcat': 'tomcat',
    'jenkins': 'jenkins',
    'grafana': 'grafana',
    'gitlab': 'gitlab',
    'php': 'php',
    'python': 'python',
    'node.js': 'nodejs', 'node': 'nodejs', 'nodejs': 'nodejs',
    'docker': 'docker-engine', 'k8s': 'kubernetes', 'mssql': 'mssqlserver',
    'exim': 'exim',
    'postfix': 'postfix',
    'dovecot': 'dovecot',
    'proftpd': 'proftpd',
    'vsftpd': 'vsftpd',
    'haproxy': 'haproxy',
    'consul': 'consul',
    'vault': 'hashicorp-vault',
    'varnish': 'varnish',
    'squid': 'squid',
}


def _load_known_products():
    try:
        if os.path.exists(VERSIONS_FILE):
            with open(VERSIONS_FILE, 'r') as f:
                data = json.load(f)
            return set(data.get('products', {}).keys())
    except Exception:
        pass
    return set()


def _resolve_product_slug(product_name):
    name = product_name.lower().strip()

    if name in SERVICE_ALIASES:
        return SERVICE_ALIASES[name]

    known = _load_known_products()
    if name in known:
        return name

    for suffix in ['server', 'db', '-server', '-db']:
        stripped = name.replace(suffix, '').strip()
        if stripped in known:
            return stripped
        with_suffix = name + suffix if suffix.startswith('-') else name + '-' + suffix
        if with_suffix in known:
            return with_suffix

    for slug in known:
        if name in slug or slug in name:
            return slug

    return name


def load_cache():
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
            cached_time = datetime.fromisoformat(cache.get('timestamp', '2000-01-01'))
            if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
                return cache.get('data', {})
    except Exception:
        pass
    return {}


def save_cache(data):
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'data': data
            }, f, indent=2)
    except Exception:
        pass


def fetch_latest_version(product_slug):
    # Check local file first
    try:
        if os.path.exists(VERSIONS_FILE):
            with open(VERSIONS_FILE, 'r') as f:
                local_data = json.load(f)
            if product_slug in local_data.get('products', {}):
                info = local_data['products'][product_slug]
                return {
                    'latest_version': info['latest'],
                    'latest_cycle': info['latest_cycle'],
                    'supported_version': info['supported'],
                    'supported_cycle': info['supported_cycle'],
                    'all_cycles': info.get('all_cycles', []),
                    'product': product_slug
                }
    except Exception:
        pass

    # API fallback
    try:
        url = f'https://endoflife.date/api/{product_slug}.json'
        resp = requests.get(url, timeout=10, headers={'Accept': 'application/json'})
        if resp.status_code != 200:
            return None

        cycles = resp.json()
        if not cycles or not isinstance(cycles, list):
            return None

        latest = cycles[0]

        latest_supported = None
        for cycle in cycles:
            eol = cycle.get('eol')
            is_eol = False
            if isinstance(eol, bool):
                is_eol = eol
            elif isinstance(eol, str):
                try:
                    eol_date = datetime.strptime(eol, '%Y-%m-%d')
                    is_eol = eol_date < datetime.now()
                except ValueError:
                    is_eol = False

            if not is_eol and not latest_supported:
                latest_supported = cycle

        if not latest_supported:
            latest_supported = latest

        return {
            'latest_version': latest.get('latest', latest.get('cycle', '')),
            'latest_cycle': latest.get('cycle', ''),
            'supported_version': latest_supported.get('latest', latest_supported.get('cycle', '')),
            'supported_cycle': latest_supported.get('cycle', ''),
            'all_cycles': [c.get('cycle', '') for c in cycles[:10]],
            'product': product_slug
        }
    except Exception:
        return None


def extract_version_from_banner(banner, service=''):
    if not banner:
        return None, None

    banner_lower = banner.lower().strip()

    known = _load_known_products()
    search_keys = set(SERVICE_ALIASES.keys()) | known

    for key in sorted(search_keys, key=len, reverse=True):
        if key in banner_lower:
            patterns = [
                rf'{re.escape(key)}[/_\s-]*(\d+\.\d+[\.\d]*)',
                rf'{re.escape(key)}[a-z_\s/-]*v?=?(\d+\.\d+[\.\d]*)',
                rf'(\d+\.\d+[\.\d]*)\s*{re.escape(key)}',
            ]
            for pattern in patterns:
                match = re.search(pattern, banner_lower)
                if match:
                    return key, match.group(1)
            return key, None

    return None, None


def compare_versions(detected, latest):
    try:
        def parse_ver(v):
            return [int(x) for x in re.findall(r'\d+', str(v))]

        det = parse_ver(detected)
        lat = parse_ver(latest)

        if not det or not lat:
            return 'unknown'

        for d, l in zip(det, lat):
            if d < l:
                return 'outdated'
            elif d > l:
                return 'newer'

        if len(det) < len(lat):
            return 'outdated'

        return 'current'
    except Exception:
        return 'unknown'


def get_version_severity(detected_version, latest_version, product_slug):
    try:
        det = [int(x) for x in re.findall(r'\d+', str(detected_version))]
        lat = [int(x) for x in re.findall(r'\d+', str(latest_version))]

        if not det or not lat:
            return 'Info', 0.0

        major_diff = lat[0] - det[0] if len(det) > 0 and len(lat) > 0 else 0
        minor_diff = lat[1] - det[1] if len(det) > 1 and len(lat) > 1 else 0

        if major_diff >= 2:
            return 'Critical', 9.0
        elif major_diff >= 1:
            return 'High', 7.5
        elif minor_diff >= 5:
            return 'High', 7.0
        elif minor_diff >= 2:
            return 'Medium', 5.5
        elif minor_diff >= 1:
            return 'Low', 3.0
        else:
            return 'Low', 2.0
    except Exception:
        return 'Info', 0.0


def check_service_version(port_data):
    banner = port_data.get('banner', '')
    service = port_data.get('service', '')

    product_key, detected_version = extract_version_from_banner(banner, service)

    if not product_key or not detected_version:
        return None

    product_slug = _resolve_product_slug(product_key)
    if not product_slug:
        return None

    cache = load_cache()
    cache_key = product_slug

    if cache_key in cache:
        version_info = cache[cache_key]
    else:
        version_info = fetch_latest_version(product_slug)
        if version_info:
            cache[cache_key] = version_info
            save_cache(cache)

    if not version_info:
        return None

    latest = version_info.get('latest_version', '')
    comparison = compare_versions(detected_version, latest)

    if comparison != 'outdated':
        return None

    severity, cvss = get_version_severity(detected_version, latest, product_slug)

    return {
        'ip': port_data['ip'],
        'port': port_data['port'],
        'finding_id': 9000 + hash(product_slug) % 1000,
        'finding_name': f'Outdated {product_key.title()} Version ({detected_version} -> {latest})',
        'severity': severity,
        'cvss': cvss,
        'cve': None,
        'vulnerable': True,
        'detail': f'Detected: {product_key} {detected_version}\nLatest: {latest}\nSupported latest: {version_info.get("supported_version", "N/A")}\n\nRecent versions: {", ".join(version_info.get("all_cycles", [])[:5])}',
        'category': 'version',
        'command': f'nmap -sV -p {port_data["port"]} {port_data["ip"]} (version from banner)'
    }


def check_all_versions(port_results):
    findings = []
    checked_products = set()

    for port_data in port_results:
        product_key, _ = extract_version_from_banner(port_data.get('banner', ''))
        if product_key and product_key not in checked_products:
            checked_products.add(product_key)
            finding = check_service_version(port_data)
            if finding:
                findings.append(finding)

    return findings
