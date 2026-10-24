import os
import io
import csv
import re
import json
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response
)
import models
import nmap_runner
import findings_engine
import version_checker
import scan_parser
from command_generator import generate_commands_for_scan, analyze_command_output

app = Flask(__name__)
app.secret_key = 'netscan-dev-secret-key-change-in-production'

live_scans = {}


class ScanController:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.nmap_pids = []
        self.stop_requested = False
        self.executor = None
        self._lock = threading.Lock()

    def register_nmap(self, pid):
        with self._lock:
            self.nmap_pids.append(pid)

    def request_stop(self):
        with self._lock:
            self.stop_requested = True
            for pid in self.nmap_pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if self.executor:
                self.executor.shutdown(wait=False, cancel_futures=True)

    def should_stop(self):
        return self.stop_requested


scan_controllers = {}


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = models.get_user_by_id(session['user_id'])
        if not user or user['role'] != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = models.get_user_by_id(session['user_id'])
    return {'current_user': user}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = models.authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not username or not password:
            flash('Username and password are required.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif models.create_user(username, password):
            flash('Account created. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists.', 'error')
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    stats = models.get_dashboard_stats(session['user_id'])
    recent_scans = models.get_user_scans(session['user_id'], limit=5)
    scan_findings = {}
    for scan in recent_scans:
        scan_findings[scan['id']] = models.get_finding_stats(scan['id'])
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans, scan_findings=scan_findings)


@app.route('/scan/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        targets = request.form.get('targets', '').strip()
        tcp_args = request.form.get('tcp_args', '-sS -p- --min-rate 5000 -T4 -n -Pn').strip()
        udp_scan = request.form.get('udp_scan') == 'on'
        udp_args = request.form.get('udp_args', '-sU --top-ports 100 --min-rate 3000 -T4 -n -Pn').strip()

        if not name:
            name = f"Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        if not targets:
            flash('Please enter target(s) to scan.', 'error')
            return render_template('new_scan.html')

        scan_id = models.create_scan(
            session['user_id'], name, targets, tcp_args,
            tcp_args=tcp_args,
            udp_args=udp_args if udp_scan else '',
            udp_enabled=udp_scan
        )

        live_scans[scan_id] = {
            'ports': [], 'findings': [], 'status': 'phase1', 'phase': 1,
            'phase_label': 'TCP Port Discovery', 'cmds': [],
            'port_count': 0, 'finding_count': 0, 'vuln_count': 0,
            'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'udp_enabled': udp_scan
        }

        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, targets, tcp_args, udp_scan, udp_args)
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('scan_detail', scan_id=scan_id))

    return render_template('new_scan.html')


def run_scan_background(scan_id, targets, tcp_args, udp_scan, udp_args):
    """Multi-phase scan with live updates, stop support, and dedup."""
    lock = threading.Lock()
    findings_db = findings_engine.load_findings()
    controller = ScanController(scan_id)
    controller.executor = ThreadPoolExecutor(max_workers=5)
    scan_controllers[scan_id] = controller
    finding_futures = []
    checked_findings = set()

    def on_port_found(port_data):
        with lock:
            live_scans[scan_id]['ports'].append(port_data)
            live_scans[scan_id]['port_count'] += 1
        models.save_scan_result(scan_id, port_data)
        if not controller.should_stop():
            future = controller.executor.submit(
                run_findings_for_port, scan_id, port_data, findings_db, lock, checked_findings
            )
            finding_futures.append(future)

    try:
        # === PHASE 1: TCP Port Discovery ===
        live_scans[scan_id]['status'] = 'phase1'
        live_scans[scan_id]['phase'] = 1
        live_scans[scan_id]['phase_label'] = 'TCP Port Discovery'

        tcp_ports, cmd1 = nmap_runner.run_phase1_streaming(
            targets, tcp_args, callback=on_port_found, controller=controller
        )
        with lock:
            live_scans[scan_id]['cmds'].append(cmd1)
        models.set_scan_nmap_command(scan_id, cmd1)

        if controller.should_stop():
            raise Exception('Scan stopped by user')

        # === PHASE 2: TCP Version Detection ===
        live_scans[scan_id]['status'] = 'phase2'
        live_scans[scan_id]['phase'] = 2
        live_scans[scan_id]['phase_label'] = 'TCP Version Detection'

        port_numbers = [p['port'] for p in tcp_ports]
        phase2_results, cmd2 = nmap_runner.run_phase2(targets, port_numbers, controller=controller)
        if cmd2:
            with lock:
                live_scans[scan_id]['cmds'].append(cmd2)

        for p2 in phase2_results:
            with lock:
                for i, p1 in enumerate(live_scans[scan_id]['ports']):
                    if p1['port'] == p2['port'] and p1['ip'] == p2['ip']:
                        live_scans[scan_id]['ports'][i]['service'] = p2['service']
                        live_scans[scan_id]['ports'][i]['banner'] = p2['banner']
                        live_scans[scan_id]['ports'][i]['phase'] = 2
                        break
            models.update_scan_result_details(scan_id, p2)

        if controller.should_stop():
            raise Exception('Scan stopped by user')

        # === PHASE 3 & 4: UDP (if enabled) ===
        if udp_scan and udp_args:
            live_scans[scan_id]['status'] = 'phase3'
            live_scans[scan_id]['phase'] = 3
            live_scans[scan_id]['phase_label'] = 'UDP Port Discovery'

            udp_ports_data, cmd3 = nmap_runner.run_udp_phase1(targets, udp_args, controller=controller)
            with lock:
                live_scans[scan_id]['cmds'].append(cmd3)

            for udp_port in udp_ports_data:
                on_port_found(udp_port)

            if controller.should_stop():
                raise Exception('Scan stopped by user')

            live_scans[scan_id]['status'] = 'phase4'
            live_scans[scan_id]['phase'] = 4
            live_scans[scan_id]['phase_label'] = 'UDP Version Detection'

            udp_port_numbers = [p['port'] for p in udp_ports_data]
            udp_phase2_results, cmd4 = nmap_runner.run_udp_phase2(targets, udp_port_numbers, controller=controller)
            if cmd4:
                with lock:
                    live_scans[scan_id]['cmds'].append(cmd4)

            for p2 in udp_phase2_results:
                with lock:
                    for i, p1 in enumerate(live_scans[scan_id]['ports']):
                        if p1['port'] == p2['port'] and p1['ip'] == p2['ip'] and p1['protocol'] == 'udp':
                            live_scans[scan_id]['ports'][i]['service'] = p2['service']
                            live_scans[scan_id]['ports'][i]['banner'] = p2['banner']
                            live_scans[scan_id]['ports'][i]['phase'] = 4
                            break
                models.update_scan_result_details(scan_id, p2)

        # === VERSION CHECKS ===
        if not controller.should_stop():
            live_scans[scan_id]['status'] = 'version_check'
            live_scans[scan_id]['phase_label'] = 'Checking for outdated versions'
            try:
                ports_with_banners = [p for p in live_scans[scan_id]['ports'] if p.get('banner')]
                version_findings = version_checker.check_all_versions(ports_with_banners)
                with lock:
                    for vf in version_findings:
                        live_scans[scan_id]['findings'].append(vf)
                        live_scans[scan_id]['vuln_count'] += 1
                        sev = vf['severity'].lower()
                        if sev in live_scans[scan_id]['stats']:
                            live_scans[scan_id]['stats'][sev] += 1
                        models.save_single_finding(scan_id, vf)
                    live_scans[scan_id]['finding_count'] += len(version_findings)
            except Exception:
                pass

        # Wait for findings
        live_scans[scan_id]['status'] = 'finishing'
        live_scans[scan_id]['phase_label'] = 'Finishing checks'
        for future in finding_futures:
            try:
                future.result(timeout=30)
            except Exception:
                pass

        all_cmds = live_scans[scan_id]['cmds']
        models.set_scan_nmap_command(scan_id, '\n'.join(all_cmds))

        live_scans[scan_id]['status'] = 'done'
        live_scans[scan_id]['phase_label'] = 'Complete'
        models.update_scan_status(scan_id, 'completed', json.dumps({
            'services_found': live_scans[scan_id]['port_count'],
            'findings_checked': live_scans[scan_id]['finding_count'],
            'vulnerabilities': live_scans[scan_id]['vuln_count'],
            'tcp_args': tcp_args,
            'udp_args': udp_args if udp_scan else '',
            'commands': all_cmds
        }))

    except Exception as e:
        err_msg = str(e)
        if controller.should_stop():
            live_scans[scan_id]['status'] = 'stopped'
            live_scans[scan_id]['phase_label'] = 'Stopped by user'
            all_cmds = live_scans[scan_id]['cmds']
            models.set_scan_nmap_command(scan_id, '\n'.join(all_cmds))
            models.update_scan_status(scan_id, 'stopped', json.dumps({
                'services_found': live_scans[scan_id]['port_count'],
                'findings_checked': live_scans[scan_id]['finding_count'],
                'vulnerabilities': live_scans[scan_id]['vuln_count'],
                'stopped': True
            }))
        else:
            live_scans[scan_id]['status'] = 'error'
            live_scans[scan_id]['phase_label'] = f'Error: {err_msg}'
            models.update_scan_status(scan_id, 'failed', json.dumps({'error': err_msg}))
    finally:
        scan_controllers.pop(scan_id, None)
        try:
            controller.executor.shutdown(wait=False)
        except Exception:
            pass


def run_findings_for_port(scan_id, port_data, findings_db, lock, checked_findings):
    """Run all findings for one port with dedup."""
    port_findings = findings_engine.run_checks_for_port(port_data, findings_db)
    for f in port_findings:
        with lock:
            key = (f['ip'], f['port'], f['finding_id'])
            if key in checked_findings:
                continue
            checked_findings.add(key)
            live_scans[scan_id]['finding_count'] += 1
            if f['vulnerable']:
                live_scans[scan_id]['findings'].append(f)
                live_scans[scan_id]['vuln_count'] += 1
                sev = f['severity'].lower()
                if sev in live_scans[scan_id]['stats']:
                    live_scans[scan_id]['stats'][sev] += 1
        models.save_single_finding(scan_id, f)


# --- Live API ---

@app.route('/api/scan/<int:scan_id>/live')
@login_required
def scan_live(scan_id):
    data = live_scans.get(scan_id)
    if not data:
        scan = models.get_scan(scan_id)
        if scan:
            return jsonify({'status': 'done', 'from_db': True})
        return jsonify({'error': 'not found'}), 404

    return jsonify({
        'status': data['status'],
        'phase': data['phase'],
        'phase_label': data['phase_label'],
        'ports': data['ports'],
        'findings': data['findings'],
        'port_count': data['port_count'],
        'finding_count': data['finding_count'],
        'vuln_count': data['vuln_count'],
        'stats': data['stats'],
        'cmds': data['cmds'],
        'udp_enabled': data.get('udp_enabled', False)
    })


@app.route('/api/scan/<int:scan_id>/stop', methods=['POST'])
@login_required
def stop_scan(scan_id):
    controller = scan_controllers.get(scan_id)
    if controller:
        controller.request_stop()
        return jsonify({'status': 'stopping'})
    return jsonify({'error': 'Scan not running'}), 404


@app.route('/scan/<int:scan_id>/progress')
@login_required
def scan_progress_api(scan_id):
    data = live_scans.get(scan_id)
    if data:
        pct_map = {'phase1': 20, 'phase2': 50, 'phase3': 65, 'phase4': 80, 'version_check': 85, 'finishing': 90, 'done': 100, 'stopped': 100, 'error': 100}
        return jsonify({
            'phase': data['phase_label'],
            'percent': pct_map.get(data['status'], 0)
        })
    scan = models.get_scan(scan_id)
    if scan and scan['status'] in ('completed', 'failed', 'stopped'):
        return jsonify({'phase': scan['status'].capitalize(), 'percent': 100})
    return jsonify({'phase': 'Unknown', 'percent': 0})


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('dashboard'))

    results = models.get_scan_results(scan_id)
    findings = models.get_finding_results(scan_id, vulnerable_only=True)
    finding_stats = models.get_finding_stats(scan_id)
    tab = request.args.get('tab', 'services')

    is_live = scan_id in live_scans and live_scans[scan_id]['status'] not in ('done', 'error', 'stopped')

    return render_template('scan_detail.html',
                           scan=scan, results=results, findings=findings,
                           finding_stats=finding_stats, tab=tab, is_live=is_live)


@app.route('/scan/<int:scan_id>/findings')
@login_required
def findings_detail(scan_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('dashboard'))

    severity = request.args.get('severity')
    port = request.args.get('port')
    category = request.args.get('category')
    export = request.args.get('export')

    findings = models.get_finding_results(scan_id, severity=severity, port=port, category=category)
    finding_stats = models.get_finding_stats(scan_id)
    categories = models.get_all_finding_categories(scan_id)
    ports_list = sorted(set(f['port'] for f in models.get_finding_results(scan_id)))

    if export == 'json':
        return Response(
            json.dumps(findings, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=findings_scan_{scan_id}.json'}
        )

    return render_template('findings_detail.html',
                           scan=scan, findings=findings, finding_stats=finding_stats,
                           categories=categories, ports_list=ports_list,
                           filter_severity=severity, filter_port=port, filter_category=category)


@app.route('/scan/<int:scan_id>/export-findings')
@login_required
def export_findings(scan_id):
    conn = models.get_db()
    scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    findings = conn.execute(
        'SELECT * FROM finding_results WHERE scan_id=? ORDER BY severity, ip, port',
        (scan_id,)
    ).fetchall()
    conn.close()
    if not scan:
        flash('السكان غير موجود', 'error')
        return redirect(url_for('dashboard'))

    fmt = request.args.get('format', 'csv')

    if fmt == 'json':
        data = [dict(f) for f in findings]
        return Response(
            json.dumps(data, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=findings_scan_{scan_id}.json'}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['IP', 'Port', 'Finding', 'Severity', 'CVSS', 'CVE', 'Category', 'Detail', 'Command'])
        for f in findings:
            writer.writerow([f['ip'], f['port'], f['finding_name'], f['severity'],
                           f['cvss'], f['cve'], f['category'], f['detail'], f['command']])
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=findings_scan_{scan_id}.csv'}
        )


@app.route('/scan/<int:scan_id>/export-raw')
@login_required
def export_raw_scan(scan_id):
    conn = models.get_db()
    scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return 'Not found', 404

    results = conn.execute('SELECT * FROM scan_results WHERE scan_id=?', (scan_id,)).fetchall()
    findings = conn.execute('SELECT * FROM finding_results WHERE scan_id=?', (scan_id,)).fetchall()
    conn.close()

    data = {
        'scan': {
            'id': scan['id'],
            'name': scan['name'],
            'targets': scan['targets'],
            'created_at': scan['created_at'],
            'status': scan['status'],
        },
        'results': [dict(r) for r in results],
        'findings': [dict(f) for f in findings],
        'stats': {
            'total_services': len(results),
            'total_findings': len(findings),
            'unique_ips': len(set(r['ip'] for r in results)),
            'unique_ports': len(set(r['port'] for r in results)),
        }
    }

    return Response(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_full_export.json'}
    )


@app.route('/scan/<int:scan_id>/run-findings', methods=['POST'])
@login_required
def run_findings(scan_id):
    conn = models.get_db()
    scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not scan:
        flash('السكان غير موجود', 'error')
        conn.close()
        return redirect(url_for('dashboard'))

    results = conn.execute('SELECT * FROM scan_results WHERE scan_id=?', (scan_id,)).fetchall()

    conn.execute('DELETE FROM finding_results WHERE scan_id=?', (scan_id,))
    conn.commit()
    conn.close()

    LATEST_VERSIONS = {
        'openssh': '10.0',
        'openssl': '3.5.0',
        'apache': '2.4.62',
        'nginx': '1.27.3',
        'mariadb': '11.6.2',
        'mysql': '8.4.3',
        'mongodb': '8.0.4',
        'postgresql': '17.2',
        'redis': '7.4.2',
        'tomcat': '11.0.2',
        'proftpd': '1.3.8b',
        'vsftpd': '3.0.5',
        'postfix': '3.9.1',
        'exim': '4.98',
        'dovecot': '2.3.21',
        'bind': '9.20.4',
        'samba': '4.21.2',
        'elasticsearch': '8.17.0',
        'opensearch': '2.18.0',
    }

    def parse_version(ver_str):
        if not ver_str:
            return None
        m = re.search(r'(\d+(?:\.\d+){1,4})', ver_str)
        return m.group(1) if m else None

    def version_tuple(ver):
        try:
            return tuple(int(x) for x in ver.split('.'))
        except Exception:
            return (0,)

    def is_outdated(software, detected_ver):
        latest = LATEST_VERSIONS.get(software.lower())
        if not latest or not detected_ver:
            return False, None
        return version_tuple(detected_ver) < version_tuple(latest), latest

    def check_ssh_banner(ip, port, service, banner):
        if port == 22 and 'ssh' in service.lower():
            return True, f'SSH banner exposed: {banner}'
        return False, ''

    def check_ssh_version(ip, port, service, banner):
        if 'openssh' not in banner.lower():
            return False, ''
        ver = parse_version(banner)
        outdated, latest = is_outdated('openssh', ver)
        if outdated:
            return True, f'OpenSSH {ver} outdated (latest: {latest})'
        return False, ''

    def check_mongodb_exposed(ip, port, service, banner):
        if 'mongodb' in service.lower() or 'mongo' in banner.lower():
            ver = parse_version(banner)
            detail = f'MongoDB {ver} exposed on port {port}' if ver else f'MongoDB exposed on port {port}'
            outdated, latest = is_outdated('mongodb', ver)
            if outdated:
                detail += f' — outdated (latest: {latest})'
            return True, detail
        return False, ''

    def check_mysql_exposed(ip, port, service, banner):
        if 'mysql' in service.lower() or 'mariadb' in banner.lower():
            ver = parse_version(banner)
            sw = 'MariaDB' if 'mariadb' in banner.lower() else 'MySQL'
            detail = f'{sw} {ver} exposed on port {port}' if ver else f'{sw} exposed on port {port}'
            outdated, latest = is_outdated(sw.lower(), ver)
            if outdated:
                detail += f' — outdated (latest: {latest})'
            return True, detail
        return False, ''

    def check_opensearch_basic_auth(ip, port, service, banner):
        if 'opensearch' in banner.lower() and 'basic auth' in banner.lower():
            return True, f'OpenSearch with Basic Auth on port {port} — weak authentication'
        return False, ''

    def check_kubelet_exposed(ip, port, service, banner):
        if port == 10250 and ('http' in service.lower() or 'ssl' in service.lower()):
            return True, f'Kubelet API exposed on port {port} — can leak pod info'
        return False, ''

    def check_k8s_api_exposed(ip, port, service, banner):
        if port == 6443 and ('http' in service.lower() or 'ssl' in service.lower()):
            return True, f'Kubernetes API Server exposed on port {port}'
        return False, ''

    def check_etcd_exposed(ip, port, service, banner):
        if port in (2379, 2380, 2381) and ('etcd' in service.lower() or 'etcd' in banner.lower() or 'http' in service.lower()):
            proto = 'HTTPS' if 'ssl' in service.lower() else 'HTTP'
            return True, f'etcd exposed on port {port} ({proto}) — may leak cluster secrets'
        return False, ''

    def check_tomcat_exposed(ip, port, service, banner):
        if 'tomcat' not in banner.lower():
            return False, ''
        ver = parse_version(banner)
        detail = f'Apache Tomcat {ver} exposed on port {port}' if ver else f'Apache Tomcat exposed on port {port}'
        outdated, latest = is_outdated('tomcat', ver)
        if outdated:
            detail += f' — outdated (latest: {latest})'
        return True, detail

    def check_nginx_exposed(ip, port, service, banner):
        if 'nginx' in banner.lower():
            return True, f'nginx reverse proxy on port {port}'
        return False, ''

    def check_rpcbind_exposed(ip, port, service, banner):
        if port == 111 and 'rpcbind' in service.lower():
            return True, f'RPCbind exposed on port {port} — may leak NFS/service info'
        return False, ''

    def check_grpc_exposed(ip, port, service, banner):
        if 'grpc' in service.lower():
            return True, f'gRPC service exposed on port {port} — may allow unauthenticated calls'
        return False, ''

    def check_rtsp_exposed(ip, port, service, banner):
        if 'rtsp' in service.lower():
            return True, f'RTSP (camera/streaming) exposed on port {port}'
        return False, ''

    SMART_RULES = [
        ('SSH Banner Detection', 'Info', 0.0, 'ssh_config', check_ssh_banner),
        ('SSH Version Outdated', 'Medium', 5.3, 'ssh_config', check_ssh_version),
        ('MongoDB Exposed to Network', 'High', 7.5, 'nosql', check_mongodb_exposed),
        ('MySQL/MariaDB Exposed to Network', 'High', 7.5, 'database', check_mysql_exposed),
        ('OpenSearch Weak Authentication', 'High', 7.5, 'authentication', check_opensearch_basic_auth),
        ('Kubelet API Exposed', 'High', 8.1, 'container', check_kubelet_exposed),
        ('Kubernetes API Server Exposed', 'Critical', 9.1, 'container', check_k8s_api_exposed),
        ('etcd Exposed', 'Critical', 9.8, 'container', check_etcd_exposed),
        ('Apache Tomcat Exposed', 'Medium', 5.3, 'http_exposure', check_tomcat_exposed),
        ('nginx Reverse Proxy Exposed', 'Info', 0.0, 'http_exposure', check_nginx_exposed),
        ('RPCbind Exposed', 'Medium', 5.0, 'info_disclosure', check_rpcbind_exposed),
        ('gRPC Service Exposed', 'Medium', 5.3, 'info_disclosure', check_grpc_exposed),
        ('RTSP Stream Exposed', 'Medium', 5.3, 'info_disclosure', check_rtsp_exposed),
    ]

    grouped = {}

    for r in results:
        ip = r['ip']
        port = r['port']
        service = r['service'] or ''
        banner = r['banner'] or ''

        for rule_name, severity, cvss, category, check_fn in SMART_RULES:
            vulnerable, detail = check_fn(ip, port, service, banner)
            if not vulnerable:
                continue

            if rule_name not in grouped:
                grouped[rule_name] = {
                    'finding_name': rule_name,
                    'severity': severity,
                    'cvss': cvss,
                    'category': category,
                    'ips': set(),
                    'ports': set(),
                    'details': [],
                }

            grouped[rule_name]['ips'].add(ip)
            grouped[rule_name]['ports'].add(port)
            if detail not in grouped[rule_name]['details']:
                grouped[rule_name]['details'].append(detail)

    count = 0
    c = models.get_db()
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}

    for fname in sorted(grouped.keys(), key=lambda x: severity_order.get(grouped[x]['severity'], 5)):
        info = grouped[fname]
        ips_sorted = sorted(info['ips'], key=lambda x: list(map(int, x.split('.'))))
        ips_str = ', '.join(ips_sorted)

        if len(info['details']) > 3:
            detail_str = ' | '.join(info['details'][:3]) + f' | +{len(info["details"])-3} more'
        else:
            detail_str = ' | '.join(info['details'])

        c.execute(
            '''INSERT INTO finding_results
            (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (scan_id, ips_str, int(sorted(info['ports'])[0]), f'AUTO-{count+1:04d}',
             info['finding_name'], info['severity'], info['cvss'],
             '', 1, detail_str,
             '', info['category'])
        )
        count += 1

    c.commit()
    c.close()

    total_ips = len(set().union(*(info['ips'] for info in grouped.values()))) if grouped else 0
    crit = sum(1 for info in grouped.values() if info['severity'] == 'Critical')
    high = sum(1 for info in grouped.values() if info['severity'] == 'High')
    med = sum(1 for info in grouped.values() if info['severity'] == 'Medium')

    flash(f'تم الفحص: {count} ثغرة · {total_ips} IP · {crit} Critical · {high} High · {med} Medium', 'success')
    return redirect(url_for('scan_detail', scan_id=scan_id))


@app.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan_route(scan_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('Scan not found.', 'error')
    elif scan['user_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('Permission denied.', 'error')
    else:
        controller = scan_controllers.get(scan_id)
        if controller:
            controller.request_stop()
        models.delete_scan(scan_id)
        live_scans.pop(scan_id, None)
        flash('Scan deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/scan/import', methods=['GET', 'POST'])
@login_required
def scan_import():
    if request.method == 'GET':
        return render_template('scan_import.html')

    scan_name = request.form.get('scan_name', 'Imported Scan').strip()
    target = request.form.get('target', '').strip()
    run_findings_flag = request.form.get('run_findings') == 'on'
    paste_content = request.form.get('paste_content', '').strip()
    scan_file = request.files.get('scan_file')

    content = ''
    if scan_file and scan_file.filename:
        content = scan_file.read().decode('utf-8', errors='ignore')
    elif paste_content:
        content = paste_content

    if not content:
        flash('No scan data provided. Paste output or upload a file.', 'error')
        return redirect(url_for('scan_import'))

    if not target:
        flash('Target IP/Host is required.', 'error')
        return redirect(url_for('scan_import'))

    services = scan_parser.parse_scan_input(content, target)

    if not services:
        flash('Could not parse any open ports from the input. Check the format.', 'error')
        return redirect(url_for('scan_import'))

    scan_id = models.create_scan(
        session['user_id'], scan_name, target, 'imported',
        tcp_args='imported', udp_args='', udp_enabled=False
    )

    for svc in services:
        models.save_scan_result(scan_id, {
            'ip': svc['ip'], 'port': svc['port'],
            'protocol': svc.get('protocol', 'tcp'),
            'state': 'open',
            'service': svc.get('service', ''),
            'banner': svc.get('banner', ''),
        })

    if run_findings_flag:
        models.update_scan_status(scan_id, 'running')
        thread = threading.Thread(
            target=run_imported_findings,
            args=(scan_id, services)
        )
        thread.daemon = True
        thread.start()
        flash(f'Imported {len(services)} open ports. Running findings checks...', 'success')
    else:
        models.update_scan_status(scan_id, 'completed', json.dumps({
            'services_found': len(services),
            'findings_checked': 0,
            'vulnerabilities': 0,
            'imported': True
        }))
        flash(f'Imported {len(services)} open ports.', 'success')

    return redirect(url_for('scan_detail', scan_id=scan_id))


def run_imported_findings(scan_id, services):
    """Run findings checks against imported scan results."""
    try:
        findings_db = findings_engine.load_findings()
        checked_findings = set()
        total_checked = 0
        total_vulns = 0

        for svc in services:
            port_info = {
                'port': svc['port'],
                'ip': svc['ip'],
                'service': svc.get('service', ''),
            }
            port_results = findings_engine.run_checks_for_port(port_info, findings_db)
            for f in port_results:
                key = (f['ip'], f['port'], f['finding_id'])
                if key in checked_findings:
                    continue
                checked_findings.add(key)
                total_checked += 1
                if f['vulnerable']:
                    total_vulns += 1
                models.save_single_finding(scan_id, f)

        # Version checks
        ports_with_banners = [s for s in services if s.get('banner')]
        try:
            version_findings = version_checker.check_all_versions(ports_with_banners)
            for vf in version_findings:
                models.save_single_finding(scan_id, vf)
                total_vulns += 1
                total_checked += 1
        except Exception:
            pass

        models.update_scan_status(scan_id, 'completed', json.dumps({
            'services_found': len(services),
            'findings_checked': total_checked,
            'vulnerabilities': total_vulns,
            'imported': True
        }))
    except Exception as e:
        models.update_scan_status(scan_id, 'failed', json.dumps({'error': str(e)}))


@app.route('/scan/<int:scan_id>/rescan', methods=['POST'])
@login_required
def rescan(scan_id):
    old_scan = models.get_scan(scan_id)
    if not old_scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('dashboard'))

    tcp_args = old_scan.get('tcp_args') or '-sS -p- --min-rate 5000 -T4 -n -Pn'
    udp_args = old_scan.get('udp_args') or ''
    udp_enabled = bool(old_scan.get('udp_enabled'))

    new_scan_id = models.create_scan(
        session['user_id'],
        f"Rescan: {old_scan['name']}",
        old_scan['targets'],
        tcp_args,
        tcp_args=tcp_args,
        udp_args=udp_args,
        udp_enabled=udp_enabled
    )

    live_scans[new_scan_id] = {
        'ports': [], 'findings': [], 'status': 'phase1', 'phase': 1,
        'phase_label': 'TCP Port Discovery', 'cmds': [],
        'port_count': 0, 'finding_count': 0, 'vuln_count': 0,
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'udp_enabled': udp_enabled
    }

    thread = threading.Thread(
        target=run_scan_background,
        args=(new_scan_id, old_scan['targets'], tcp_args, udp_enabled, udp_args)
    )
    thread.daemon = True
    thread.start()
    return redirect(url_for('scan_detail', scan_id=new_scan_id))


# --- Manual Commands ---

@app.route('/scan/<int:scan_id>/commands')
@login_required
def scan_commands(scan_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('السكان غير موجود', 'error')
        return redirect(url_for('dashboard'))
    commands, grouped = generate_commands_for_scan(scan_id, models.get_db)
    return render_template('scan_commands.html',
                           scan=scan, grouped_commands=grouped, total_commands=len(commands))


@app.route('/scan/<int:scan_id>/commands/json')
@login_required
def scan_commands_json(scan_id):
    commands, grouped = generate_commands_for_scan(scan_id, models.get_db)
    return jsonify({
        'total': len(commands),
        'grouped': {cat: [{
            'id': c['id'], 'tool': c['tool'], 'description': c['description'],
            'port': c['port'], 'ip': c['ip'], 'command': c['command'],
            'severity': c['severity']
        } for c in cmds] for cat, cmds in grouped.items()}
    })


@app.route('/scan/<int:scan_id>/command/<int:cmd_id>/upload', methods=['GET', 'POST'])
@login_required
def upload_command_output(scan_id, cmd_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('السكان غير موجود', 'error')
        return redirect(url_for('dashboard'))

    commands, _ = generate_commands_for_scan(scan_id, models.get_db)
    cmd = next((c for c in commands if c['id'] == cmd_id), None)
    if not cmd:
        flash('الأمر غير موجود', 'danger')
        return redirect(url_for('scan_commands', scan_id=scan_id))

    if request.method == 'GET':
        return render_template('upload_output.html', scan=scan, cmd=cmd)

    content = ''
    output_file = request.files.get('output_file')
    paste_content = request.form.get('output_content', '').strip()

    if output_file and output_file.filename:
        content = output_file.read().decode('utf-8', errors='ignore')
    elif paste_content:
        content = paste_content

    if not content:
        flash('لم يتم تقديم أي مخرجات', 'danger')
        return redirect(url_for('upload_command_output', scan_id=scan_id, cmd_id=cmd_id))

    def save_func(sid, finding):
        c = models.get_db()
        c.execute(
            '''INSERT INTO finding_results
            (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (sid, finding['ip'], finding['port'], finding['finding_id'],
             finding['finding_name'], finding['severity'], finding['cvss'],
             finding.get('cve', ''), 1, finding['detail'],
             finding.get('command', ''), finding['category'])
        )
        c.commit()
        c.close()

    results = analyze_command_output(content, cmd, scan_id, save_func)
    if results:
        flash(f'تم تحليل المخرجات: {len(results)} ثغرة مكتشفة', 'success')
    else:
        flash('تم تحليل المخرجات: لا توجد ثغرات', 'info')
    return redirect(url_for('scan_commands', scan_id=scan_id))


@app.route('/scan/<int:scan_id>/upload-bulk', methods=['POST'])
@login_required
def upload_bulk_output(scan_id):
    scan = models.get_scan(scan_id)
    if not scan:
        flash('السكان غير موجود', 'error')
        return redirect(url_for('dashboard'))

    commands, _ = generate_commands_for_scan(scan_id, models.get_db)

    contents = []
    paste_content = request.form.get('paste_content', '').strip()
    if paste_content:
        contents.append(paste_content)

    files = request.files.getlist('output_files')
    for f in files:
        if f and f.filename:
            contents.append(f.read().decode('utf-8', errors='ignore'))

    if not contents:
        flash('لم يتم تقديم أي مخرجات', 'danger')
        return redirect(url_for('scan_commands', scan_id=scan_id))

    combined = '\n'.join(contents)

    def save_func(sid, finding):
        c = models.get_db()
        c.execute(
            '''INSERT INTO finding_results
            (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (sid, finding['ip'], finding['port'], finding['finding_id'],
             finding['finding_name'], finding['severity'], finding['cvss'],
             finding.get('cve', ''), 1, finding['detail'],
             finding.get('command', ''), finding['category'])
        )
        c.commit()
        c.close()

    total_findings = 0
    for cmd in commands:
        results = analyze_command_output(combined, cmd, scan_id, save_func)
        total_findings += len(results)

    flash(f'تحليل شامل: {total_findings} ثغرة مكتشفة', 'success')
    return redirect(url_for('scan_detail', scan_id=scan_id))


# --- Compare ---

@app.route('/compare')
@login_required
def compare():
    scans = models.get_user_scans(session['user_id'])
    scan1_id = request.args.get('scan1', type=int)
    scan2_id = request.args.get('scan2', type=int)

    scan1 = scan2 = None
    results1 = results2 = []
    findings1 = findings2 = []

    if scan1_id:
        scan1 = models.get_scan(scan1_id)
        results1 = models.get_scan_results(scan1_id)
        findings1 = models.get_finding_results(scan1_id)
    if scan2_id:
        scan2 = models.get_scan(scan2_id)
        results2 = models.get_scan_results(scan2_id)
        findings2 = models.get_finding_results(scan2_id)

    return render_template('compare.html', scans=scans,
                           scan1=scan1, scan2=scan2,
                           results1=results1, results2=results2,
                           findings1=findings1, findings2=findings2)


# --- Settings ---

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        for key in request.form:
            if key.startswith('setting_'):
                setting_key = key[8:]
                models.set_setting(setting_key, request.form[key])
        flash('Settings saved.', 'success')
        return redirect(url_for('settings'))

    all_settings = models.get_all_settings()
    version_db_date = None
    versions_file = os.path.join(os.path.dirname(__file__), '..', 'findings', 'latest_versions.json')
    try:
        if os.path.exists(versions_file):
            with open(versions_file) as f:
                vdata = json.load(f)
            version_db_date = vdata.get('updated_at', '')[:16].replace('T', ' ')
    except Exception:
        pass
    return render_template('settings.html', settings=all_settings, version_db_date=version_db_date)


@app.route('/settings/update-versions', methods=['POST'])
@login_required
def update_versions():
    import subprocess
    import sys
    script = os.path.join(os.path.dirname(__file__), '..', 'update_versions.py')
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True, text=True, timeout=120
        )
        flash('Version database updated successfully!', 'success')
    except subprocess.TimeoutExpired:
        flash('Update timed out after 2 minutes.', 'error')
    except Exception as e:
        flash(f'Update failed: {str(e)}', 'error')
    return redirect(url_for('settings'))


# --- Admin ---

@app.route('/admin/users')
@admin_required
def admin_users():
    users = models.get_all_users()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def update_role(user_id):
    role = request.form.get('role', 'user')
    if role in ('admin', 'user'):
        models.update_user_role(user_id, role)
        flash('User role updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user_route(user_id):
    if user_id == session['user_id']:
        flash('Cannot delete your own account.', 'error')
    else:
        models.delete_user(user_id)
        flash('User deleted.', 'success')
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    models.init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
