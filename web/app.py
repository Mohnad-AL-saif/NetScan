import os
import io
import csv
import re
import json
import signal
import subprocess
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
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

live_scans = {}

try:
    _conn = models.get_db()
    _conn.execute('ALTER TABLE scan_results ADD COLUMN scripts TEXT DEFAULT ""')
    _conn.commit()
    _conn.close()
except Exception:
    pass

try:
    _conn = models.get_db()
    _conn.execute('ALTER TABLE finding_results ADD COLUMN status TEXT DEFAULT "unknown"')
    _conn.commit()
    _conn.close()
except Exception:
    pass

try:
    _conn = models.get_db()
    _conn.execute('''CREATE TABLE IF NOT EXISTS scan_raw_output (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        phase TEXT NOT NULL,
        output_type TEXT DEFAULT 'xml',
        output TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )''')
    _conn.commit()
    _conn.close()
except Exception:
    pass


def classify_finding(vulnerable, detail, command):
    """Classify finding as 'vulnerable', 'safe', or 'error'."""
    detail_lower = (detail or '').lower()
    cmd = command or ''

    not_a_command = (
        cmd.startswith('Check ') or cmd.startswith('Send ') or
        cmd.startswith('Related') or cmd.startswith('~/') or
        cmd.startswith('Mount ') or cmd.startswith('OpenSSH ') or
        cmd.startswith('See ') or cmd.startswith('Look ') or
        cmd.startswith('Note') or cmd == 'SSH_AUTH_SOCK'
    )

    has_error = (
        '/bin/sh:' in detail_lower or
        'syntax error' in detail_lower or
        'file for logins not found' in detail_lower or
        'no such file' in detail_lower or
        detail_lower.strip() == 'timeout' or
        'not allowed' in detail_lower
    )

    if not_a_command or has_error:
        return 'error'
    elif vulnerable:
        false_indicators = ['not found', 'access denied', 'permission denied',
                            'connection refused', '404', 'timeout']
        if any(ind in detail_lower for ind in false_indicators):
            return 'error'
        return 'vulnerable'
    else:
        return 'safe'


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
    conn = models.get_db()
    stats = {
        'total_scans': conn.execute('SELECT COUNT(*) FROM scans WHERE user_id=?', (session['user_id'],)).fetchone()[0],
        'total_ips': conn.execute('SELECT COUNT(DISTINCT ip) FROM scan_results sr JOIN scans s ON sr.scan_id=s.id WHERE s.user_id=?', (session['user_id'],)).fetchone()[0],
        'total_services': conn.execute('SELECT COUNT(*) FROM scan_results sr JOIN scans s ON sr.scan_id=s.id WHERE s.user_id=?', (session['user_id'],)).fetchone()[0],
        'vuln_findings': conn.execute('SELECT COUNT(*) FROM finding_results fr JOIN scans s ON fr.scan_id=s.id WHERE s.user_id=? AND fr.vulnerable=1', (session['user_id'],)).fetchone()[0],
        'critical': conn.execute('SELECT COUNT(*) FROM finding_results fr JOIN scans s ON fr.scan_id=s.id WHERE s.user_id=? AND fr.vulnerable=1 AND fr.severity="Critical"', (session['user_id'],)).fetchone()[0],
    }

    top_ports = conn.execute('''
        SELECT sr.port, sr.service, COUNT(DISTINCT sr.ip) as host_count
        FROM scan_results sr JOIN scans s ON sr.scan_id=s.id
        WHERE s.user_id=?
        GROUP BY sr.port ORDER BY host_count DESC LIMIT 10
    ''', (session['user_id'],)).fetchall()

    critical_findings = conn.execute('''
        SELECT finding_name, severity, ip, port
        FROM finding_results fr JOIN scans s ON fr.scan_id=s.id
        WHERE s.user_id=? AND fr.vulnerable=1
        ORDER BY CASE fr.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, fr.finding_name
        LIMIT 15
    ''', (session['user_id'],)).fetchall()

    recent_scans = models.get_user_scans(session['user_id'], limit=5)
    scan_findings = {}
    for scan in recent_scans:
        scan_findings[scan['id']] = models.get_finding_stats(scan['id'])

    conn.close()
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans,
                           scan_findings=scan_findings, top_ports=top_ports,
                           critical_findings=critical_findings)


@app.route('/scan/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        targets = request.form.get('targets', '').strip()
        tcp_args = request.form.get('tcp_args', '-sS -p- --min-rate 5000 -T4 -n -Pn').strip()
        udp_scan = request.form.get('udp_scan') == 'on'
        udp_args = request.form.get('udp_args', '-sU --top-ports 100 --min-rate 3000 -T4 -n -Pn').strip()
        scan_mode = request.form.get('scan_mode', 'serial')
        max_threads = int(request.form.get('max_threads', 3))
        if max_threads < 1:
            max_threads = 1
        elif max_threads > 20:
            max_threads = 20

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
            'udp_enabled': udp_scan,
            'scan_mode': scan_mode
        }

        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, targets, tcp_args, udp_scan, udp_args, scan_mode, max_threads)
        )
        thread.daemon = True
        thread.start()

        return redirect(url_for('scan_detail', scan_id=scan_id))

    return render_template('new_scan.html')


def group_ports_across_ips(port_list):
    """Group discovered ports by port number across all IPs.
    Returns: [(port, proto, [{'ip': ip, 'service': svc}, ...]), ...]
    sorted by number of IPs sharing the port (most shared first).
    """
    groups = {}
    for p in port_list:
        key = (p['port'], p.get('protocol', 'tcp'))
        if key not in groups:
            groups[key] = []
        groups[key].append({'ip': p['ip'], 'service': p.get('service', '')})
    return sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)


def run_scan_background(scan_id, targets, tcp_args, udp_scan, udp_args, scan_mode='serial', max_threads=3):
    """Multi-phase scan with live updates, stop support, and dedup."""
    lock = threading.Lock()
    findings_db = findings_engine.load_findings()
    controller = ScanController(scan_id)
    workers = 1 if scan_mode == 'serial' else max_threads
    controller.executor = ThreadPoolExecutor(max_workers=max(workers, 5))
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

        tcp_port_groups = group_ports_across_ips(tcp_ports)
        group_summary = ', '.join(
            f':{port}({len(ips)}IPs)' for (port, _proto), ips in tcp_port_groups[:5]
        )
        live_scans[scan_id]['phase_label'] = f'TCP Version Detection — {group_summary}'

        port_numbers = list(set(p['port'] for p in tcp_ports))
        phase2_results, cmd2, phase2_xml = nmap_runner.run_phase2(targets, port_numbers, controller=controller)
        if cmd2:
            with lock:
                live_scans[scan_id]['cmds'].append(cmd2)

        if phase2_xml:
            try:
                _db = models.get_db()
                _db.execute('INSERT INTO scan_raw_output (scan_id, phase, output_type, output) VALUES (?,?,?,?)',
                            (scan_id, 'phase2_tcp_version', 'xml', phase2_xml))
                _db.commit()
                _db.close()
            except Exception:
                pass

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

        # === PHASE 2.5: Targeted NSE Scripts ===
        if phase2_results:
            live_scans[scan_id]['status'] = 'scripts'
            live_scans[scan_id]['phase_label'] = 'Running targeted scripts'
            try:
                svc_list = [dict(r) if hasattr(r, 'keys') else r for r in phase2_results]
                script_results, script_raw = nmap_runner.run_service_scripts(targets, svc_list)
                for stype, raw_xml in script_raw.items():
                    try:
                        _db = models.get_db()
                        _db.execute('INSERT INTO scan_raw_output (scan_id, phase, output_type, output) VALUES (?,?,?,?)',
                                    (scan_id, f'phase2.5_{stype}', 'xml', raw_xml))
                        _db.commit()
                        _db.close()
                    except Exception:
                        pass
                if script_results:
                    conn = models.get_db()
                    for key, output in script_results.items():
                        parts = key.split('/')
                        if len(parts) >= 2:
                            ip_port = parts[0]
                            script_name = parts[1]
                            if ':' in ip_port:
                                ip, port_str = ip_port.rsplit(':', 1)
                                try:
                                    existing = conn.execute(
                                        'SELECT scripts FROM scan_results WHERE scan_id=? AND ip=? AND port=?',
                                        (scan_id, ip, int(port_str))
                                    ).fetchone()
                                    if existing:
                                        current_scripts = existing['scripts'] or ''
                                        new_scripts = current_scripts + f'\n[{script_name}] {output}'
                                        conn.execute(
                                            'UPDATE scan_results SET scripts=? WHERE scan_id=? AND ip=? AND port=?',
                                            (new_scripts.strip(), scan_id, ip, int(port_str))
                                        )
                                except Exception:
                                    pass
                    conn.commit()
                    conn.close()
            except Exception as e:
                print(f"Script scan error: {e}")

        if controller.should_stop():
            raise Exception('Scan stopped by user')

        # Wait for all TCP findings to complete before starting UDP
        for future in finding_futures:
            try:
                future.result(timeout=30)
            except Exception:
                pass
        finding_futures.clear()

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

            udp_port_groups = group_ports_across_ips(udp_ports_data)
            udp_group_summary = ', '.join(
                f':{port}({len(ips)}IPs)' for (port, _proto), ips in udp_port_groups[:5]
            )
            live_scans[scan_id]['phase_label'] = f'UDP Version Detection — {udp_group_summary}'

            udp_port_numbers = list(set(p['port'] for p in udp_ports_data))
            udp_phase2_results, cmd4, udp_xml = nmap_runner.run_udp_phase2(targets, udp_port_numbers, controller=controller)
            if cmd4:
                with lock:
                    live_scans[scan_id]['cmds'].append(cmd4)

            if udp_xml:
                try:
                    _db = models.get_db()
                    _db.execute('INSERT INTO scan_raw_output (scan_id, phase, output_type, output) VALUES (?,?,?,?)',
                                (scan_id, 'phase4_udp_version', 'xml', udp_xml))
                    _db.commit()
                    _db.close()
                except Exception:
                    pass

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

        # === PHASE 5: Deep Enumeration (script-based) ===
        if not controller.should_stop():
            live_scans[scan_id]['status'] = 'deep_enum'
            live_scans[scan_id]['phase'] = 5
            live_scans[scan_id]['phase_label'] = 'Deep Service Enumeration'

            all_ports = live_scans[scan_id]['ports']
            deep_count = 0
            for p_data in all_ports:
                if controller.should_stop():
                    break
                p_ip = p_data['ip']
                p_port = p_data['port']
                p_proto = p_data.get('protocol', 'tcp')
                p_svc = p_data.get('service', '') or ''

                live_scans[scan_id]['phase_label'] = f'Deep Enum: {p_svc or "unknown"} on {p_ip}:{p_port}'

                try:
                    deep_findings, raw_out = nmap_runner.run_deep_enumeration(
                        p_ip, p_port, p_proto, p_svc, scan_id
                    )
                    if deep_findings:
                        deep_db = models.get_db()
                        for df in deep_findings:
                            try:
                                deep_db.execute(
                                    '''INSERT INTO finding_results
                                    (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category, status)
                                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                                    (scan_id, df['ip'], df['port'], df['finding_id'],
                                     df['finding_name'], df['severity'], df['cvss'],
                                     df.get('cve', ''), df['vulnerable'],
                                     (df.get('detail', '') or '')[:500],
                                     df.get('command', ''), df['category'],
                                     df.get('status', 'info'))
                                )
                                deep_count += 1
                            except Exception:
                                pass
                        deep_db.commit()
                        deep_db.close()

                        with lock:
                            for df in deep_findings:
                                if df.get('vulnerable'):
                                    live_scans[scan_id]['findings'].append(df)
                                    live_scans[scan_id]['vuln_count'] += 1
                                    sev = df['severity'].lower()
                                    if sev in live_scans[scan_id]['stats']:
                                        live_scans[scan_id]['stats'][sev] += 1
                            live_scans[scan_id]['finding_count'] += len(deep_findings)

                    if raw_out:
                        try:
                            _db = models.get_db()
                            _db.execute('INSERT INTO scan_raw_output (scan_id, phase, output_type, output) VALUES (?,?,?,?)',
                                        (scan_id, f'phase5_{p_svc}_{p_ip}_{p_port}', 'text', raw_out[:50000]))
                            _db.commit()
                            _db.close()
                        except Exception:
                            pass
                except Exception as e:
                    print(f"Deep enum error {p_ip}:{p_port}: {e}")

            live_scans[scan_id]['phase_label'] = f'Deep Enum complete — {deep_count} findings'

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
        'udp_enabled': data.get('udp_enabled', False),
        'scan_mode': data.get('scan_mode', 'serial')
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
        pct_map = {'phase1': 15, 'phase2': 35, 'scripts': 45, 'phase3': 55, 'phase4': 65, 'version_check': 70, 'deep_enum': 80, 'finishing': 95, 'done': 100, 'stopped': 100, 'error': 100}
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
    all_findings = models.get_finding_results(scan_id, vulnerable_only=False)
    for f in all_findings:
        if not f.get('status') or f['status'] == 'unknown':
            f['status'] = classify_finding(f.get('vulnerable'), f.get('detail'), f.get('command'))
    findings = [f for f in all_findings if f['status'] == 'vulnerable']
    finding_stats = models.get_finding_stats(scan_id)
    tab = request.args.get('tab', 'services')

    filter_counts = {
        'all': len(all_findings),
        'vulnerable': sum(1 for f in all_findings if f['status'] == 'vulnerable'),
        'safe': sum(1 for f in all_findings if f['status'] == 'safe'),
        'error': sum(1 for f in all_findings if f['status'] == 'error'),
    }

    is_live = scan_id in live_scans and live_scans[scan_id]['status'] not in ('done', 'error', 'stopped')

    return render_template('scan_detail.html',
                           scan=scan, results=results, findings=all_findings,
                           finding_stats=finding_stats, tab=tab, is_live=is_live,
                           filter_counts=filter_counts)


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
    if not scan:
        conn.close()
        flash('السكان غير موجود', 'error')
        return redirect(url_for('dashboard'))

    filter_type = request.args.get('filter', '')
    query = 'SELECT * FROM finding_results WHERE scan_id=?'
    params = [scan_id]

    if filter_type == 'vulnerable':
        query += " AND status = 'vulnerable'"
    elif filter_type == 'safe':
        query += " AND status = 'safe'"
    elif filter_type == 'error':
        query += " AND status NOT IN ('vulnerable', 'safe')"

    query += ' ORDER BY severity, ip, port'
    findings = conn.execute(query, params).fetchall()
    conn.close()

    fmt = request.args.get('format', 'csv')
    filter_suffix = f'_{filter_type}' if filter_type and filter_type != 'all' else ''

    if fmt == 'json':
        data = [dict(f) for f in findings]
        return Response(
            json.dumps(data, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=findings_scan_{scan_id}{filter_suffix}.json'}
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
            headers={'Content-Disposition': f'attachment; filename=findings_scan_{scan_id}{filter_suffix}.csv'}
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


@app.route('/scan/<int:scan_id>/export-raw-xml')
@login_required
def export_raw_xml(scan_id):
    import zipfile
    conn = models.get_db()
    rows = conn.execute(
        'SELECT phase, output_type, output, created_at FROM scan_raw_output WHERE scan_id=? ORDER BY id',
        (scan_id,)
    ).fetchall()
    conn.close()

    if not rows:
        flash('No raw output saved for this scan.', 'error')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            filename = f"{row['phase']}.{row['output_type']}"
            zf.writestr(filename, row['output'])
    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}_raw_output.zip'}
    )


def get_ssh_nmap_data(scripts_text):
    """Extract SSH data from nmap scripts output stored in scan_results.scripts."""
    if not scripts_text:
        return None

    data = {
        'auth_methods': [],
        'kex_algorithms': [],
        'ciphers': [],
        'macs': [],
        'host_key_types': [],
        'raw': scripts_text,
    }

    auth_match = re.findall(r'(?:authentication_methods|auth_methods)[:\s]+([^\n]+)', scripts_text, re.IGNORECASE)
    if auth_match:
        for m in auth_match:
            data['auth_methods'].extend([x.strip() for x in m.split(',')])

    if 'password' in scripts_text.lower() and ('auth' in scripts_text.lower() or 'authentication' in scripts_text.lower()):
        if 'password' not in data['auth_methods']:
            data['auth_methods'].append('password')

    kex_match = re.findall(r'kex_algorithms[:\s]+([^\n]+)', scripts_text, re.IGNORECASE)
    if kex_match:
        for m in kex_match:
            data['kex_algorithms'].extend([x.strip() for x in m.split(',')])

    cipher_match = re.findall(r'encryption_algorithms[:\s]+([^\n]+)', scripts_text, re.IGNORECASE)
    if cipher_match:
        for m in cipher_match:
            data['ciphers'].extend([x.strip() for x in m.split(',')])

    mac_match = re.findall(r'mac_algorithms[:\s]+([^\n]+)', scripts_text, re.IGNORECASE)
    if mac_match:
        for m in mac_match:
            data['macs'].extend([x.strip() for x in m.split(',')])

    hk_match = re.findall(r'server_host_key_algorithms[:\s]+([^\n]+)', scripts_text, re.IGNORECASE)
    if hk_match:
        for m in hk_match:
            data['host_key_types'].extend([x.strip() for x in m.split(',')])

    return data


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

    SCRIPT_FINDINGS = [
        ('ssl-heartbleed', 'VULNERABLE', 'Heartbleed Vulnerability (CVE-2014-0160)', 'Critical', 9.8, 'ssl_vuln'),
        ('ssl-poodle', 'VULNERABLE', 'POODLE Vulnerability (CVE-2014-3566)', 'High', 7.5, 'ssl_vuln'),
        ('ssl-ccs-injection', 'VULNERABLE', 'CCS Injection (CVE-2014-0224)', 'High', 7.4, 'ssl_vuln'),
        ('smb-vuln-ms17-010', 'VULNERABLE', 'EternalBlue (MS17-010)', 'Critical', 9.8, 'smb_vuln'),
        ('smb-vuln-ms08-067', 'VULNERABLE', 'MS08-067 (Conficker)', 'Critical', 9.8, 'smb_vuln'),
        ('smb-double-pulsar-backdoor', 'VULNERABLE', 'DoublePulsar Backdoor', 'Critical', 10.0, 'smb_vuln'),
        ('ftp-anon', 'Anonymous FTP login allowed', 'Anonymous FTP Login Allowed', 'High', 7.5, 'ftp_vuln'),
        ('ftp-vsftpd-backdoor', 'VULNERABLE', 'vsftpd 2.3.4 Backdoor', 'Critical', 9.8, 'ftp_vuln'),
        ('ftp-proftpd-backdoor', 'VULNERABLE', 'ProFTPd Backdoor', 'Critical', 9.8, 'ftp_vuln'),
        ('http-shellshock', 'VULNERABLE', 'Shellshock (CVE-2014-6271)', 'Critical', 9.8, 'http_vuln'),
        ('rdp-vuln-ms12-020', 'VULNERABLE', 'MS12-020 RDP Remote Code Execution', 'Critical', 9.3, 'rdp_vuln'),
        ('dns-zone-transfer', 'Transfer', 'DNS Zone Transfer Allowed', 'High', 7.5, 'dns_vuln'),
        ('smtp-open-relay', 'relay', 'SMTP Open Relay', 'High', 7.5, 'smtp_vuln'),
        ('realvnc-auth-bypass', 'VULNERABLE', 'RealVNC Authentication Bypass', 'Critical', 9.8, 'vnc_vuln'),
        ('mysql-empty-password', 'account has empty password', 'MySQL Empty Password', 'Critical', 9.8, 'database'),
        ('smb-vuln-conficker', 'VULNERABLE', 'Conficker Worm (MS08-067)', 'Critical', 9.8, 'smb_vuln'),
    ]

    for r in results:
        ip = r['ip']
        port = r['port']
        try:
            scripts_output = r['scripts'] or ''
        except (IndexError, KeyError):
            scripts_output = ''
        if not scripts_output:
            continue

        for script_id, match_str, finding_name, severity, cvss, category in SCRIPT_FINDINGS:
            if script_id in scripts_output and match_str.lower() in scripts_output.lower():
                if finding_name not in grouped:
                    grouped[finding_name] = {
                        'finding_name': finding_name,
                        'severity': severity,
                        'cvss': cvss,
                        'category': category,
                        'ips': set(),
                        'ports': set(),
                        'details': [],
                    }
                grouped[finding_name]['ips'].add(ip)
                grouped[finding_name]['ports'].add(port)
                detail = f'{finding_name} on {ip}:{port}'
                if detail not in grouped[finding_name]['details']:
                    grouped[finding_name]['details'].append(detail)

        if 'ssl-enum-ciphers' in scripts_output:
            if 'TLSv1.0' in scripts_output or 'SSLv3' in scripts_output:
                fname = 'Weak TLS/SSL Version Supported'
                if fname not in grouped:
                    grouped[fname] = {
                        'finding_name': fname,
                        'severity': 'Medium',
                        'cvss': 5.3,
                        'category': 'ssl_vuln',
                        'ips': set(),
                        'ports': set(),
                        'details': [],
                    }
                grouped[fname]['ips'].add(ip)
                grouped[fname]['ports'].add(port)
                weak = []
                if 'SSLv3' in scripts_output:
                    weak.append('SSLv3')
                if 'TLSv1.0' in scripts_output:
                    weak.append('TLSv1.0')
                detail = f'Weak protocols ({", ".join(weak)}) on {ip}:{port}'
                if detail not in grouped[fname]['details']:
                    grouped[fname]['details'].append(detail)

    for r in results:
        ip = r['ip']
        port = r['port']
        try:
            scripts_text = r['scripts'] or ''
        except (IndexError, KeyError):
            scripts_text = ''
        if not scripts_text or port != 22:
            continue

        ssh_data = get_ssh_nmap_data(scripts_text)
        if not ssh_data:
            continue

        if 'password' in ssh_data['auth_methods']:
            fname = 'SSH Password Authentication Enabled'
            if fname not in grouped:
                grouped[fname] = {'finding_name': fname, 'severity': 'Medium', 'cvss': 5.3,
                                  'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
            grouped[fname]['ips'].add(ip)
            grouped[fname]['ports'].add(port)
            detail = f'Auth methods: {", ".join(ssh_data["auth_methods"])} on {ip}:{port}'
            if detail not in grouped[fname]['details']:
                grouped[fname]['details'].append(detail)

        if 'keyboard-interactive' in ssh_data['auth_methods']:
            fname = 'SSH Keyboard-Interactive Auth Enabled'
            if fname not in grouped:
                grouped[fname] = {'finding_name': fname, 'severity': 'Low', 'cvss': 3.7,
                                  'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
            grouped[fname]['ips'].add(ip)
            grouped[fname]['ports'].add(port)

        cbc_ciphers = [c for c in ssh_data['ciphers'] if 'cbc' in c.lower()]
        if cbc_ciphers:
            fname = 'SSH CBC Mode Ciphers Enabled'
            sev = 'High' if any('3des' in c for c in cbc_ciphers) else 'Medium'
            cvss = 7.5 if sev == 'High' else 5.3
            if fname not in grouped:
                grouped[fname] = {'finding_name': fname, 'severity': sev, 'cvss': cvss,
                                  'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
            grouped[fname]['ips'].add(ip)
            grouped[fname]['ports'].add(port)
            detail = f'CBC ciphers: {", ".join(cbc_ciphers)} on {ip}:{port}'
            if detail not in grouped[fname]['details']:
                grouped[fname]['details'].append(detail)

        weak_kex = {
            'diffie-hellman-group1-sha1': ('Medium', 5.3),
            'diffie-hellman-group-exchange-sha1': ('Medium', 5.3),
            'diffie-hellman-group14-sha1': ('Low', 3.7),
        }
        for kex in ssh_data['kex_algorithms']:
            kex_clean = kex.strip()
            if kex_clean in weak_kex:
                sev, cvss = weak_kex[kex_clean]
                fname = f'SSH Weak Key Exchange ({kex_clean})'
                if fname not in grouped:
                    grouped[fname] = {'finding_name': fname, 'severity': sev, 'cvss': cvss,
                                      'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
                grouped[fname]['ips'].add(ip)
                grouped[fname]['ports'].add(port)

        weak_macs = {
            'hmac-md5': ('Medium', 5.3),
            'hmac-md5-96': ('Medium', 5.3),
            'hmac-sha1': ('Low', 3.7),
            'hmac-sha1-96': ('Medium', 5.3),
            'umac-64': ('Low', 3.7),
            'umac-64@openssh.com': ('Low', 3.7),
        }
        for mac in ssh_data['macs']:
            mac_clean = mac.strip().lower()
            for weak_name, (sev, cvss) in weak_macs.items():
                if weak_name in mac_clean:
                    fname = f'SSH Weak MAC ({mac.strip()})'
                    if fname not in grouped:
                        grouped[fname] = {'finding_name': fname, 'severity': sev, 'cvss': cvss,
                                          'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
                    grouped[fname]['ips'].add(ip)
                    grouped[fname]['ports'].add(port)
                    break

        arcfour_ciphers = [c for c in ssh_data['ciphers'] if 'arcfour' in c.lower()]
        if arcfour_ciphers:
            fname = 'SSH Weak Encryption (arcfour)'
            if fname not in grouped:
                grouped[fname] = {'finding_name': fname, 'severity': 'Medium', 'cvss': 5.3,
                                  'category': 'ssh_config', 'ips': set(), 'ports': set(), 'details': []}
            grouped[fname]['ips'].add(ip)
            grouped[fname]['ports'].add(port)

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

    def _tool_exists(name):
        return subprocess.run(f'which {name}', shell=True, capture_output=True).returncode == 0

    def _run_cmd(cmd, timeout=15):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            return f'Error: {e}'

    def _save_svc_finding(fid, name, ip, port, sev, cvss, vuln, detail, cmd, cat, cve=None):
        nonlocal count
        status = classify_finding(vuln, detail, cmd)
        c.execute(
            '''INSERT INTO finding_results
            (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (scan_id, ip, port, fid, name, sev, cvss, cve or '', vuln, (detail or '')[:500], cmd, cat, status)
        )
        count += 1

    for r in results:
        ip = r['ip']
        port = r['port']
        service = (r['service'] or '').lower()
        banner = (r['banner'] or '').lower()

        # === MongoDB ===
        if 'mongo' in service or port in (27017, 27018, 27019):
            if _tool_exists('mongosh'):
                out = _run_cmd(f'mongosh --host {ip} --port {port} --eval "db.adminCommand(\'listDatabases\')" --quiet 2>&1')
                if out is None:
                    _save_svc_finding('FIND-MONGO-NOAUTH', 'MongoDB No Authentication', ip, port,
                                      'Critical', 9.8, 0, 'Connection timed out',
                                      f'mongosh --host {ip} --port {port} --eval "db.adminCommand(\'listDatabases\')" --quiet',
                                      'authentication')
                elif 'databases' in out.lower() or '"name"' in out:
                    _save_svc_finding('FIND-MONGO-NOAUTH', 'MongoDB No Authentication', ip, port,
                                      'Critical', 9.8, 1, f'MongoDB accepts connections without authentication!\n{out[:400]}',
                                      f'mongosh --host {ip} --port {port} --eval "db.adminCommand(\'listDatabases\')" --quiet',
                                      'authentication')
                    out2 = _run_cmd(f'mongosh --host {ip} --port {port} --eval "JSON.stringify(db.adminCommand(\'listDatabases\'))" --quiet 2>&1')
                    if out2 and ('"name"' in out2 or 'databases' in out2.lower()):
                        try:
                            db_info = json.loads(out2)
                            db_names = [d['name'] for d in db_info.get('databases', [])]
                            total_size = db_info.get('totalSize', 0)
                            detail3 = f'Databases: {", ".join(db_names)}\nTotal size: {total_size / 1024 / 1024:.1f} MB'
                        except Exception:
                            detail3 = f'Raw output: {out2[:300]}'
                        _save_svc_finding('FIND-MONGO-DATA', 'MongoDB Data Exposure', ip, port,
                                          'Critical', 9.8, 1, detail3,
                                          f'mongosh --host {ip} --port {port} --eval "db.adminCommand(\'listDatabases\')" --quiet',
                                          'data_exposure')
                    out4 = _run_cmd(f'mongosh --host {ip} --port {port} --eval "JSON.stringify(rs.status())" --quiet 2>&1')
                    if out4 and '"members"' in out4:
                        _save_svc_finding('FIND-MONGO-REPL', 'MongoDB Replica Set Exposed', ip, port,
                                          'High', 7.5, 1, f'Replica set info accessible: {out4[:300]}',
                                          f'mongosh --host {ip} --port {port} --eval "rs.status()" --quiet',
                                          'info_disclosure')
                else:
                    vuln = 0
                    if 'auth' in out.lower() or 'unauthorized' in out.lower():
                        det = f'Authentication required: {out[:200]}'
                    else:
                        det = f'Connection result: {out[:200]}'
                    _save_svc_finding('FIND-MONGO-NOAUTH', 'MongoDB No Authentication', ip, port,
                                      'Critical', 9.8, vuln, det,
                                      f'mongosh --host {ip} --port {port} --eval "db.adminCommand(\'listDatabases\')" --quiet',
                                      'authentication')

        # === etcd ===
        if 'etcd' in service or port in (2379, 2380, 2381):
            proto = 'https' if port in (2379, 2380) else 'http'
            out = _run_cmd(f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/version 2>&1')
            if out and ('etcdserver' in out.lower() or 'etcdcluster' in out.lower()):
                _save_svc_finding('FIND-ETCD-VER', 'etcd Version Disclosure', ip, port,
                                  'Medium', 5.3, 1, f'etcd version exposed: {out[:200]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/version',
                                  'info_disclosure')
            else:
                _save_svc_finding('FIND-ETCD-VER', 'etcd Version Disclosure', ip, port,
                                  'Medium', 5.3, 0, f'Response: {(out or "Connection failed")[:200]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/version',
                                  'info_disclosure')

            if port == 2379:
                out2 = _run_cmd(f'curl -sk --connect-timeout 5 -X POST {proto}://{ip}:{port}/v3/kv/range -d \'{{"key":"AA=="}}\' 2>&1')
                if out2 and ('"kvs"' in out2 or '"key"' in out2):
                    _save_svc_finding('FIND-ETCD-READ', 'etcd Anonymous Data Access', ip, port,
                                      'Critical', 9.8, 1, f'etcd allows anonymous data read!\n{out2[:300]}',
                                      f'curl -sk --connect-timeout 5 -X POST {proto}://{ip}:{port}/v3/kv/range',
                                      'data_exposure')
                elif out2:
                    _save_svc_finding('FIND-ETCD-READ', 'etcd Anonymous Data Access', ip, port,
                                      'Critical', 9.8, 0, f'Response: {out2[:200]}',
                                      f'curl -sk --connect-timeout 5 -X POST {proto}://{ip}:{port}/v3/kv/range',
                                      'data_exposure')

            if port == 2381:
                out3 = _run_cmd(f'curl -s --connect-timeout 5 http://{ip}:{port}/health 2>&1')
                if out3 and ('health' in out3.lower() or 'true' in out3.lower()):
                    _save_svc_finding('FIND-ETCD-HEALTH', 'etcd Health Endpoint Exposed', ip, port,
                                      'Low', 3.7, 1, f'Health endpoint accessible: {out3[:200]}',
                                      f'curl -s --connect-timeout 5 http://{ip}:{port}/health',
                                      'info_disclosure')
                out4 = _run_cmd(f'curl -s --connect-timeout 5 http://{ip}:{port}/metrics 2>&1 | head -20')
                if out4 and ('etcd_' in out4 or 'grpc_' in out4 or 'process_' in out4):
                    _save_svc_finding('FIND-ETCD-METRICS', 'etcd Metrics Exposed', ip, port,
                                      'Medium', 5.3, 1, f'Metrics accessible:\n{out4[:300]}',
                                      f'curl -s --connect-timeout 5 http://{ip}:{port}/metrics | head -20',
                                      'info_disclosure')

        # === Kubernetes API ===
        if port in (6443, 8443) or 'kubernetes' in service:
            out = _run_cmd(f'curl -sk --connect-timeout 5 https://{ip}:{port}/version 2>&1')
            if out and ('"major"' in out or '"gitVersion"' in out):
                _save_svc_finding('FIND-K8S-VER', 'Kubernetes API Version Disclosure', ip, port,
                                  'Medium', 5.3, 1, f'K8s API version exposed: {out[:300]}',
                                  f'curl -sk --connect-timeout 5 https://{ip}:{port}/version',
                                  'info_disclosure')
            else:
                _save_svc_finding('FIND-K8S-VER', 'Kubernetes API Version Disclosure', ip, port,
                                  'Medium', 5.3, 0, f'Response: {(out or "Connection failed")[:200]}',
                                  f'curl -sk --connect-timeout 5 https://{ip}:{port}/version',
                                  'info_disclosure')

            out2 = _run_cmd(f'curl -sk --connect-timeout 5 https://{ip}:{port}/api/v1/namespaces 2>&1')
            if out2 and ('"items"' in out2 or '"namespaces"' in out2.lower()):
                _save_svc_finding('FIND-K8S-ANON', 'Kubernetes Anonymous API Access', ip, port,
                                  'Critical', 9.8, 1, f'K8s API allows anonymous namespace listing!\n{out2[:300]}',
                                  f'curl -sk --connect-timeout 5 https://{ip}:{port}/api/v1/namespaces',
                                  'authentication')
                out3 = _run_cmd(f'curl -sk --connect-timeout 5 https://{ip}:{port}/api/v1/secrets 2>&1')
                if out3 and '"items"' in out3 and 'secret' in out3.lower():
                    _save_svc_finding('FIND-K8S-SECRETS', 'Kubernetes Secrets Readable', ip, port,
                                      'Critical', 9.8, 1, f'K8s secrets accessible anonymously!\n{out3[:300]}',
                                      f'curl -sk --connect-timeout 5 https://{ip}:{port}/api/v1/secrets',
                                      'data_exposure')
            elif out2:
                vuln2 = 0
                if 'forbidden' in out2.lower() or 'unauthorized' in out2.lower():
                    det2 = f'Access denied (good): {out2[:200]}'
                else:
                    det2 = f'Response: {out2[:200]}'
                _save_svc_finding('FIND-K8S-ANON', 'Kubernetes Anonymous API Access', ip, port,
                                  'Critical', 9.8, vuln2, det2,
                                  f'curl -sk --connect-timeout 5 https://{ip}:{port}/api/v1/namespaces',
                                  'authentication')

        # === Kubelet ===
        if port in (10250, 10255) or 'kubelet' in service:
            proto = 'https' if port == 10250 else 'http'
            out = _run_cmd(f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/pods 2>&1')
            if out and ('"items"' in out or '"metadata"' in out):
                _save_svc_finding('FIND-KUBELET-PODS', 'Kubelet Pods Endpoint Exposed', ip, port,
                                  'High', 7.5, 1, f'Kubelet pods endpoint accessible!\n{out[:300]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/pods',
                                  'info_disclosure')
            elif out:
                vuln = 0
                det = f'Access denied (good): {out[:200]}' if ('unauthorized' in out.lower() or 'forbidden' in out.lower()) else f'Response: {out[:200]}'
                _save_svc_finding('FIND-KUBELET-PODS', 'Kubelet Pods Endpoint Exposed', ip, port,
                                  'High', 7.5, vuln, det,
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/pods',
                                  'info_disclosure')
            out2 = _run_cmd(f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/metrics 2>&1 | head -20')
            if out2 and ('kubelet_' in out2 or 'apiserver_' in out2 or 'process_' in out2):
                _save_svc_finding('FIND-KUBELET-METRICS', 'Kubelet Metrics Exposed', ip, port,
                                  'Medium', 5.3, 1, f'Kubelet metrics accessible:\n{out2[:300]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/metrics | head -20',
                                  'info_disclosure')

        # === OpenSearch/Elasticsearch ===
        if 'elastic' in service or 'opensearch' in service or port in (9200, 9300):
            proto = 'https' if port == 9200 else 'http'
            out = _run_cmd(f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/ 2>&1')
            if out and ('"cluster_name"' in out or '"version"' in out):
                _save_svc_finding('FIND-ES-NOAUTH', 'OpenSearch/Elasticsearch No Authentication', ip, port,
                                  'Critical', 9.8, 1, f'OpenSearch/ES accessible without auth!\n{out[:300]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/',
                                  'authentication')
                out3 = _run_cmd(f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/_cat/indices?v 2>&1')
                if out3 and ('green' in out3 or 'yellow' in out3 or 'red' in out3):
                    _save_svc_finding('FIND-ES-INDICES', 'OpenSearch Indices Exposed', ip, port,
                                      'High', 7.5, 1, f'Indices accessible:\n{out3[:500]}',
                                      f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/_cat/indices?v',
                                      'data_exposure')
            else:
                _save_svc_finding('FIND-ES-NOAUTH', 'OpenSearch/Elasticsearch No Authentication', ip, port,
                                  'Critical', 9.8, 0, f'Response: {(out or "Connection failed")[:200]}',
                                  f'curl -sk --connect-timeout 5 {proto}://{ip}:{port}/',
                                  'authentication')

            out2 = _run_cmd(f'curl -sk --connect-timeout 5 -u admin:admin {proto}://{ip}:{port}/ 2>&1')
            if out2 and '"cluster_name"' in out2:
                _save_svc_finding('FIND-ES-DEFCRED', 'OpenSearch Default Credentials (admin:admin)', ip, port,
                                  'Critical', 9.8, 1, f'Default admin:admin credentials work!\n{out2[:300]}',
                                  f'curl -sk --connect-timeout 5 -u admin:admin {proto}://{ip}:{port}/',
                                  'authentication')

        # === MariaDB/MySQL ===
        if 'mysql' in service or 'maria' in service or port in (3306,):
            if _tool_exists('mysql'):
                out = _run_cmd(f'mysql -h {ip} -P {port} -u root --connect-timeout=5 -e "SELECT VERSION(); SHOW DATABASES;" 2>&1')
                if out is None:
                    _save_svc_finding('FIND-MYSQL-NOPASS', 'MySQL/MariaDB Root No Password', ip, port,
                                      'Critical', 9.8, 0, 'Connection timed out',
                                      f'mysql -h {ip} -P {port} -u root --connect-timeout=5 -e "SELECT VERSION();"',
                                      'authentication')
                elif 'version()' in out.lower() or 'information_schema' in out.lower():
                    _save_svc_finding('FIND-MYSQL-NOPASS', 'MySQL/MariaDB Root No Password', ip, port,
                                      'Critical', 9.8, 1, f'MySQL root login without password!\n{out[:300]}',
                                      f'mysql -h {ip} -P {port} -u root --connect-timeout=5 -e "SELECT VERSION(); SHOW DATABASES;"',
                                      'authentication')
                else:
                    det = f'Root login denied (good): {out[:200]}' if 'access denied' in out.lower() else f'Response: {out[:200]}'
                    _save_svc_finding('FIND-MYSQL-NOPASS', 'MySQL/MariaDB Root No Password', ip, port,
                                      'Critical', 9.8, 0, det,
                                      f'mysql -h {ip} -P {port} -u root --connect-timeout=5 -e "SELECT VERSION();"',
                                      'authentication')

                out2 = _run_cmd(f"mysql -h {ip} -P {port} -u root -p'root' --connect-timeout=5 -e \"SELECT VERSION();\" 2>&1")
                if out2 and 'version()' in out2.lower() and 'access denied' not in out2.lower():
                    _save_svc_finding('FIND-MYSQL-DEFCRED', 'MySQL Default Credentials (root:root)', ip, port,
                                      'Critical', 9.8, 1, f'Default root:root credentials work!\n{out2[:200]}',
                                      f"mysql -h {ip} -P {port} -u root -p'root' --connect-timeout=5 -e \"SELECT VERSION();\"",
                                      'authentication')

        # === Prometheus / Node Exporter ===
        if port in (9090, 9100) or 'prometheus' in service:
            out = _run_cmd(f'curl -s --connect-timeout 5 http://{ip}:{port}/metrics 2>&1 | head -20')
            if out and ('node_' in out or 'process_' in out or 'go_' in out or 'prometheus_' in out):
                _save_svc_finding('FIND-PROM-METRICS', 'Prometheus Metrics Exposed', ip, port,
                                  'Medium', 5.3, 1, f'Metrics endpoint accessible:\n{out[:400]}',
                                  f'curl -s --connect-timeout 5 http://{ip}:{port}/metrics | head -20',
                                  'info_disclosure')

        # === Tomcat ===
        if 'tomcat' in service or 'coyote' in service or 'tomcat' in banner:
            proto = 'https' if 'ssl' in banner else 'http'
            for user, passwd in [('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager')]:
                auth = f'-u {user}:{passwd}'
                out = _run_cmd(f'curl -sk --connect-timeout 5 {auth} {proto}://{ip}:{port}/manager/html 2>&1')
                if out and '401' not in out and '403' not in out and ('manager' in out.lower() or 'deploy' in out.lower()):
                    _save_svc_finding(f'FIND-TOMCAT-CRED-{user}', f'Tomcat Manager Default Credentials ({user}:{passwd})', ip, port,
                                      'Critical', 9.8, 1, f'Tomcat Manager accessible with {user}:{passwd}!\n{out[:200]}',
                                      f'curl -sk --connect-timeout 5 {auth} {proto}://{ip}:{port}/manager/html',
                                      'authentication')
                    break

        # === gRPC ===
        if 'grpc' in service:
            if _tool_exists('grpcurl'):
                out = _run_cmd(f'grpcurl -plaintext {ip}:{port} list 2>&1')
                if out and 'failed' not in out.lower() and 'error' not in out.lower() and out.strip():
                    _save_svc_finding('FIND-GRPC-LIST', 'gRPC Services Exposed', ip, port,
                                      'Medium', 5.3, 1, f'gRPC services listed:\n{out[:400]}',
                                      f'grpcurl -plaintext {ip}:{port} list',
                                      'info_disclosure')

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


# --- IP Profile ---

@app.route('/ip/<ip_address>')
@login_required
def ip_profile(ip_address):
    conn = models.get_db()
    results = conn.execute('''
        SELECT sr.*, s.id as scan_id, s.name as scan_name, s.created_at as scan_date
        FROM scan_results sr JOIN scans s ON sr.scan_id = s.id
        WHERE sr.ip = ? AND s.user_id = ?
        ORDER BY s.id DESC, sr.port
    ''', (ip_address, session['user_id'])).fetchall()

    findings = conn.execute('''
        SELECT fr.* FROM finding_results fr
        JOIN scans s ON fr.scan_id = s.id
        WHERE fr.ip LIKE ? AND s.user_id = ? AND fr.vulnerable = 1
        ORDER BY CASE fr.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END
    ''', (f'%{ip_address}%', session['user_id'])).fetchall()

    scan_history = conn.execute('''
        SELECT DISTINCT s.id, s.name, s.created_at, s.status,
               COUNT(sr.id) as port_count
        FROM scans s JOIN scan_results sr ON s.id = sr.scan_id
        WHERE sr.ip = ? AND s.user_id = ?
        GROUP BY s.id ORDER BY s.id DESC
    ''', (ip_address, session['user_id'])).fetchall()

    seen_ports = set()
    latest_results = []
    for r in results:
        if r['port'] not in seen_ports:
            seen_ports.add(r['port'])
            latest_results.append(r)

    conn.close()
    return render_template('ip_profile.html', ip=ip_address,
                           results=latest_results, findings=findings,
                           history=scan_history)


# --- Service Inventory ---

@app.route('/inventory')
@login_required
def inventory():
    conn = models.get_db()
    services = conn.execute('''
        SELECT sr.service, sr.port, sr.banner,
               COUNT(DISTINCT sr.ip) as host_count,
               GROUP_CONCAT(DISTINCT sr.ip) as ips
        FROM scan_results sr JOIN scans s ON sr.scan_id = s.id
        WHERE s.user_id = ?
        GROUP BY sr.service, sr.port
        ORDER BY host_count DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('inventory.html', services=services)


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
    diff = None

    if scan1_id:
        scan1 = models.get_scan(scan1_id)
        results1 = models.get_scan_results(scan1_id)
        findings1 = models.get_finding_results(scan1_id)
    if scan2_id:
        scan2 = models.get_scan(scan2_id)
        results2 = models.get_scan_results(scan2_id)
        findings2 = models.get_finding_results(scan2_id)

    if scan1 and scan2:
        svc_a = {(r['ip'], r['port']): r for r in results1}
        svc_b = {(r['ip'], r['port']): r for r in results2}
        keys_a, keys_b = set(svc_a.keys()), set(svc_b.keys())

        new_services = [svc_b[k] for k in sorted(keys_b - keys_a)]
        removed_services = [svc_a[k] for k in sorted(keys_a - keys_b)]

        changed_banners = []
        for k in sorted(keys_a & keys_b):
            a, b = svc_a[k], svc_b[k]
            old_banner = (a['banner'] or '')
            new_banner = (b['banner'] or '')
            old_svc = (a['service'] or '')
            new_svc = (b['service'] or '')
            if old_banner != new_banner or old_svc != new_svc:
                changed_banners.append({
                    'ip': k[0], 'port': k[1],
                    'old_service': old_svc, 'new_service': new_svc,
                    'old_banner': old_banner, 'new_banner': new_banner,
                })

        find_a = {(f['finding_name'], f['port']) for f in findings1}
        find_b = {(f['finding_name'], f['port']) for f in findings2}
        find_b_map = {(f['finding_name'], f['port']): f for f in findings2}
        find_a_map = {(f['finding_name'], f['port']): f for f in findings1}
        new_findings = [find_b_map[k] for k in sorted(find_b - find_a)]
        resolved_findings = [find_a_map[k] for k in sorted(find_a - find_b)]

        diff = {
            'new_services': new_services,
            'removed_services': removed_services,
            'changed_banners': changed_banners,
            'new_findings': new_findings,
            'resolved_findings': resolved_findings,
            'total_a': len(results1),
            'total_b': len(results2),
            'findings_a': len(findings1),
            'findings_b': len(findings2),
        }

    return render_template('compare.html', scans=scans,
                           scan1=scan1, scan2=scan2,
                           results1=results1, results2=results2,
                           findings1=findings1, findings2=findings2,
                           diff=diff)


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
