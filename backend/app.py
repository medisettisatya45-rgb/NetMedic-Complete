import os
import re
import time
import socket
import sqlite3
import ipaddress
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, jsonify, request
from flask_cors import CORS
import dns.resolver
import psutil

BASE = Path(__file__).resolve().parent
DB = BASE / 'netmedic.db'
app = Flask(__name__)
CORS(app, resources={r'/api/*': {'origins': ['http://localhost:5173', 'http://127.0.0.1:5173']}})
# Explicit allowlist: change through environment variable only, never via an unauthenticated API.
DEFAULT_TARGETS = '127.0.0.1,1.1.1.1,8.8.8.8,example.com,localhost'
ALLOWED_TARGETS = {x.strip().lower() for x in os.environ.get('NETMEDIC_TARGETS', DEFAULT_TARGETS).split(',') if x.strip()}
ALLOWED_PORTS = {53, 80, 443, 5000, 5173}
executor = ThreadPoolExecutor(max_workers=3)

def connect():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS diagnostics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target TEXT NOT NULL,
            score INTEGER,
            severity TEXT NOT NULL,
            issue TEXT NOT NULL,
            ping_ms REAL,
            packet_loss REAL,
            dns_ms REAL,
            tcp_ms REAL,
            payload TEXT NOT NULL
        )''')
        db.commit()


def safe_target(target):
    if not isinstance(target, str) or len(target) > 253:
        return False
    target = target.strip().lower()
    if target not in ALLOWED_TARGETS:
        return False
    if not re.fullmatch(r'[a-z0-9][a-z0-9.:-]*', target):
        return False
    return True

def resolve_target(target):
    # Resolve immediately before connecting; validate all resolved addresses.
    infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    addresses = sorted({x[4][0] for x in infos})
    if not addresses:
        raise ValueError('No address returned')
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local:
            raise ValueError('Target resolves to a restricted address')
        if ip.is_private or ip.is_loopback:
            # Only explicit local names/IPs configured by the server operator.
            if target not in ALLOWED_TARGETS:
                raise ValueError('Local target not approved')
    return addresses

def ping_test(target):
    flag = '-n' if platform.system() == 'Windows' else '-c'
    times = []
    failures = 0
    errors = []
    for _ in range(3):
        start = time.monotonic()
        try:
            args = ['ping', flag, '1']
            if platform.system() == 'Windows':
                args += ['-w', '1500']
            else:
                args += ['-W', '2']
            args.append(target)
            proc = subprocess.run(args, capture_output=True, text=True, timeout=4, shell=False)
            if proc.returncode == 0:
                # Wall-clock elapsed is a cross-platform approximation, including process overhead.
                times.append(round((time.monotonic()-start)*1000, 1))
            else:
                failures += 1
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures += 1
            errors.append(str(exc))
    return {'status': 'ok' if times else 'failed', 'latency_ms': round(sum(times)/len(times),1) if times else None,
            'packet_loss': round(failures/3*100,1), 'sent': 3, 'received': len(times),
            'note': 'Latency includes ping command startup overhead.', 'error': errors[0] if errors else None}

def dns_test(target):
    start = time.monotonic()
    try:
        # Explicit A/AAAA DNS query rather than system hosts-file resolution.
        if target == 'localhost' or re.fullmatch(r'[0-9.:]+', target):
            domain = 'example.com'
        else:
            domain = target
        answers = dns.resolver.resolve(domain, 'A', lifetime=3)
        ips = [str(a) for a in answers]
        return {'status': 'ok', 'domain': domain, 'addresses': ips,
                'latency_ms': round((time.monotonic()-start)*1000,1)}
    except Exception as exc:
        return {'status': 'failed', 'domain': domain, 'addresses': [], 'latency_ms': None, 'error': str(exc)[:200]}

def tcp_test(target, port):
    start = time.monotonic()
    try:
        addresses = resolve_target(target)
        # Connect to validated numeric address, never resolve again inside socket.create_connection.
        with socket.create_connection((addresses[0], port), timeout=3):
            pass
        return {'status': 'ok', 'port': port, 'latency_ms': round((time.monotonic()-start)*1000,1)}
    except (OSError, ValueError) as exc:
        return {'status': 'failed', 'port': port, 'latency_ms': None, 'error': str(exc)[:200]}

def diagnosis(ping, dns_result, tcp):
    steps = []
    score = 100
    if ping['packet_loss'] == 100:
        score -= 35
        steps.append('ICMP probes failed. Check connectivity or whether the destination blocks ping.')
    elif ping['packet_loss'] > 0:
        score -= 20
        steps.append('Intermittent ICMP replies: check Wi-Fi signal, cables, and network congestion.')
    if ping['latency_ms'] is not None and ping['latency_ms'] > 200:
        score -= 20
        steps.append('High ping elapsed time: check congestion and compare multiple test targets.')
    if dns_result['status'] != 'ok':
        score -= 25
        steps.append('DNS lookup failed: check DNS resolver configuration and internet connectivity.')
    if tcp['status'] != 'ok':
        score -= 20
        steps.append('TCP connection failed: check the destination service, port, and firewall rules.')
    if not steps:
        steps = ['No issues detected in these checks. Continue monitoring if problems are intermittent.']
    score = max(0,score)
    severity = 'Healthy' if score >= 90 else 'Good' if score >= 75 else 'Warning' if score >= 50 else 'Critical'
    issue = 'No significant issues detected' if score >= 90 else ('Potential connectivity or service issue' if score >= 50 else 'Multiple diagnostic checks failed')
    return {'score':score,'severity':severity,'issue':issue,'recommendations':steps,
            'disclaimer':'These checks suggest possible causes, not a definitive root cause. ICMP may be blocked.'}

def do_diagnosis(target, port):
    ping = ping_test(target)
    dns_result = dns_test(target)
    tcp = tcp_test(target, port)
    analysis = diagnosis(ping,dns_result,tcp)
    return {'target':target,'timestamp':datetime.now(timezone.utc).isoformat(),
            'ping':ping,'dns':dns_result,'tcp':tcp,**analysis}

@app.get('/')
def home():
    return jsonify(project='NetMedic',status='success',message='NetMedic API is running',frontend='http://localhost:5173')

@app.get('/api/health')
def health():
    return jsonify(status='ok',project='NetMedic',time=datetime.now(timezone.utc).isoformat())

@app.get('/api/targets')
def targets():
    return jsonify(targets=sorted(ALLOWED_TARGETS),ports=sorted(ALLOWED_PORTS))

@app.get('/api/network/status')
def network_status():
    stats=psutil.net_io_counters()
    return jsonify(hostname=socket.gethostname(),bytes_sent=stats.bytes_sent,bytes_recv=stats.bytes_recv,
                   interfaces=[{'name':k,'is_up':v.isup,'speed_mbps':v.speed} for k,v in psutil.net_if_stats().items()],
                   note='Network statistics are from the computer running the Flask backend.')

@app.post('/api/diagnostics/run')
def run_diagnostics():
    body=request.get_json(silent=True) or {}
    target=body.get('target','')
    port=body.get('port',443)
    if not safe_target(target) or type(port) is not int or port not in ALLOWED_PORTS:
        return jsonify(error='Target or port is not on the server-approved allowlist.'),400
    target=target.strip().lower()
    # Guard against DNS rebinding to restricted destinations for non-local targets.
    try:
        resolve_target(target)
    except (OSError,ValueError) as exc:
        return jsonify(error=f'Target resolution failed: {str(exc)[:150]}'),400
    try:
        result=executor.submit(do_diagnosis,target,port).result(timeout=25)
    except Exception as exc:
        return jsonify(error=f'Diagnostic failed: {str(exc)[:160]}'),500
    import json
    with connect() as db:
        cur=db.execute('''INSERT INTO diagnostics(timestamp,target,score,severity,issue,ping_ms,packet_loss,dns_ms,tcp_ms,payload)
            VALUES(?,?,?,?,?,?,?,?,?,?)''',(result['timestamp'],target,result['score'],result['severity'],result['issue'],
            result['ping']['latency_ms'],result['ping']['packet_loss'],result['dns']['latency_ms'],result['tcp']['latency_ms'],json.dumps(result)))
        db.commit()
        result['id']=cur.lastrowid
    return jsonify(result)

@app.get('/api/diagnostics')
def history():
    with connect() as db:
        rows=db.execute('SELECT id,timestamp,target,score,severity,issue,ping_ms,packet_loss FROM diagnostics ORDER BY id DESC LIMIT 100').fetchall()
    return jsonify(records=[dict(r) for r in rows])

@app.get('/api/diagnostics/<int:record_id>')
def detail(record_id):
    import json
    with connect() as db:
        row=db.execute('SELECT payload FROM diagnostics WHERE id=?',(record_id,)).fetchone()
    if not row: return jsonify(error='Record not found'),404
    return jsonify(json.loads(row['payload']))

@app.delete('/api/diagnostics/<int:record_id>')
def delete(record_id):
    with connect() as db:
        cur=db.execute('DELETE FROM diagnostics WHERE id=?',(record_id,))
        db.commit()
    if not cur.rowcount: return jsonify(error='Record not found'),404
    return jsonify(status='deleted')

@app.get('/api/analytics/summary')
def analytics():
    with connect() as db:
        rows=[dict(r) for r in db.execute('SELECT id,timestamp,target,score,ping_ms,packet_loss,severity FROM diagnostics ORDER BY id DESC LIMIT 100')]
    scores=[r['score'] for r in rows if r['score'] is not None]
    return jsonify(total=len(rows),average_score=round(sum(scores)/len(scores),1) if scores else None,records=list(reversed(rows)))

@app.errorhandler(404)
def missing(_):
    return jsonify(status='error',message='API endpoint not found'),404

if __name__=='__main__':
    init_db()
    app.run(host='127.0.0.1',port=5000,debug=False)
else:
    init_db()
