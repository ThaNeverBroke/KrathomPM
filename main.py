#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KratomPM - process manager for Python and Node.js projects (PM2 style).

Run:   python kratompm.py
Then open the address printed in the terminal and log in.

Single file, Python standard library only. Settings, projects and the login
password are saved next to this file in kratompm_data.json.
"""
import collections
import glob
import hashlib
import hmac
import http.cookies
import http.server
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile

VERSION = '1.0.0'
WIN = os.name == 'nt'
LINUX = sys.platform.startswith('linux')
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(APP_DIR, 'kratompm_data.json')
PROJ_DIR = os.path.join(APP_DIR, 'projects')      # uploaded ZIP projects are extracted here
MAX_ZIP = 500 * 1024 * 1024
NCPU = os.cpu_count() or 1
try:
    CLK = os.sysconf('SC_CLK_TCK')
except Exception:
    CLK = 100
BOOT = time.time()

try:                                   # optional: better CPU / RAM numbers
    import psutil
except ImportError:
    psutil = None
    if not LINUX:                      # Linux uses /proc, others try to install psutil once
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', 'psutil'],
                           capture_output=True, timeout=180)
            import psutil
        except Exception:
            psutil = None

# --------------------------------------------------------------------------
# DATA: settings + projects (saved to kratompm_data.json)
# --------------------------------------------------------------------------
DEFAULTS = {
    'host': '127.0.0.1', 'port': 8000, 'defLang': 'python',
    'maxMem': 0,
    'retention': 1000, 'notifyCrash': True, 'notifyStatus': True, 'notifyPkg': False,
}
LOCK = threading.RLock()
DATA = {'settings': dict(DEFAULTS), 'next_id': 1, 'pw': None}
PROJECTS = {}                          # id -> Project
SESSIONS = {}                          # cookie token -> expiry
ACTUAL = {'host': DEFAULTS['host'], 'port': DEFAULTS['port']}
SEQ = [0]
SEQ_LOCK = threading.Lock()
WEAK = [False]                         # True while the password is still the default 123
EVENTS = collections.deque(maxlen=100)
EV_ID = [0]
SYS = {'cpu': 0.0, 'mem': 0.0, 'used': 0, 'total': 0}
PING = {'ms': None, 'hist': collections.deque([0] * 30, maxlen=30)}
ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')


class Project:
    def __init__(self, cfg):
        self.cfg = cfg
        self.proc = None
        self.status = 'stopped'        # stopped | running | crashed | restarting
        self.start_ts = None
        self.pid = None
        self.cpu = 0.0
        self.ram = 0
        self.stopping = False
        self.starting = False
        self.cancel = False
        self.inst = None
        self.missing = set()
        self.tried = set()
        self.lock = threading.RLock()
        self.logs = collections.deque(maxlen=DATA['settings']['retention'])


def load():
    try:
        with open(DATA_FILE, encoding='utf-8') as f:
            d = json.load(f)
    except Exception:
        d = {}
    DATA['settings'].update(d.get('settings', {}))
    DATA['next_id'] = d.get('next_id', 1)
    DATA['pw'] = d.get('pw')
    for cfg in d.get('projects', []):
        PROJECTS[cfg['id']] = Project(cfg)


def save():
    with LOCK:
        d = {'settings': DATA['settings'], 'next_id': DATA['next_id'], 'pw': DATA['pw'],
             'projects': [p.cfg for p in PROJECTS.values()]}
        tmp = DATA_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, DATA_FILE)


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), 120000).hex()


def set_pw(pw):
    salt = secrets.token_hex(16)
    DATA['pw'] = {'salt': salt, 'hash': hash_pw(pw, salt)}
    WEAK[0] = (pw == '123')


def check_pw(pw):
    d = DATA['pw']
    return bool(d) and hmac.compare_digest(hash_pw(pw, d['salt']), d['hash'])


# --------------------------------------------------------------------------
# LOGS + EVENTS
# --------------------------------------------------------------------------
def add_log(p, text, kind='out'):
    with SEQ_LOCK:
        SEQ[0] += 1
        s = SEQ[0]
    p.logs.append({'s': s, 'p': p.cfg['id'], 't': round(time.time(), 3), 'm': ANSI.sub('', text)[:4000], 'k': kind})


def sys_log(p, text):
    add_log(p, text, 'sys')


def event(text, typ='info', cat='status'):
    EV_ID[0] += 1
    EVENTS.append({'id': EV_ID[0], 't': time.time(), 'text': text, 'type': typ, 'cat': cat})


def get_logs(proj, after, limit):
    if proj == 'all':
        items = [e for p in list(PROJECTS.values()) for e in list(p.logs) if e['s'] > after]
        items.sort(key=lambda e: e['s'])
    else:
        p = PROJECTS.get(int(proj))
        items = [e for e in list(p.logs) if e['s'] > after] if p else []
    return items[-limit:]


# --------------------------------------------------------------------------
# RUNTIMES: find Python / Node.js versions installed on this machine
# --------------------------------------------------------------------------
_VER = {}
_RT = {'t': 0, 'd': None}


def runtime_version(exe):
    if exe in _VER:
        return _VER[exe]
    try:
        out = subprocess.run([exe, '--version'], capture_output=True, text=True, timeout=10)
        v = (out.stdout or out.stderr).strip().replace('Python ', '').lstrip('v')
    except Exception:
        v = ''
    _VER[exe] = v
    return v


def detect_runtimes():
    if _RT['d'] and time.time() - _RT['t'] < 60:
        return _RT['d']
    py = {}
    for m in range(8, 14):
        exe = shutil.which('python3.%d' % m)
        if exe:
            py.setdefault('3.%d' % m, exe)
    py.setdefault('%d.%d' % sys.version_info[:2], sys.executable)
    nd = {}
    home = os.path.expanduser('~')
    pats = [home + '/.nvm/versions/node/v*/bin/node', '/usr/local/n/versions/node/*/bin/node',
            home + '/.local/share/fnm/node-versions/v*/installation/bin/node', '/www/server/nodejs/v*/bin/node']

    def vkey(e):
        m = re.search(r'v?(\d+)\.(\d+)\.(\d+)', e)
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)
    for pat in pats:
        for exe in sorted(glob.glob(pat), key=vkey):
            m = re.search(r'v?(\d+)\.\d+\.\d+', exe)
            if m:
                nd[m.group(1)] = exe
    exe = shutil.which('node')
    if exe:
        m = re.match(r'(\d+)', runtime_version(exe))
        if m:
            nd.setdefault(m.group(1), exe)
    order = lambda d: sorted(d, key=lambda k: [int(x) for x in k.split('.')])
    d = {'python': [{'v': k, 'full': runtime_version(py[k])} for k in order(py)],
         'node': [{'v': k, 'full': runtime_version(nd[k])} for k in order(nd)],
         'def': {'python': '%d.%d' % sys.version_info[:2],
                 'node': (re.match(r'(\d+)', runtime_version(shutil.which('node') or '')) or [None, ''])[1] if shutil.which('node') else ''},
         '_py': py, '_nd': nd}
    _RT['d'], _RT['t'] = d, time.time()
    return d


def resolve_runtime(lang, version, folder):
    """Return (executable, note)."""
    rt = detect_runtimes()
    if lang == 'python':
        for d in ('venv', '.venv', 'env'):
            exe = os.path.join(folder, d, 'Scripts' if WIN else 'bin', 'python.exe' if WIN else 'python')
            if os.path.isfile(exe):
                return exe, 'virtualenv "%s"' % d
        if not version:
            return sys.executable, ''
        if version in rt['_py']:
            return rt['_py'][version], ''
        return sys.executable, 'Python %s not found, using default interpreter' % version
    if version in rt['_nd']:
        return rt['_nd'][version], ''
    exe = shutil.which('node')
    if exe:
        return exe, ('Node %s not found, using default node' % version) if version else ''
    return 'node', 'node was not found in PATH'


def rt_env(exe):
    env = os.environ.copy()
    if os.path.isabs(exe):
        env['PATH'] = os.path.dirname(exe) + os.pathsep + env.get('PATH', '')
    return env


def npm_exe(node_exe):
    cand = os.path.join(os.path.dirname(node_exe), 'npm.cmd' if WIN else 'npm')
    return cand if os.path.isfile(cand) else (shutil.which('npm') or 'npm')


# --------------------------------------------------------------------------
# PROCESS CONTROL (real subprocesses)
# --------------------------------------------------------------------------
def kill_tree(proc, force=False):
    try:
        if WIN:
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T'] + (['/F'] if force else []), capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
    except Exception:
        try:
            proc.kill() if force else proc.terminate()
        except Exception:
            pass


MOD_PY = re.compile(r"No module named '([\w.\-]+)'")
MOD_JS = re.compile(r"Cannot find (?:module|package) '([^']+)'")
PIP_NAMES = {'cv2': 'opencv-python', 'PIL': 'pillow', 'yaml': 'pyyaml', 'bs4': 'beautifulsoup4', 'sklearn': 'scikit-learn',
             'dotenv': 'python-dotenv', 'telegram': 'python-telegram-bot', 'Crypto': 'pycryptodome', 'jwt': 'pyjwt',
             'dateutil': 'python-dateutil', 'serial': 'pyserial', 'discord': 'discord.py', 'telebot': 'pyTelegramBotAPI',
             'MySQLdb': 'mysqlclient', 'google': 'google-api-python-client', 'socks': 'pysocks'}


def clean_mod(lang, name, folder):
    if lang == 'python':
        top = name.split('.')[0]
        if os.path.exists(os.path.join(folder, top)) or os.path.exists(os.path.join(folder, top + '.py')):
            return None                # a local file, not a package
        return top
    if name.startswith(('.', '/', 'node:')):
        return None
    parts = name.split('/')
    return '/'.join(parts[:2]) if name.startswith('@') else parts[0]


def run_logged(p, cmd, cwd, env):
    """Run a command and stream its output into the project's log. Returns the exit code."""
    sys_log(p, '$ ' + ' '.join(cmd))
    kw = {} if WIN else {'start_new_session': True}
    try:
        pr = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', **kw)
    except Exception as e:
        sys_log(p, 'Install failed: %s' % e)
        return -1
    p.inst = pr
    for line in pr.stdout:
        add_log(p, line.rstrip('\r\n'))
    code = pr.wait()
    p.inst = None
    return code


def prepare(p, exe, env):
    """Install requirements.txt / package.json packages before the first start (only when they exist)."""
    cfg, folder = p.cfg, p.cfg['folder']
    if cfg['lang'] == 'python':
        req = os.path.join(folder, 'requirements.txt')
        if os.path.isfile(req) and cfg.get('reqm') != os.path.getmtime(req):
            p.status = 'installing'
            sys_log(p, 'Installing requirements.txt ...')
            if run_logged(p, [exe, '-m', 'pip', 'install', '-r', 'requirements.txt'], folder, env) == 0:
                cfg['reqm'] = os.path.getmtime(req)
                save()
            else:
                sys_log(p, 'Requirements install failed, starting anyway')
    elif os.path.isfile(os.path.join(folder, 'package.json')) and not os.path.isdir(os.path.join(folder, 'node_modules')):
        p.status = 'installing'
        sys_log(p, 'Installing npm packages ...')
        if run_logged(p, [npm_exe(exe), 'install'], folder, env) != 0:
            sys_log(p, 'npm install failed, starting anyway')


def auto_install(p, mods):
    """A module was missing when the project crashed: install it, then start again."""
    cfg, folder = p.cfg, p.cfg['folder']
    exe, _ = resolve_runtime(cfg['lang'], cfg.get('version', ''), folder)
    env = rt_env(exe)
    mods = [m for m in mods if not m.startswith('-') and NAME_OK.match(m)]
    if not mods:
        p.status = 'crashed'
        return
    p.status = 'installing'
    if cfg['lang'] == 'python':
        cmd = [exe, '-m', 'pip', 'install'] + [PIP_NAMES.get(m, m) for m in mods]
    else:
        cmd = [npm_exe(exe), 'install'] + mods
    sys_log(p, 'Missing %s - installing automatically...' % ', '.join(mods))
    code = run_logged(p, cmd, folder, env)
    if p.cancel:
        p.status = 'stopped'
        return
    if code == 0:
        start_project(p, user=False)
    else:
        p.status = 'crashed'
        sys_log(p, 'Automatic install failed')
        event('%s crashed: could not install %s' % (cfg['name'], ', '.join(mods)), 'error', 'crash')


def start_project(p, user=True):
    cfg = p.cfg
    with p.lock:
        if p.starting or (p.proc and p.proc.poll() is None):
            return False
        p.starting = True
        p.cancel = False
        if user:
            p.tried = set()
    try:
        folder = cfg['folder']
        if not os.path.isdir(folder):
            sys_log(p, 'Folder not found: %s' % folder)
            p.status = 'crashed'
            return False
        if not os.path.isfile(os.path.join(folder, cfg['entry'])):
            sys_log(p, 'Entry file not found: %s' % cfg['entry'])
            p.status = 'crashed'
            return False
        exe, note = resolve_runtime(cfg['lang'], cfg.get('version', ''), folder)
        env = rt_env(exe)
        env['PYTHONUNBUFFERED'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        if cfg.get('port'):
            env['PORT'] = str(cfg['port'])
        if note:
            sys_log(p, note)
        prepare(p, exe, env)
        if p.cancel:
            p.status = 'stopped'
            return False
        cmd = [exe, '-u', cfg['entry']] if cfg['lang'] == 'python' else [exe, cfg['entry']]
        kw = {}
        if WIN:
            kw['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kw['start_new_session'] = True
        try:
            proc = subprocess.Popen(cmd, cwd=folder, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, bufsize=1, text=True, encoding='utf-8',
                                    errors='replace', **kw)
        except Exception as e:
            sys_log(p, 'Failed to start: %s' % e)
            if cfg['lang'] == 'node' and not shutil.which('node'):
                sys_log(p, 'Node.js is not installed. In Termux run: pkg install nodejs')
            p.status = 'crashed'
            event('%s failed to start' % cfg['name'], 'error', 'crash')
            return False
        with p.lock:
            p.proc, p.pid, p.status, p.start_ts, p.stopping = proc, proc.pid, 'running', time.time(), False
            p.missing = set()
            if user:
                cfg['run'] = True
                save()
    finally:
        p.starting = False
    sys_log(p, 'Started %s (pid %d) with %s %s' % (cfg['entry'], proc.pid, 'Python' if cfg['lang'] == 'python' else 'Node.js',
                                                  runtime_version(exe)))
    threading.Thread(target=pump, args=(p, proc), daemon=True).start()
    return True


def pump(p, proc):
    rx = MOD_PY if p.cfg['lang'] == 'python' else MOD_JS
    try:
        for line in proc.stdout:
            line = line.rstrip('\r\n')
            add_log(p, line)
            m = rx.search(line)
            if m:
                mod = clean_mod(p.cfg['lang'], m.group(1), p.cfg['folder'])
                if mod:
                    p.missing.add(mod)
    except Exception:
        pass
    on_exit(p, proc, proc.wait())


def on_exit(p, proc, code):
    with p.lock:
        if p.proc is not proc:
            return
        p.proc, p.pid, p.start_ts, p.cpu, p.ram = None, None, None, 0.0, 0
        if p.stopping:
            p.status = 'stopped'
            return
        p.status = 'stopped' if code == 0 else 'crashed'
    sys_log(p, 'Process exited with code %s' % code)
    if code == 0:
        event('%s exited' % p.cfg['name'], 'warn')
        return
    new = [m for m in sorted(p.missing) if m not in p.tried]
    p.missing = set()
    if new:                            # missing package: install it once and start again
        p.tried.update(new)
        p.status = 'installing'
        bg(auto_install, p, new)
        return
    event('%s crashed (exit code %s)' % (p.cfg['name'], code), 'error', 'crash')


def stop_project(p, user=True, final='stopped'):
    with p.lock:
        p.cancel = True
        if p.inst:
            kill_tree(p.inst, True)
        proc = p.proc
        if not proc or proc.poll() is not None:
            if p.status in ('crashed', 'installing'):
                p.status = 'stopped'
            if user:
                p.cfg['run'] = False
                save()
            return
        p.stopping = True
    sys_log(p, 'Stopping process...')
    kill_tree(proc)
    try:
        proc.wait(8)
    except subprocess.TimeoutExpired:
        sys_log(p, 'Did not exit in time, killing')
        kill_tree(proc, True)
        try:
            proc.wait(5)
        except Exception:
            pass
    with p.lock:
        if p.proc is proc:
            p.proc, p.pid, p.start_ts, p.cpu, p.ram = None, None, None, 0.0, 0
        p.status = final
        p.stopping = False
        if user:
            p.cfg['run'] = False
    if user:
        save()
    sys_log(p, 'Process stopped')


def restart_project(p):
    with p.lock:
        if p.status == 'restarting':
            return
        p.status = 'restarting'
    sys_log(p, 'Restarting...')
    stop_project(p, user=False, final='restarting')
    start_project(p, user=True)


def bg(fn, *a):
    threading.Thread(target=fn, args=a, daemon=True).start()


def shutdown_all():
    ps = [p for p in PROJECTS.values() if p.proc]
    for p in ps:
        stop_project(p, user=False)


# --------------------------------------------------------------------------
# METRICS: per-process and system CPU / RAM, internet ping
# --------------------------------------------------------------------------
_PS = {}
_PREV = {}
_SYSPREV = [None]
_PROCPREV = [None]
CPU_PARTIAL = [False]                   # True when system CPU is estimated from visible processes
PSCPU = [True]                         # False when the system blocks /proc/stat (Android)


def ps_stats(pid):                     # psutil: CPU as % of one core (like top / PM2)
    try:
        root = _PS.get(pid) or psutil.Process(pid)
        _PS[pid] = root
        cpu = ram = 0
        for q in [root] + root.children(recursive=True):
            q = _PS.setdefault(q.pid, q)
            try:
                cpu += q.cpu_percent(None)
                ram += q.memory_info().rss
            except psutil.Error:
                pass
        if len(_PS) > 400:
            _PS.clear()
        return cpu, ram
    except Exception:
        return 0.0, 0


def scan_procs():
    """Linux without psutil: pid -> (parent pid, cpu ticks, rss bytes) for every process we are allowed to see."""
    tbl = {}
    page = os.sysconf('SC_PAGE_SIZE')
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % d) as f:
                st = f.read()
            rest = st[st.rindex(')') + 2:].split()
            tbl[int(d)] = (int(rest[1]), int(rest[11]) + int(rest[12]), int(rest[21]) * page)
        except Exception:
            continue
    return tbl


def tree_stats(pid, tbl):              # the process plus all its children, CPU as % of one core
    kids = {}
    for q, v in tbl.items():
        kids.setdefault(v[0], []).append(q)
    stack, seen, ticks, rss = [pid], set(), 0, 0
    while stack:
        q = stack.pop()
        if q in seen or q not in tbl:
            continue
        seen.add(q)
        ticks += tbl[q][1]
        rss += tbl[q][2]
        stack.extend(kids.get(q, []))
    now = time.time()
    prev = _PREV.get(pid)
    _PREV[pid] = (ticks, now)
    cpu = 0.0
    if prev and now > prev[1]:
        cpu = max(0.0, (ticks - prev[0]) / CLK / (now - prev[1]) * 100)
    return cpu, rss


def cpu_from_tbl(tbl):                 # system CPU from the processes we are allowed to see
    CPU_PARTIAL[0] = True
    if not tbl:
        return 0.0
    ticks, now = sum(v[1] for v in tbl.values()), time.time()
    prev, _PROCPREV[0] = _PROCPREV[0], (ticks, now)
    if prev and now > prev[1]:
        return (ticks - prev[0]) / CLK / (now - prev[1]) * 100 / NCPU
    return 0.0


def sys_stats(tbl=None):
    if psutil:
        try:
            vm = psutil.virtual_memory()
            cpu = None
            if PSCPU[0]:
                try:
                    cpu = psutil.cpu_percent(None)
                except Exception:
                    PSCPU[0] = False
            if cpu is None:
                cpu = cpu_from_tbl(tbl)
            return cpu, vm.percent, (vm.total - vm.available) >> 20, vm.total >> 20
        except Exception:
            pass
    if not LINUX:
        return 0.0, 0.0, 0, 0
    cpu = 0.0
    try:
        with open('/proc/stat') as f:
            v = [int(x) for x in f.readline().split()[1:]]
        idle, total = v[3] + v[4], sum(v)
        prev, _SYSPREV[0] = _SYSPREV[0], (idle, total)
        if prev and total > prev[1]:
            cpu = 100.0 * (1 - (idle - prev[0]) / (total - prev[1]))
    except Exception:                  # Android blocks /proc/stat
        cpu = cpu_from_tbl(tbl)
    try:
        mi = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, _, val = line.partition(':')
                mi[k] = int(val.split()[0])
        tot, av = mi['MemTotal'], mi.get('MemAvailable', mi.get('MemFree', 0))
        return cpu, (tot - av) * 100.0 / tot, (tot - av) >> 10, tot >> 10
    except Exception:
        try:
            tot = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
        except Exception:
            tot = 0
        used = sum(v[2] for v in tbl.values()) if tbl else 0
        return cpu, (used * 100.0 / tot if tot else 0.0), used >> 20, tot >> 20


def sampler():
    if psutil:
        try:
            psutil.cpu_percent(None)
        except Exception:
            PSCPU[0] = False
    while True:
        time.sleep(2)
        try:
            tbl = None
            if LINUX and (not psutil or not PSCPU[0]):
                try:
                    tbl = scan_procs()
                except Exception:
                    tbl = None
            c, m, u, t = sys_stats(tbl)
            SYS.update(cpu=round(max(0.0, min(100.0, c)), 1), mem=round(m, 1), used=u, total=t)
            lim = int(DATA['settings'].get('maxMem') or 0)
            for p in list(PROJECTS.values()):
                if p.proc and p.status == 'running' and p.pid:
                    if tbl is not None:
                        p.cpu, p.ram = tree_stats(p.pid, tbl)
                    elif psutil:
                        p.cpu, p.ram = ps_stats(p.pid)
                    if lim and p.ram > lim * 1048576:
                        sys_log(p, 'Memory limit of %d MB exceeded, restarting' % lim)
                        bg(restart_project, p)
        except Exception:
            pass


TUN = {'status': 'starting', 'url': None, 'err': '', 'proc': None, 'since': 0}
TUN_URL = re.compile(r'https://[a-zA-Z0-9\-]+\.trycloudflare\.com')


def tunnel_loop():
    """Keeps a Cloudflare quick tunnel open to this dashboard. A new link is made whenever it dies."""
    tried_install = False
    while True:
        exe = shutil.which('cloudflared')
        if not exe and not tried_install and 'com.termux' in os.environ.get('PREFIX', ''):
            tried_install = True       # Termux: install it once automatically
            TUN.update(status='installing', url=None, err='')
            print('  Installing cloudflared (pkg install cloudflared)...')
            try:
                subprocess.run(['pkg', 'install', '-y', 'cloudflared'], stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
            except Exception:
                pass
            exe = shutil.which('cloudflared')
        if not exe:
            TUN.update(status='missing', url=None, err='')
            time.sleep(10)
            continue
        TUN.update(status='starting', url=None, err='')
        try:
            kw = {} if WIN else {'start_new_session': True}
            proc = subprocess.Popen([exe, 'tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:%d' % ACTUAL['port']],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    encoding='utf-8', errors='replace', bufsize=1, **kw)
        except Exception as e:
            TUN.update(status='restarting', err=str(e)[:200])
            time.sleep(10)
            continue
        TUN['proc'] = proc
        last = ''
        for line in proc.stdout:
            line = ANSI.sub('', line).strip()
            if line:
                last = line
                if re.search(r'\b(ERR|error|failed)\b', line, re.I):
                    TUN['err'] = line[-200:]
            m = TUN_URL.search(line)
            if m and m.group(0) != 'https://api.trycloudflare.com' and TUN['url'] != m.group(0):
                TUN.update(status='online', url=m.group(0), since=time.time(), err='')
                print('  Public link: %s' % m.group(0))
        code = proc.wait()
        TUN['proc'] = None
        TUN.update(status='restarting', url=None, err=(TUN['err'] or last or 'exit code %s' % code)[-200:])
        time.sleep(4)


def tunnel_watch():
    """Only if the internet is fine but the public link stays dead for a few minutes, make a new one.
    While the internet is down (and for 2 minutes after it returns) the old link is left alone: cloudflared reconnects it."""
    bad, down = 0, 0
    while True:
        time.sleep(30)
        if PING['ms'] is None:
            down = time.time()
        url, proc = TUN['url'], TUN['proc']
        if not url or not proc or time.time() - TUN['since'] < 90 or time.time() - down < 120:
            bad = 0
            continue
        try:
            urllib.request.urlopen(url + '/login', timeout=15).read(1)
            bad = 0
        except Exception:              # no answer, or a Cloudflare error page (530 / 1033 = tunnel is gone)
            bad += 1
        if bad >= 4:
            print('  Public link stopped answering, making a new one...')
            kill_tree(proc, True)
            bad = 0


def pinger():
    while True:
        ms = None
        for host in ('1.1.1.1', '8.8.8.8'):
            try:
                t = time.time()
                socket.create_connection((host, 443), 2).close()
                ms = int((time.time() - t) * 1000)
                break
            except Exception:
                continue
        PING['ms'] = ms
        PING['hist'].append(ms or 0)
        time.sleep(4)


# --------------------------------------------------------------------------
# PACKAGES + JOBS (real pip / npm, output streamed to the browser)
# --------------------------------------------------------------------------
JOBS = collections.OrderedDict()
NAME_OK = re.compile(r'^[A-Za-z0-9@._/\-\[\]=<>~!,]+$')


def run_job(cmd, cwd, env, label='pkg', done=None):
    jid = secrets.token_hex(4)
    job = {'lines': ['$ ' + ' '.join(cmd)], 'done': False, 'code': None, 'label': label}
    JOBS[jid] = job
    while len(JOBS) > 30:
        JOBS.popitem(last=False)

    def work():
        try:
            pr = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            for line in pr.stdout:
                if len(job['lines']) < 3000:
                    job['lines'].append(ANSI.sub('', line.rstrip('\r\n')))
            job['code'] = pr.wait()
        except Exception as e:
            job['lines'].append('ERROR: %s' % e)
            job['code'] = -1
        job['done'] = True
        if label == 'pkg':
            event('Package task %s' % ('finished' if job['code'] == 0 else 'failed'),
                  'success' if job['code'] == 0 else 'error', 'pkg')
        if done:
            try:
                done()
            except Exception:
                pass
    bg(work)
    return jid


def pkg_cmd(cfg, op, name='', names=None):
    folder = cfg['folder']
    if not os.path.isdir(folder):
        raise ValueError('Folder does not exist')
    exe, _ = resolve_runtime(cfg['lang'], cfg.get('version', ''), folder)
    for n in ([name] if name else []) + list(names or []):
        if n.startswith('-') or not NAME_OK.match(n):
            raise ValueError('Invalid package name: %s' % n)
    names = list(names or [])
    if cfg['lang'] == 'python':
        base = [exe, '-m', 'pip']
        if op == 'install':
            return base + ['install', name]
        if op == 'uninstall':
            return base + ['uninstall', '-y', name]
        if op == 'update':
            return base + ['install', '-U', name]
        if op == 'updateall':
            return base + ['install', '-U'] + names
        if op == 'requirements':
            if not os.path.isfile(os.path.join(folder, 'requirements.txt')):
                raise ValueError('requirements.txt not found in the project folder')
            return base + ['install', '-r', 'requirements.txt']
    else:
        npm = npm_exe(exe)
        if op == 'install':
            return [npm, 'install', name]
        if op == 'uninstall':
            return [npm, 'uninstall', name]
        if op == 'update':
            return [npm, 'install', name + '@latest']
        if op == 'updateall':
            return [npm, 'install'] + [n + '@latest' for n in names]
        if op == 'requirements':
            return [npm, 'install']
    raise ValueError('Unknown operation')


def gpkg_list(mgr, outdated):
    """Global packages: pip of the default Python, or npm -g."""
    env = os.environ.copy()
    env['PIP_BREAK_SYSTEM_PACKAGES'] = '1'
    try:
        if mgr == 'pip':
            base = [sys.executable, '-m', 'pip', 'list', '--format=json', '--disable-pip-version-check']
            r = subprocess.run(base, env=env, capture_output=True, text=True, timeout=120)
            if r.returncode:
                return {'error': ((r.stderr or r.stdout).strip()[-300:]) or 'pip failed'}
            items = [{'name': x['name'], 'ver': x['version'], 'latest': None} for x in json.loads(r.stdout)]
            if outdated:
                r = subprocess.run(base + ['--outdated'], env=env, capture_output=True, text=True, timeout=180)
                latest = {x['name'].lower(): x['latest_version'] for x in json.loads(r.stdout or '[]')}
                for it in items:
                    it['latest'] = latest.get(it['name'].lower())
        else:
            npm = shutil.which('npm')
            if not npm:
                return {'error': 'npm is not installed. On Termux run: pkg install nodejs'}
            r = subprocess.run([npm, 'ls', '-g', '--depth=0', '--json'], env=env, capture_output=True, text=True, timeout=120)
            deps = json.loads(r.stdout or '{}').get('dependencies', {})
            items = [{'name': n, 'ver': (v or {}).get('version', ''), 'latest': None} for n, v in deps.items()]
            if outdated:
                r = subprocess.run([npm, 'outdated', '-g', '--json'], env=env, capture_output=True, text=True, timeout=180)
                out = json.loads(r.stdout or '{}')
                for it in items:
                    if isinstance(out.get(it['name']), dict):
                        it['latest'] = out[it['name']].get('latest')
        items.sort(key=lambda x: x['name'].lower())
        return {'packages': items}
    except subprocess.TimeoutExpired:
        return {'error': 'Timed out'}
    except Exception as e:
        return {'error': str(e)}


def gpkg_cmd(mgr, op, name, names):
    names = list(names or [])
    for n in ([name] if name else []) + names:
        if n.startswith('-') or not NAME_OK.match(n):
            raise ValueError('Invalid package name: %s' % n)
    if mgr == 'pip':
        base = [sys.executable, '-m', 'pip']
        if op == 'install' and name:
            return base + ['install', name]
        if op == 'uninstall' and name:
            return base + ['uninstall', '-y', name]
        if op == 'update' and name:
            return base + ['install', '-U', name]
        if op == 'updateall' and names:
            if 'com.termux' in os.environ.get('PREFIX', ''):
                names = [n for n in names if n.lower() != 'pip']   # Termux does not allow upgrading pip with pip
            return base + ['install', '-U'] + names
    elif mgr == 'npm':
        npm = shutil.which('npm')
        if not npm:
            raise ValueError('npm is not installed. On Termux run: pkg install nodejs')
        if op == 'install' and name:
            return [npm, 'install', '-g', name]
        if op == 'uninstall' and name:
            return [npm, 'uninstall', '-g', name]
        if op == 'update' and name:
            return [npm, 'install', '-g', name + '@latest']
        if op == 'updateall' and names:
            return [npm, 'install', '-g'] + [n + '@latest' for n in names]
    raise ValueError('Unknown operation')


PKG = {m: {'items': None, 'sig': None, 'latest': {}, 'checked': 0, 'tried': 0, 'checking': False, 'err': None,
           'rev': 0, 'root': None, 'lock': threading.Lock()} for m in ('pip', 'npm')}
PKG_CHECK_EVERY = 6 * 3600             # look for newer versions every 6 hours


def pkg_sig(m):
    """Cheap fingerprint of where packages live: changes whenever something is installed / removed / updated."""
    try:
        if m == 'pip':
            import site
            dirs = []
            try:
                dirs += site.getsitepackages()
            except Exception:
                pass
            try:
                dirs.append(site.getusersitepackages())
            except Exception:
                pass
        else:
            npm = shutil.which('npm')
            if not npm:
                return None
            st = PKG['npm']
            if not st['root']:
                st['root'] = subprocess.run([npm, 'root', '-g'], capture_output=True, text=True, timeout=30).stdout.strip()
            root = st['root']
            dirs = [root]
            if root and os.path.isdir(root):
                dirs += [os.path.join(root, n) for n in os.listdir(root) if n.startswith('@')]
        return tuple((d, os.stat(d).st_mtime_ns) for d in dirs if d and os.path.isdir(d))
    except Exception:
        return None


def pkg_refresh(m, check=False):
    st = PKG[m]
    with st['lock']:
        if check:
            st['checking'] = True
            st['tried'] = time.time()
            st['rev'] += 1
        r = gpkg_list(m, check)
        if r.get('error'):
            st['err'] = r['error']
            if st['items'] is None:
                st['items'] = []
        else:
            st['err'] = None
            items = r['packages']
            if check:
                st['latest'] = {x['name'].lower(): x['latest'] for x in items if x['latest']}
                st['checked'] = time.time()
            else:
                for x in items:
                    x['latest'] = st['latest'].get(x['name'].lower())
            st['items'] = items
        st['checking'] = False
        st['rev'] += 1


def pkg_watch(m):
    st = PKG[m]
    while True:
        try:
            sig = pkg_sig(m)
            if st['items'] is None or sig != st['sig']:
                st['sig'] = sig
                pkg_refresh(m)
            if st['items'] is not None and not st['err'] and time.time() - st['tried'] > PKG_CHECK_EVERY:
                pkg_refresh(m, True)
        except Exception:
            pass
        time.sleep(2)


def pkg_list(cfg, outdated):
    folder = cfg['folder']
    if not os.path.isdir(folder):
        return {'error': 'Folder does not exist'}
    exe, _ = resolve_runtime(cfg['lang'], cfg.get('version', ''), folder)
    env = rt_env(exe)
    try:
        if cfg['lang'] == 'python':
            base = [exe, '-m', 'pip', 'list', '--format=json', '--disable-pip-version-check']
            r = subprocess.run(base, cwd=folder, env=env, capture_output=True, text=True, timeout=90)
            if r.returncode:
                return {'error': ((r.stderr or r.stdout).strip()[-300:]) or 'pip failed'}
            items = [{'name': x['name'], 'ver': x['version'], 'latest': None} for x in json.loads(r.stdout)]
            if outdated:
                r = subprocess.run(base + ['--outdated'], cwd=folder, env=env, capture_output=True, text=True, timeout=120)
                latest = {x['name'].lower(): x['latest_version'] for x in json.loads(r.stdout or '[]')}
                for it in items:
                    it['latest'] = latest.get(it['name'].lower())
            items.sort(key=lambda x: x['name'].lower())
            return {'packages': items}
        pj = os.path.join(folder, 'package.json')
        deps = {}
        if os.path.isfile(pj):
            with open(pj, encoding='utf-8') as f:
                data = json.load(f)
            deps = dict(data.get('dependencies', {}))
            deps.update(data.get('devDependencies', {}))
        else:                          # no package.json: list whatever is in node_modules
            nm = os.path.join(folder, 'node_modules')
            if os.path.isdir(nm):
                for n in os.listdir(nm):
                    if n.startswith('.'):
                        continue
                    if n.startswith('@'):
                        for sub in os.listdir(os.path.join(nm, n)):
                            deps[n + '/' + sub] = ''
                    else:
                        deps[n] = ''
        items = []
        for n, spec in deps.items():
            ver = spec
            try:
                with open(os.path.join(folder, 'node_modules', n, 'package.json'), encoding='utf-8') as f:
                    ver = json.load(f).get('version', spec)
            except Exception:
                pass
            items.append({'name': n, 'ver': ver, 'latest': None})
        if outdated:
            r = subprocess.run([npm_exe(exe), 'outdated', '--json'], cwd=folder, env=env, capture_output=True, text=True, timeout=120)
            out = json.loads(r.stdout or '{}')
            for it in items:
                if it['name'] in out and isinstance(out[it['name']], dict):
                    it['latest'] = out[it['name']].get('latest')
        items.sort(key=lambda x: x['name'].lower())
        return {'packages': items}
    except subprocess.TimeoutExpired:
        return {'error': 'Timed out'}
    except Exception as e:
        return {'error': str(e)}


# --------------------------------------------------------------------------
# API helpers
# --------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, msg, code=400):
        Exception.__init__(self, msg)
        self.code = code


def pjson(p):
    c = p.cfg
    up = int(time.time() - p.start_ts) if p.start_ts and p.status == 'running' else 0
    exe, _ = resolve_runtime(c['lang'], c.get('version', ''), c['folder'])
    return {'id': c['id'], 'name': c['name'], 'lang': c['lang'], 'version': c.get('version', ''), 'folder': c['folder'],
            'entry': c['entry'], 'port': c.get('port'), 'status': p.status,
            'cpu': round(p.cpu, 1), 'ram': int(p.ram >> 20), 'uptime': up, 'pid': p.pid,
            'runtime': runtime_version(exe)}


def info():
    node = shutil.which('node')
    return {'version': VERSION, 'host': ACTUAL['host'], 'port': ACTUAL['port'], 'os': '%s %s' % (platform.system(), platform.release()),
            'python': platform.python_version(), 'node': runtime_version(node) if node else 'not installed',
            'uptime': int(time.time() - BOOT), 'projects': len(PROJECTS), 'psutil': bool(psutil),
            'settings': DATA['settings']}


def clean_cfg(body, exclude=None):
    name = str(body.get('name', '')).strip()
    lang = body.get('lang')
    folder = os.path.abspath(os.path.expanduser(str(body.get('folder', '')).strip()))
    entry = str(body.get('entry', '')).strip()
    if not name or len(name) > 40:
        raise ApiError('Project name is required (max 40 characters)')
    if any(q.cfg['name'].lower() == name.lower() and q.cfg['id'] != exclude for q in PROJECTS.values()):
        raise ApiError('A project with this name already exists')
    if lang not in ('python', 'node'):
        raise ApiError('Language must be Python or Node.js')
    if not os.path.isdir(folder):
        raise ApiError('Folder does not exist: %s' % folder)
    if not entry or not os.path.isfile(os.path.join(folder, entry)):
        raise ApiError('Entry file not found in the folder: %s' % entry)
    port = body.get('port')
    if port in (None, ''):
        port = None
    else:
        try:
            port = int(port)
        except Exception:
            raise ApiError('Port must be a number')
        if not 1 <= port <= 65535:
            raise ApiError('Port must be between 1 and 65535')
    return {'name': name, 'lang': lang, 'version': str(body.get('version', ''))[:12], 'folder': folder, 'entry': entry,
            'port': port}


def guess_entry(folder):
    try:
        names = os.listdir(folder)
    except OSError:
        return '', 'python'
    py = [n for n in names if n.endswith('.py') and os.path.isfile(os.path.join(folder, n))]
    js = [n for n in names if n.endswith(('.js', '.mjs', '.cjs')) and os.path.isfile(os.path.join(folder, n))]
    node = 'package.json' in names or (js and not py)
    if node:
        main = ''
        try:
            with open(os.path.join(folder, 'package.json'), encoding='utf-8') as f:
                main = str(json.load(f).get('main') or '')
        except Exception:
            pass
        if main and os.path.isfile(os.path.join(folder, main)):
            return main, 'node'
        want, pool = ['index.js', 'server.js', 'app.js', 'main.js', 'bot.js'], js
    else:
        want, pool = ['main.py', 'app.py', 'server.py', 'bot.py', 'run.py'], py
    return next((w for w in want if w in pool), pool[0] if pool else ''), ('node' if node else 'python')


def save_zip(handler, name, fname=''):
    """Receive a ZIP (raw request body), extract it into projects/<name>/ and describe it."""
    n = int(handler.headers.get('Content-Length') or 0)
    if n <= 0:
        raise ApiError('No file received')
    if n > MAX_ZIP:
        raise ApiError('ZIP is too big (max %d MB)' % (MAX_ZIP >> 20))
    os.makedirs(PROJ_DIR, exist_ok=True)
    base = re.sub(r'[^\w.\-]+', '_', os.path.splitext(name or 'project')[0]).strip('._') or 'project'
    dest, i = os.path.join(PROJ_DIR, base), 2
    while os.path.exists(dest):
        dest = os.path.join(PROJ_DIR, '%s-%d' % (base, i))
        i += 1
    tmp = dest + '.upload.zip'
    try:
        with open(tmp, 'wb') as f:
            left = n
            while left > 0:
                chunk = handler.rfile.read(min(1 << 20, left))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left:
            raise ApiError('Upload was interrupted')
        ext = os.path.splitext(fname or '')[1].lower()
        if ext in ('.py', '.js', '.mjs', '.cjs'):      # a single script instead of a ZIP
            safe = re.sub(r'[^\w.\-]+', '_', os.path.basename(fname)).strip('.') or ('main' + ext)
            os.makedirs(dest)
            os.replace(tmp, os.path.join(dest, safe))
            return {'folder': dest, 'entry': safe, 'lang': 'python' if ext == '.py' else 'node', 'name': os.path.basename(dest)}
        try:
            zf = zipfile.ZipFile(tmp)
        except zipfile.BadZipFile:
            raise ApiError('This is not a valid ZIP file')
        with zf:
            if sum(z.file_size for z in zf.infolist()) > 2 * MAX_ZIP:
                raise ApiError('ZIP is too big when extracted')
            root = os.path.realpath(dest)
            os.makedirs(root)
            for z in zf.infolist():
                if z.filename.startswith('__MACOSX/') or ((z.external_attr >> 16) & 0o170000) == 0o120000:
                    continue                           # mac junk and symlinks are skipped
                target = os.path.realpath(os.path.join(root, z.filename))
                if target != root and not target.startswith(root + os.sep):
                    raise ApiError('Unsafe path in ZIP: %s' % z.filename)
                if z.is_dir():
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with zf.open(z) as src, open(target, 'wb') as out:
                        shutil.copyfileobj(src, out)
        items = [x for x in os.listdir(dest) if x != '__MACOSX']
        if len(items) == 1 and os.path.isdir(os.path.join(dest, items[0])):   # ZIP made from a folder: use its contents
            inner = os.path.join(dest, items[0])
            for x in os.listdir(inner):
                shutil.move(os.path.join(inner, x), os.path.join(dest, x))
            os.rmdir(inner)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    entry, lang = guess_entry(dest)
    return {'folder': dest, 'entry': entry, 'lang': lang, 'name': os.path.basename(dest)}


def fs_op(b):
    """Rename or delete something inside the KratomPM projects folder (nowhere else)."""
    root = os.path.realpath(PROJ_DIR)
    target = os.path.realpath(str(b.get('path', '')))
    if not target.startswith(root + os.sep):
        raise ApiError('Only items inside the KratomPM projects folder can be changed')
    for p in PROJECTS.values():
        f = os.path.realpath(p.cfg['folder'])
        if f == target or f.startswith(target + os.sep):
            raise ApiError('Used by project "%s". Delete that project first' % p.cfg['name'])
    if b.get('op') == 'delete':
        if os.path.isdir(target):
            shutil.rmtree(target)
        else:
            os.remove(target)
    elif b.get('op') == 'rename':
        new = re.sub(r'[^\w.\-]+', '_', str(b.get('name', '')).strip()).strip('.')
        if not new:
            raise ApiError('Enter a new name')
        dest = os.path.join(os.path.dirname(target), new)
        if os.path.realpath(dest) == target:
            return {'ok': True, 'path': dest}
        if os.path.exists(dest):
            raise ApiError('That name already exists')
        os.rename(target, dest)
        return {'ok': True, 'path': dest}
    else:
        raise ApiError('Unknown operation')
    return {'ok': True}


def browse(path):
    path = os.path.abspath(os.path.expanduser(path or '~'))
    while not os.path.isdir(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    dirs, files, note = [], [], ''
    try:
        for n in sorted(os.listdir(path), key=str.lower):
            full = os.path.join(path, n)
            if n.startswith('.'):
                continue
            if os.path.isdir(full):
                dirs.append({'n': n, 'p': full})
            elif n.endswith(('.py', '.js', '.mjs', '.cjs')):
                files.append(n)
    except OSError:
        note = 'Cannot read this folder. On Termux run once: termux-setup-storage'
    os.makedirs(PROJ_DIR, exist_ok=True)
    local = '/sdcard' if os.path.isdir('/sdcard') else os.path.abspath(os.sep)   # phone storage, or the first folder of this computer
    places = [{'n': 'KratomPM projects', 'p': PROJ_DIR}, {'n': 'Local Server', 'p': local}]
    root = os.path.realpath(PROJ_DIR)
    here = os.path.realpath(path)
    parent = os.path.dirname(path)
    return {'kpm': here == root or here.startswith(root + os.sep), 'path': path, 'parent': parent if parent != path else None, 'dirs': dirs, 'files': files, 'note': note, 'places': places}


_DEV = {}


def device_info():
    if not _DEV:
        android = os.path.exists('/system/build.prop') or 'ANDROID_ROOT' in os.environ
        d = {'android': android}
        if android:
            props = {}
            try:
                exe = shutil.which('getprop') or '/system/bin/getprop'
                for line in subprocess.run([exe], capture_output=True, text=True, timeout=8).stdout.splitlines():
                    m = re.match(r'\[(.*?)\]: \[(.*?)\]', line)
                    if m:
                        props[m.group(1)] = m.group(2)
            except Exception:
                pass
            g = lambda k: props.get(k) or '-'
            d.update(os='Android %s (SDK %s)' % (g('ro.build.version.release'), g('ro.build.version.sdk')),
                     brand=g('ro.product.brand').capitalize(), model=g('ro.product.model'),
                     device=g('ro.product.device'), abi=g('ro.product.cpu.abi'))
        else:
            pretty = ''
            try:
                with open('/etc/os-release') as f:
                    kv = dict(l.split('=', 1) for l in f.read().splitlines() if '=' in l)
                pretty = kv.get('PRETTY_NAME', '').strip('"')
            except Exception:
                pass
            d.update(os=pretty or '%s %s' % (platform.system(), platform.release()), brand=platform.machine(),
                     model=platform.node(), device=platform.processor() or platform.machine(), abi=platform.machine())
        node = shutil.which('node')
        d.update(kernel=platform.release(), cores=NCPU, python=platform.python_version(),
                 node=runtime_version(node) if node else 'not installed')
        _DEV.update(d)
    d = dict(_DEV)
    path = '/data' if d['android'] else (os.path.expanduser('~') if WIN else '/')
    try:
        du = shutil.disk_usage(path)
    except Exception:
        path = os.path.expanduser('~')
        du = shutil.disk_usage(path)
    d.update(cpu=SYS['cpu'], cpuPartial=CPU_PARTIAL[0], ramTotal=SYS['total'], ramUsed=SYS['used'], ramPct=SYS['mem'],
             stPath=path, stTotal=du.total, stUsed=du.used, stFree=du.free)
    return d


def pick_project(pid):
    p = PROJECTS.get(int(pid))
    if not p:
        raise ApiError('Project not found', 404)
    return p


def api_get(path, q):
    g = lambda k, d='': q.get(k, [d])[0]
    if path == '/api/state':
        since = int(g('ev', 0) or 0)
        return {'projects': [pjson(p) for p in PROJECTS.values()], 'sys': SYS, 'ping': PING['ms'], 'pingHist': list(PING['hist']),
                'events': [e for e in list(EVENTS) if e['id'] > since],
                'tunnel': {'status': TUN['status'], 'url': TUN['url'], 'err': TUN['err'], 'weak': WEAK[0], 'since': TUN['since']}}
    if path == '/api/info':
        return info()
    if path == '/api/device':
        return device_info()
    if path == '/api/runtimes':
        d = detect_runtimes()
        return {'python': d['python'], 'node': d['node'], 'def': d['def']}
    if path == '/api/logs':
        proj = g('proj', 'all')
        return_lines = get_logs(proj, int(g('after', 0) or 0), min(int(g('limit', 300) or 300), 5000))
        return {'lines': return_lines, 'next': return_lines[-1]['s'] if return_lines else int(g('after', 0) or 0)}
    if path == '/api/browse':
        return browse(g('path'))
    if path == '/api/pkg/list':
        if g('mgr') in PKG:
            st = PKG[g('mgr')]
            if g('outdated') == '1' and not st['checking'] and st['items'] is not None:
                st['checking'] = True
                st['rev'] += 1
                bg(pkg_refresh, g('mgr'), True)
            if st['items'] is None:
                return {'loading': True, 'rev': st['rev']}
            if g('rev') and int(g('rev')) == st['rev']:
                return {'same': True, 'rev': st['rev']}
            return {'packages': st['items'], 'rev': st['rev'], 'checked': st['checked'], 'checking': st['checking'], 'err': st['err']}
        return pkg_list(pick_project(g('id')).cfg, g('outdated') == '1')
    if path == '/api/job':
        job = JOBS.get(g('id'))
        if not job:
            raise ApiError('Job not found', 404)
        after = int(g('after', 0) or 0)
        return {'lines': job['lines'][after:], 'next': len(job['lines']), 'done': job['done'], 'code': job['code']}
    raise ApiError('Not found', 404)


def api_post(path, b):
    if path == '/api/project':
        cfg = clean_cfg(b)
        with LOCK:
            cfg['id'] = DATA['next_id']
            DATA['next_id'] += 1
            cfg['run'] = False
            PROJECTS[cfg['id']] = Project(cfg)
        save()
        event('Project %s added' % cfg['name'], 'info')
        return pjson(PROJECTS[cfg['id']])
    m = re.match(r'^/api/project/(\d+)/(\w+)$', path)
    if m:
        p = pick_project(m.group(1))
        a = m.group(2)
        if a == 'start':
            if p.status == 'running':
                raise ApiError('Already running')
            bg(start_project, p)
            event('%s started' % p.cfg['name'], 'success')
        elif a == 'stop':
            bg(stop_project, p)
            event('%s stopped' % p.cfg['name'], 'warn')
        elif a == 'restart':
            bg(restart_project, p)
            event('%s restarted' % p.cfg['name'], 'success')
        elif a == 'clear':
            p.logs.clear()
        elif a == 'update':
            new = clean_cfg(b, exclude=p.cfg['id'])
            p.cfg.update(new)
            save()
            sys_log(p, 'Settings updated' + (' (restart to apply)' if p.status == 'running' else ''))
        elif a == 'delete':
            def rm():
                stop_project(p, user=False)
                with LOCK:
                    PROJECTS.pop(p.cfg['id'], None)
                save()
            bg(rm)
            event('Project %s deleted' % p.cfg['name'], 'warn')
        else:
            raise ApiError('Unknown action', 404)
        return {'ok': True}
    if path in ('/api/all/restart', '/api/all/stop'):
        for p in list(PROJECTS.values()):
            if path.endswith('restart'):
                bg(restart_project, p)
            elif p.status == 'running':
                bg(stop_project, p)
        event('All projects ' + ('restarted' if path.endswith('restart') else 'stopped'), 'info')
        return {'ok': True}
    if path == '/api/settings':
        s = DATA['settings']
        host = str(b.get('host', s['host'])).strip()
        try:
            port = int(b.get('port', s['port']))
        except Exception:
            raise ApiError('Port must be a number')
        if not host or not 1 <= port <= 65535:
            raise ApiError('Invalid host or port')
        s.update(host=host, port=port, defLang=b.get('defLang', s['defLang']),
                 maxMem=max(0, int(b.get('maxMem') or 0)), retention=int(b.get('retention', 1000)),
                 notifyCrash=bool(b.get('notifyCrash')), notifyStatus=bool(b.get('notifyStatus')), notifyPkg=bool(b.get('notifyPkg')))
        for p in PROJECTS.values():
            p.logs = collections.deque(p.logs, maxlen=s['retention'])
        pw = str(b.get('password', ''))
        if pw:
            if len(pw) < 6:
                raise ApiError('Password must be at least 6 characters')
            set_pw(pw)
        save()
        return info()
    if path == '/api/fs':
        return fs_op(b)
    if path == '/api/pkg/run':
        if b.get('mgr'):
            try:
                cmd = gpkg_cmd(b.get('mgr'), b.get('op', ''), str(b.get('name', '')).strip(), b.get('names'))
            except ValueError as e:
                raise ApiError(str(e))
            env = os.environ.copy()
            env['PIP_BREAK_SYSTEM_PACKAGES'] = '1'
            mgr = b.get('mgr')
            return {'job': run_job(cmd, os.path.expanduser('~'), env, 'pkg', done=lambda: pkg_refresh(mgr))}
        if b.get('id'):
            cfg = pick_project(b['id']).cfg
        else:
            cfg = {'lang': b.get('lang'), 'version': b.get('version', ''), 'folder': os.path.abspath(os.path.expanduser(str(b.get('folder', ''))))}
            if cfg['lang'] not in ('python', 'node'):
                raise ApiError('Invalid language')
        try:
            cmd = pkg_cmd(cfg, b.get('op', ''), str(b.get('name', '')).strip(), b.get('names'))
        except ValueError as e:
            raise ApiError(str(e))
        exe, _ = resolve_runtime(cfg['lang'], cfg.get('version', ''), cfg['folder'])
        return {'job': run_job(cmd, cfg['folder'], rt_env(exe), 'pkg' if b.get('id') else 'setup')}
    raise ApiError('Not found', 404)


# --------------------------------------------------------------------------
# HTTP SERVER
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'KratomPM'

    def log_message(self, *a):
        pass

    def send_body(self, code, body, ctype, headers=None):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, code=200, headers=None):
        self.send_body(code, json.dumps(obj), 'application/json', headers)

    def authed(self):
        c = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
        tok = c['kpm'].value if 'kpm' in c else ''
        return SESSIONS.get(tok, 0) > time.time()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == '/login':
                return self.send_body(200, LOGIN_HTML, 'text/html; charset=utf-8')
            if not self.authed():
                if u.path.startswith('/api/'):
                    return self.send_json({'error': 'Not signed in'}, 401)
                return self.send_body(302, '', 'text/plain', {'Location': '/login'})
            if u.path == '/':
                return self.send_body(200, INDEX_HTML, 'text/html; charset=utf-8')
            if u.path == '/api/export':
                data = {'settings': DATA['settings'], 'projects': [p.cfg for p in PROJECTS.values()]}
                return self.send_body(200, json.dumps(data, indent=2), 'application/json',
                                      {'Content-Disposition': 'attachment; filename="kratompm-config.json"'})
            self.send_json(api_get(u.path, urllib.parse.parse_qs(u.query)))
        except ApiError as e:
            self.send_json({'error': str(e)}, e.code)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self.send_json({'error': 'Server error: %s' % e}, 500)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        try:
            if u.path == '/api/upload':
                if not self.authed():
                    return self.send_json({'error': 'Not signed in'}, 401)
                q = urllib.parse.parse_qs(u.query)
                return self.send_json(save_zip(self, (q.get('name') or [''])[0], (q.get('file') or [''])[0]))
            n = int(self.headers.get('Content-Length') or 0)
            body = json.loads(self.rfile.read(n) or b'{}') if n else {}
            if u.path == '/api/login':
                if not check_pw(str(body.get('password', ''))):
                    time.sleep(1)
                    return self.send_json({'error': 'Wrong password'}, 401)
                tok = secrets.token_urlsafe(24)
                SESSIONS[tok] = time.time() + 7 * 86400
                return self.send_json({'ok': True}, 200, {'Set-Cookie': 'kpm=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800' % tok})
            if not self.authed():
                return self.send_json({'error': 'Not signed in'}, 401)
            if u.path == '/api/logout':
                c = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
                SESSIONS.pop(c['kpm'].value if 'kpm' in c else '', None)
                return self.send_json({'ok': True}, 200, {'Set-Cookie': 'kpm=; Path=/; Max-Age=0'})
            self.send_json(api_post(u.path, body))
        except ApiError as e:
            self.send_json({'error': str(e)}, e.code)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self.send_json({'error': 'Server error: %s' % e}, 500)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --------------------------------------------------------------------------
# WEB UI (login page + dashboard)
# --------------------------------------------------------------------------
LOGIN_HTML = r'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>KratomPM – Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-50 flex items-center justify-center p-4 font-sans">
<form id="f" class="w-full max-w-sm bg-white border border-slate-200 rounded-2xl shadow-sm p-7">
  <div class="flex items-center gap-3 mb-6">
    <span class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-green-700 text-white flex items-center justify-center font-extrabold">K</span>
    <div><div class="font-extrabold text-xl tracking-tight"><span class="text-emerald-600">Kratom</span><span class="text-amber-500">PM</span></div><div class="text-xs text-slate-500">Python &amp; Node.js Process Manager</div></div>
  </div>
  <label class="block text-xs font-semibold text-slate-600 mb-1.5" for="pw">Password</label>
  <input id="pw" type="password" autofocus autocomplete="current-password" class="w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500" placeholder="Enter password">
  <p id="err" class="hidden text-sm text-red-600 mt-2"></p>
  <button class="mt-5 w-full rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold py-2.5 transition">Sign in</button>
</form>
<script>
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  const err = document.getElementById('err'); err.classList.add('hidden');
  const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:document.getElementById('pw').value})});
  if (r.ok) location.href = '/'; else { err.textContent = (await r.json()).error || 'Login failed'; err.classList.remove('hidden'); }
});
</script></body></html>
'''

INDEX_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KratomPM – Process Manager</title>
<script>try{ if(localStorage.getItem('kpm-theme')==='dark') document.documentElement.classList.add('dark'); }catch(e){}</script>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = { darkMode:'class', theme:{ extend:{ fontFamily:{
  sans:['Inter','ui-sans-serif','system-ui','-apple-system','Segoe UI','Roboto','sans-serif'],
  mono:['JetBrains Mono','ui-monospace','SFMono-Regular','Menlo','Consolas','monospace'] } } } };
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

<style type="text/tailwindcss">
@layer components {
  .card { @apply bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm; }
  .btn { @apply inline-flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition active:scale-95 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500/50 disabled:opacity-50 disabled:pointer-events-none whitespace-nowrap; }
  .btn-primary { @apply bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm; }
  .btn-success { @apply bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm; }
  .btn-warn { @apply bg-amber-500 text-white hover:bg-amber-600 shadow-sm; }
  .btn-danger { @apply bg-red-500 text-white hover:bg-red-600 shadow-sm; }
  .btn-outline { @apply border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800; }
  .btn-danger-outline { @apply border border-red-300 dark:border-red-500/50 bg-white dark:bg-slate-900 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10; }
  .input { @apply w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 focus:border-emerald-500; }
  .label { @apply block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1.5; }
  .badge { @apply inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold whitespace-nowrap; }
  .abtn { @apply inline-flex items-center justify-center gap-1.5 h-8 min-w-[2rem] px-2 rounded-lg text-white text-xs font-semibold transition hover:brightness-110 active:scale-95 disabled:opacity-40 disabled:pointer-events-none; }
  .ghost-btn { @apply w-9 h-9 inline-flex items-center justify-center rounded-lg text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition; }
  .nav-item { @apply flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-[15px] font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition; }
  .nav-item.active { @apply bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400; }
  .menu-item { @apply w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-left hover:bg-slate-100 dark:hover:bg-slate-800 transition; }
}
</style>
<style>
  html { font-size: 13px; }
  .term { background:#020617; color:#e2e8f0; font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace; font-size:12px; line-height:1.65; overflow-y:auto; overflow-wrap:anywhere; scrollbar-width:thin; scrollbar-color:#334155 transparent; }
  .term::-webkit-scrollbar { width:8px; height:8px; }
  .term::-webkit-scrollbar-thumb { background:#334155; border-radius:8px; }
  @keyframes toastIn { from { opacity:0; transform:translateY(8px) scale(.98);} to { opacity:1; transform:none; } }
  .toast { animation:toastIn .2s ease; }
  .toast.out { opacity:0; transform:translateY(8px); transition:all .25s; }
  .fade-in { animation:toastIn .25s ease; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .spin { animation:spin 1s linear infinite; }
</style>
</head>

<body class="font-sans bg-slate-50 text-slate-800 dark:bg-slate-950 dark:text-slate-200 antialiased">

<!-- TOP BAR -->
<header class="sticky top-0 z-40 h-16 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800">
  <div class="h-full px-3 sm:px-5 flex items-center gap-2 sm:gap-4">
    <button data-act="menu-toggle" class="ghost-btn lg:hidden" aria-label="Open menu"><i data-icon="menu" class="w-5 h-5"></i></button>
    <a href="#dashboard" class="flex items-center gap-2.5 shrink-0">
      <span class="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 to-green-700 text-white flex items-center justify-center shadow font-extrabold">K</span>
      <span class="hidden sm:block leading-tight">
        <span class="block font-extrabold text-lg tracking-tight"><span class="text-emerald-600">Kratom</span><span class="text-amber-500">PM</span></span>
        <span class="block text-[11px] text-slate-500 dark:text-slate-400">Python &amp; Node.js Process Manager</span>
      </span>
    </a>
    <div class="hidden xl:flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400">
      <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
      <span class="text-sm font-medium">Running on: <span id="pillHost">-</span></span>
    </div>
    <div class="flex-1 flex justify-center">
      <div class="flex items-center gap-2 px-3 py-1.5 rounded-full border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60">
        <span id="pingDot" class="w-2.5 h-2.5 rounded-full bg-slate-400"></span>
        <span id="pingTop" class="text-sm font-medium tabular-nums">Ping: --</span>
      </div>
    </div>
    <div class="flex items-center gap-1 sm:gap-2">
      <button id="themeBtn" data-act="theme" class="ghost-btn" aria-label="Toggle dark mode"></button>
      <div class="dd relative">
        <button data-act="dd" data-target="notifMenu" class="ghost-btn relative" aria-label="Notifications">
          <i data-icon="bell" class="w-5 h-5"></i>
          <span id="notifBadge" class="hidden absolute -top-0.5 -right-0.5 min-w-[18px] h-[18px] px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">0</span>
        </button>
        <div id="notifMenu" class="hidden fixed left-3 right-3 top-[4.25rem] sm:absolute sm:left-auto sm:right-0 sm:top-full sm:mt-2 sm:w-80 card shadow-xl z-50 overflow-hidden fade-in">
          <div class="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800">
            <span class="font-semibold text-sm">Notifications</span>
            <span class="flex gap-3 text-xs font-semibold"><button data-act="notif-read" class="text-emerald-600 dark:text-emerald-400">Mark read</button><button data-act="notif-clear" class="text-slate-500">Clear</button></span>
          </div>
          <div id="notifList" class="max-h-80 overflow-y-auto"></div>
        </div>
      </div>
      <div class="dd relative">
        <button data-act="dd" data-target="adminMenu" class="flex items-center gap-2 pl-1 pr-1 sm:pr-2 h-10 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 transition">
          <span class="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-slate-500 dark:text-slate-300"><i data-icon="user" class="w-4 h-4"></i></span>
          <span class="hidden sm:block text-sm font-medium">Admin</span>
          <i data-icon="chevron" class="hidden sm:block w-4 h-4 text-slate-400"></i>
        </button>
        <div id="adminMenu" class="hidden absolute right-0 top-full mt-2 w-48 card shadow-xl p-1.5 z-50 fade-in">
          <a href="#settings" class="menu-item"><i data-icon="sliders" class="w-4 h-4"></i>Settings</a>
          <button data-act="logout" class="menu-item text-red-600 dark:text-red-400"><i data-icon="logout" class="w-4 h-4"></i>Logout</button>
        </div>
      </div>
    </div>
  </div>
</header>

<div id="overlay" data-act="menu-toggle" class="fixed inset-0 z-40 bg-slate-900/50 opacity-0 pointer-events-none transition-opacity duration-300 lg:hidden"></div>

<div class="flex">
  <!-- SIDEBAR -->
  <aside id="sidebar" class="fixed lg:sticky z-50 lg:z-20 top-0 lg:top-16 left-0 lg:self-start h-full lg:h-[calc(100vh-4rem)] w-72 lg:w-64 shrink-0 -translate-x-full lg:translate-x-0 transition-transform duration-300 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col p-4 overflow-y-auto">
    <div class="flex items-center justify-between mb-4 lg:hidden">
      <span class="font-extrabold text-lg"><span class="text-emerald-600">Kratom</span><span class="text-amber-500">PM</span></span>
      <button data-act="menu-toggle" class="ghost-btn" aria-label="Close menu"><i data-icon="x" class="w-5 h-5"></i></button>
    </div>
    <nav class="space-y-1">
      <a href="#dashboard" data-nav="dashboard" class="nav-item"><i data-icon="home" class="w-5 h-5"></i>Dashboard</a>
      <a href="#projects"  data-nav="projects"  class="nav-item"><i data-icon="cube" class="w-5 h-5"></i>Projects</a>
      <a href="#packages"  data-nav="packages"  class="nav-item"><i data-icon="grid" class="w-5 h-5"></i>Packages</a>
      <a href="#logs"      data-nav="logs"      class="nav-item"><i data-icon="file" class="w-5 h-5"></i>Logs</a>
      <a href="#system"    data-nav="system"    class="nav-item"><i data-icon="monitor" class="w-5 h-5"></i>System</a>
      <a href="#settings"  data-nav="settings"  class="nav-item"><i data-icon="sliders" class="w-5 h-5"></i>Settings</a>
      <a href="#about"     data-nav="about"     class="nav-item"><i data-icon="info" class="w-5 h-5"></i>About</a>
    </nav>
    <div class="mt-auto pt-6">
      <div class="rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 p-4 text-center">
        <div class="flex items-center justify-center gap-2 font-semibold text-sm"><span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>Server Online</div>
        <div id="sideHost" class="text-sm text-slate-500 dark:text-slate-400 mt-1">-</div>
        <div class="mt-3 h-9 rounded-lg bg-emerald-600 text-white text-sm font-semibold flex items-center justify-center gap-2"><i data-icon="signal" class="w-4 h-4"></i><span id="sidePing">Ping: --</span></div>
      </div>
    </div>
  </aside>

  <main class="flex-1 min-w-0 p-3 sm:p-5 lg:p-6 pb-12">

    <!-- DASHBOARD -->
    <section data-page="dashboard">
      <div class="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div class="flex items-center gap-3">
          <span class="w-11 h-11 rounded-xl bg-emerald-100 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center justify-center"><i data-icon="activity" class="w-6 h-6"></i></span>
          <div><h1 class="text-xl font-bold tracking-tight">Dashboard</h1><p class="text-sm text-slate-500 dark:text-slate-400">Monitor and manage your Python &amp; Node.js projects</p></div>
        </div>
        <div class="flex flex-wrap gap-2">
          <button data-act="add" class="btn btn-primary"><i data-icon="plus" class="w-4 h-4"></i>Add Project</button>
          <button data-act="restartall" class="btn btn-danger-outline"><i data-icon="restart" class="w-4 h-4"></i>Restart All</button>
          <button data-act="stopall" class="btn btn-danger"><i data-icon="stop" class="w-4 h-4"></i>Stop All</button>
        </div>
      </div>
      <div id="tunnelCard" class="hidden mb-5"></div>
      <div id="statsRow" class="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3 sm:gap-4 mb-5"></div>

      <div class="card mb-5 overflow-hidden">
        <div class="flex flex-wrap items-center justify-between gap-3 p-4">
          <h2 class="flex items-center gap-2.5 text-lg font-bold"><i data-icon="cube" class="w-5 h-5 text-emerald-600"></i>Projects</h2>
          <div class="flex gap-2 w-full sm:w-auto">
            <div class="relative flex-1 sm:w-64"><i data-icon="search" class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i><input id="fDashQ" class="input pl-9" placeholder="Search projects..."></div>
            <select id="fDashStatus" class="input w-auto"><option value="all">All Status</option><option value="running">Running</option><option value="stopped">Stopped</option><option value="crashed">Crashed</option></select>
          </div>
        </div>
        <div id="list-dash"></div>
      </div>

      <div class="grid lg:grid-cols-2 gap-5">
        <div class="card p-5 min-w-0">
          <h2 class="flex items-center gap-2.5 text-lg font-bold mb-4"><i data-icon="monitor" class="w-5 h-5 text-emerald-600"></i>System Resources</h2>
          <div class="flex flex-wrap items-center justify-around gap-5">
            <div class="text-center">
              <div class="relative w-24 h-24 mx-auto">
                <svg viewBox="0 0 120 120" class="w-24 h-24 -rotate-90"><circle cx="60" cy="60" r="48" fill="none" stroke-width="10" class="stroke-slate-200 dark:stroke-slate-800"/><circle id="gCpuArc" cx="60" cy="60" r="48" fill="none" stroke-width="10" stroke-linecap="round" stroke="#3b82f6" stroke-dasharray="301.59" stroke-dashoffset="301.59" style="transition:stroke-dashoffset .7s ease"/></svg>
                <div id="gCpuTxt" class="absolute inset-0 flex items-center justify-center text-xl font-bold tabular-nums">0%</div>
              </div>
              <div class="mt-2 text-sm font-medium">CPU Usage</div>
            </div>
            <div class="text-center">
              <div class="relative w-24 h-24 mx-auto">
                <svg viewBox="0 0 120 120" class="w-24 h-24 -rotate-90"><circle cx="60" cy="60" r="48" fill="none" stroke-width="10" class="stroke-slate-200 dark:stroke-slate-800"/><circle id="gMemArc" cx="60" cy="60" r="48" fill="none" stroke-width="10" stroke-linecap="round" stroke="#10b981" stroke-dasharray="301.59" stroke-dashoffset="301.59" style="transition:stroke-dashoffset .7s ease"/></svg>
                <div id="gMemTxt" class="absolute inset-0 flex items-center justify-center text-xl font-bold tabular-nums">0%</div>
              </div>
              <div class="mt-2 text-sm font-medium">Memory Usage</div>
            </div>
            <div class="w-full sm:w-44 text-center sm:text-left sm:border-l sm:border-slate-200 sm:dark:border-slate-800 sm:pl-5">
              <div class="flex items-center justify-center sm:justify-start gap-2 text-sm font-medium"><i data-icon="wifi" class="w-4 h-4 text-emerald-600"></i>Network (Ping)</div>
              <div id="netMs" class="text-2xl font-bold mt-2 tabular-nums">--</div>
              <svg viewBox="0 0 200 60" preserveAspectRatio="none" class="w-full h-16 mt-2">
                <defs><linearGradient id="pingGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#10b981" stop-opacity=".3"/><stop offset="1" stop-color="#10b981" stop-opacity="0"/></linearGradient></defs>
                <path id="pingArea" fill="url(#pingGrad)"/><path id="pingLine" fill="none" stroke="#10b981" stroke-width="2" vector-effect="non-scaling-stroke"/>
              </svg>
            </div>
          </div>
          <div class="mt-5 pt-4 border-t border-slate-100 dark:border-slate-800"><div class="text-sm font-medium mb-3">Usage by project</div><div id="topUse" class="space-y-3"></div></div>
        </div>
        <div class="card p-5 min-w-0">
          <div class="flex items-center justify-between gap-3 mb-3">
            <h2 class="flex items-center gap-2.5 text-lg font-bold"><i data-icon="terminal" class="w-5 h-5 text-emerald-600"></i>Terminal / Logs</h2>
            <select id="dashSelect" class="input w-auto max-w-[9rem] sm:max-w-none"></select>
          </div>
          <div class="rounded-xl overflow-hidden bg-slate-950 border border-slate-800">
            <div id="dashTerm" class="term h-52 p-3"></div>
            <div class="flex items-center justify-between gap-2 px-3 py-2 border-t border-slate-800 bg-slate-900">
              <button data-act="dash-live" class="flex items-center gap-2 text-xs text-slate-300"><span id="dashLiveDot" class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span><span id="dashLiveTxt">Live Logs</span></button>
              <div class="flex gap-2">
                <button data-act="dash-clear" class="px-2.5 py-1.5 rounded-md text-xs font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 flex items-center gap-1.5"><i data-icon="trash" class="w-3.5 h-3.5"></i>Clear</button>
                <button data-act="dash-dl" class="px-2.5 py-1.5 rounded-md text-xs font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 flex items-center gap-1.5"><i data-icon="download" class="w-3.5 h-3.5"></i>Download</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- PROJECTS -->
    <section data-page="projects" class="hidden">
      <div class="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div class="flex items-center gap-3">
          <span class="w-11 h-11 rounded-xl bg-emerald-100 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center justify-center"><i data-icon="cube" class="w-6 h-6"></i></span>
          <div><h1 class="text-xl font-bold tracking-tight">Projects</h1><p id="pageCount" class="text-sm text-slate-500 dark:text-slate-400"></p></div>
        </div>
        <div class="flex flex-wrap gap-2">
          <button data-act="add" class="btn btn-primary"><i data-icon="plus" class="w-4 h-4"></i>Add Project</button>
          <button data-act="restartall" class="btn btn-danger-outline"><i data-icon="restart" class="w-4 h-4"></i>Restart All</button>
          <button data-act="stopall" class="btn btn-danger"><i data-icon="stop" class="w-4 h-4"></i>Stop All</button>
        </div>
      </div>
      <div class="card overflow-hidden">
        <div class="flex flex-wrap gap-2 p-4">
          <div class="relative flex-1 min-w-[180px]"><i data-icon="search" class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i><input id="fPageQ" class="input pl-9" placeholder="Search by name or folder..."></div>
          <select id="fPageStatus" class="input w-auto"><option value="all">All Status</option><option value="running">Running</option><option value="stopped">Stopped</option><option value="crashed">Crashed</option></select>
          <select id="fPageLang" class="input w-auto"><option value="all">All Languages</option><option value="python">Python</option><option value="node">Node.js</option></select>
          <select id="fPageSort" class="input w-auto"><option value="name">Sort: Name</option><option value="status">Sort: Status</option><option value="cpu">Sort: CPU</option><option value="ram">Sort: RAM</option></select>
        </div>
        <div id="list-page"></div>
      </div>
    </section>

    <!-- PACKAGES -->
    <section data-page="packages" class="hidden">
      <div class="flex items-center gap-3 mb-5">
        <span class="w-11 h-11 rounded-xl bg-purple-100 dark:bg-purple-500/15 text-purple-600 dark:text-purple-400 flex items-center justify-center"><i data-icon="grid" class="w-6 h-6"></i></span>
        <div><h1 class="text-xl font-bold tracking-tight">Packages</h1><p class="text-sm text-slate-500 dark:text-slate-400">Global pip &amp; npm packages on this device</p></div>
      </div>
      <div id="pkgPills" class="flex gap-2 overflow-x-auto pb-2 mb-3"></div>
      <div class="grid xl:grid-cols-5 gap-5">
        <div class="card xl:col-span-3 overflow-hidden">
          <div class="flex flex-wrap items-center justify-between gap-3 p-4">
            <div><h2 class="font-bold text-lg">Installed packages</h2><p id="pkgMeta" class="text-xs text-slate-500 dark:text-slate-400"></p></div>
            <div class="flex flex-wrap gap-2 w-full sm:w-auto">
              <div class="relative flex-1 sm:w-40"><i data-icon="search" class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i><input id="pkgQ" class="input pl-9" placeholder="Filter..."></div>
              <button data-act="pkgcheck" class="btn btn-outline"><i data-icon="restart" class="w-4 h-4"></i>Check updates</button>
              <button data-act="pkgupdateall" class="btn btn-outline"><i data-icon="up" class="w-4 h-4"></i>Update all</button>
            </div>
          </div>
          <div id="pkgTable" class="overflow-x-auto"></div>
        </div>
        <div class="xl:col-span-2 space-y-5 min-w-0">
          <div class="card p-5">
            <h2 class="font-bold text-lg mb-3">Install package</h2>
            <div class="flex gap-2">
              <input id="pkgInput" class="input" placeholder="e.g. flask  or  axios@1.7.0" autocomplete="off">
              <button data-act="pkginstall" class="btn btn-primary"><i data-icon="download" class="w-4 h-4"></i>Install</button>
            </div>
          </div>
          <div class="card overflow-hidden">
            <div class="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800"><span class="font-semibold text-sm flex items-center gap-2"><i data-icon="terminal" class="w-4 h-4 text-emerald-600"></i>Output <span id="pkgState" class="text-xs font-medium text-slate-500"></span></span><button data-act="pkgclear" class="text-xs font-semibold text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">Clear</button></div>
            <div id="pkgTerm" class="term h-64 p-3"></div>
          </div>
        </div>
      </div>
    </section>

    <!-- LOGS -->
    <section data-page="logs" class="hidden">
      <div class="flex items-center gap-3 mb-5">
        <span class="w-11 h-11 rounded-xl bg-emerald-100 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center justify-center"><i data-icon="file" class="w-6 h-6"></i></span>
        <div><h1 class="text-xl font-bold tracking-tight">Logs</h1><p class="text-sm text-slate-500 dark:text-slate-400">Live output from all your processes</p></div>
      </div>
      <div class="card p-3 sm:p-4 mb-4 flex flex-wrap gap-2 items-center">
        <select id="lg-proj" class="input w-auto"></select>
        <select id="lg-lvl" class="input w-auto"><option value="all">All levels</option><option>INFO</option><option>WARN</option><option>ERROR</option><option>SYS</option></select>
        <div class="relative flex-1 min-w-[160px]"><i data-icon="search" class="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"></i><input id="lg-q" class="input pl-9" placeholder="Search logs..."></div>
        <button data-act="lg-live" class="btn btn-outline"><span id="lgLiveDot" class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span><span id="lgLiveTxt">Live</span></button>
        <button data-act="lg-auto" id="lgAutoBtn" class="btn btn-outline">Auto-scroll: ON</button>
        <button data-act="lg-clear" class="btn btn-outline"><i data-icon="trash" class="w-4 h-4"></i>Clear</button>
        <button data-act="lg-dl" class="btn btn-outline"><i data-icon="download" class="w-4 h-4"></i>Download</button>
      </div>
      <div class="rounded-2xl overflow-hidden border border-slate-800 bg-slate-950 shadow-sm">
        <div class="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900 text-xs text-slate-400"><span class="font-mono">$ tail -f logs</span><span id="lgCount"></span></div>
        <div id="logsTerm" class="term h-[62vh] p-3"></div>
      </div>
    </section>

    <!-- SYSTEM -->
    <section data-page="system" class="hidden">
      <div class="flex items-center gap-3 mb-5">
        <span class="w-11 h-11 rounded-xl bg-sky-100 dark:bg-sky-500/15 text-sky-600 dark:text-sky-400 flex items-center justify-center"><i data-icon="monitor" class="w-6 h-6"></i></span>
        <div><h1 class="text-xl font-bold tracking-tight">System</h1><p class="text-sm text-slate-500 dark:text-slate-400">Device information and live resources</p></div>
      </div>
      <div id="sysBody"></div>
    </section>

    <!-- SETTINGS -->
    <section data-page="settings" class="hidden">
      <div class="flex flex-wrap items-start justify-between gap-4 mb-5">
        <div class="flex items-center gap-3">
          <span class="w-11 h-11 rounded-xl bg-amber-100 dark:bg-amber-500/15 text-amber-600 dark:text-amber-400 flex items-center justify-center"><i data-icon="sliders" class="w-6 h-6"></i></span>
          <div><h1 class="text-xl font-bold tracking-tight">Settings</h1><p class="text-sm text-slate-500 dark:text-slate-400">Configure KratomPM and process behaviour</p></div>
        </div>
        <button data-act="save-settings" class="btn btn-primary"><i data-icon="check" class="w-4 h-4"></i>Save changes</button>
      </div>
      <div id="settingsBody"></div>
    </section>

    <!-- ABOUT -->
    <section data-page="about" class="hidden">
      <div class="flex items-center gap-3 mb-5">
        <span class="w-11 h-11 rounded-xl bg-sky-100 dark:bg-sky-500/15 text-sky-600 dark:text-sky-400 flex items-center justify-center"><i data-icon="info" class="w-6 h-6"></i></span>
        <div><h1 class="text-xl font-bold tracking-tight">About</h1><p class="text-sm text-slate-500 dark:text-slate-400">Version, system information and features</p></div>
      </div>
      <div id="aboutBody"></div>
    </section>
  </main>
</div>

<!-- MODAL: TERMINAL (opens from the Logs button) -->
<div id="modal-term" data-modal class="fixed inset-0 z-[60] flex items-center justify-center p-3 sm:p-4 opacity-0 pointer-events-none transition-opacity duration-200">
  <div class="absolute inset-0 bg-slate-900/60" data-act="close-modal"></div>
  <div class="modal-panel relative card w-full max-w-4xl max-h-[94vh] overflow-hidden flex flex-col transition duration-200 scale-95 translate-y-2">
    <div id="termHead" class="flex items-center justify-between gap-3 px-4 py-3 border-b border-slate-100 dark:border-slate-800"></div>
    <div class="bg-slate-950 flex-1 min-h-0"><div id="termBody" class="term h-[58vh] p-3"></div></div>
    <div class="flex items-center justify-between gap-2 px-4 py-2.5 bg-slate-900 border-t border-slate-800">
      <button data-act="term-auto" data-autobtn="term" class="px-2 py-1 rounded-md text-[11px] font-semibold border"></button>
      <div class="flex gap-2">
        <button data-act="term-clear" class="px-2.5 py-1.5 rounded-md text-xs font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 flex items-center gap-1.5"><i data-icon="trash" class="w-3.5 h-3.5"></i>Clear</button>
        <button data-act="term-dl" class="px-2.5 py-1.5 rounded-md text-xs font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 flex items-center gap-1.5"><i data-icon="download" class="w-3.5 h-3.5"></i>Download</button>
      </div>
    </div>
  </div>
</div>

<!-- MODAL: PROJECT DETAIL + SETTINGS -->
<div id="modal-detail" data-modal class="fixed inset-0 z-[60] flex items-center justify-center p-3 sm:p-4 opacity-0 pointer-events-none transition-opacity duration-200">
  <div class="absolute inset-0 bg-slate-900/60" data-act="close-modal"></div>
  <div class="modal-panel relative card w-full max-w-3xl max-h-[94vh] overflow-y-auto transition duration-200 scale-95 translate-y-2">
    <div id="detailHead" class="flex items-start justify-between gap-3 p-4 sm:p-5 border-b border-slate-100 dark:border-slate-800"></div>
    <div class="p-4 sm:p-5 space-y-5">
      <div id="detailInfo" class="grid grid-cols-2 sm:grid-cols-5 gap-2"></div>
      <div id="detailActions" class="flex flex-wrap gap-2"></div>
      <form id="detailForm" class="rounded-xl border border-slate-200 dark:border-slate-800 p-3 sm:p-4" novalidate>
        <h4 class="text-sm font-bold mb-3 flex items-center gap-2"><i data-icon="sliders" class="w-4 h-4 text-emerald-600"></i>Project settings</h4>
        <div class="grid sm:grid-cols-3 gap-3">
          <div><label class="label" for="d-name">Project name</label><input id="d-name" class="input" autocomplete="off"></div>
          <div><label class="label" for="d-lang">Language</label><select id="d-lang" class="input"><option value="python">Python</option><option value="node">Node.js</option></select></div>
          <div><label class="label" for="d-ver">Version</label><select id="d-ver" class="input"></select></div>
          <div class="sm:col-span-3"><label class="label" for="d-folder">Folder location</label>
            <div class="flex gap-2"><input id="d-folder" class="input" autocomplete="off"><button type="button" data-act="browse" data-t="d" class="btn btn-outline"><i data-icon="folder" class="w-4 h-4"></i>Browse</button></div></div>
          <div><label class="label" for="d-entry">Entry file</label><input id="d-entry" class="input" autocomplete="off"></div>
          <div><label class="label" for="d-port">Port (sent as PORT env)</label><input id="d-port" type="number" class="input" placeholder="optional"></div>
                  </div>
        <p id="d-err" class="hidden text-sm text-red-600 dark:text-red-400 font-medium mt-3"></p>
        <div class="flex justify-end gap-2 mt-4"><button type="button" data-act="detail-reset" class="btn btn-outline">Reset</button><button type="submit" class="btn btn-primary"><i data-icon="check" class="w-4 h-4"></i>Save changes</button></div>
      </form>
      <div class="rounded-xl overflow-hidden border border-slate-800 bg-slate-950">
        <div class="flex items-center justify-between gap-2 px-3 py-2 border-b border-slate-800 bg-slate-900">
          <span class="text-xs font-mono text-slate-400">Terminal output</span>
          <div class="flex gap-2"><button data-act="detail-auto" data-autobtn="detail" class="px-2 py-1 rounded-md text-[11px] font-semibold border"></button><button data-act="detail-clear" class="px-2 py-1 rounded-md text-[11px] font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800">Clear</button></div>
        </div>
        <div id="detailTerm" class="term h-52 sm:h-64 p-3"></div>
      </div>
    </div>
  </div>
</div>

<!-- MODAL: ADD PROJECT -->
<div id="modal-form" data-modal class="fixed inset-0 z-[60] flex items-center justify-center p-3 sm:p-4 opacity-0 pointer-events-none transition-opacity duration-200">
  <div class="absolute inset-0 bg-slate-900/60" data-act="close-modal"></div>
  <form id="projForm" class="modal-panel relative card w-full max-w-lg max-h-[94vh] overflow-y-auto transition duration-200 scale-95 translate-y-2" novalidate>
    <div class="flex items-center justify-between p-4 sm:p-5 border-b border-slate-100 dark:border-slate-800">
      <h3 class="text-lg font-bold">Add Project</h3>
      <button type="button" data-act="close-modal" class="ghost-btn" aria-label="Close"><i data-icon="x" class="w-5 h-5"></i></button>
    </div>
    <div class="p-4 sm:p-5 space-y-4">
      <div><label class="label" for="f-name">Project name</label><input id="f-name" class="input" placeholder="my-awesome-app" autocomplete="off"></div>
      <div class="grid grid-cols-2 gap-3">
        <div><label class="label" for="f-lang">Language</label><select id="f-lang" class="input"><option value="python">Python</option><option value="node">Node.js</option></select></div>
        <div><label class="label" for="f-ver">Version</label><select id="f-ver" class="input"></select></div>
      </div>
      <div><label class="label" for="f-folder">Folder location</label>
        <div class="flex gap-2"><input id="f-folder" class="input" placeholder="/var/www/my-project" autocomplete="off"><button type="button" data-act="browse" data-t="f" class="btn btn-outline"><i data-icon="folder" class="w-4 h-4"></i>Browse</button></div>
        <div class="mt-2"><input id="f-zip" type="file" class="hidden"><button type="button" id="f-zipBtn" data-act="zip" class="btn btn-outline w-full"><i data-icon="box" class="w-4 h-4"></i>Upload from this device (ZIP or .py / .js file)</button></div>
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="col-span-2"><label class="label" for="f-entry">Entry file</label><input id="f-entry" class="input" placeholder="main.py" autocomplete="off"></div>
        <div><label class="label" for="f-port">Port</label><input id="f-port" type="number" class="input" placeholder="optional"></div>
      </div>
      <div class="rounded-xl border border-slate-200 dark:border-slate-800 p-3">
        <div class="flex items-center justify-between gap-3">
          <label class="flex items-center gap-2.5 text-sm font-medium cursor-pointer"><input id="f-install" type="checkbox" class="w-4 h-4 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500">Install dependencies</label>
          <button type="button" id="f-installBtn" data-act="install" class="btn btn-outline !py-1.5 !text-xs" disabled><i data-icon="download" class="w-3.5 h-3.5"></i>Install</button>
        </div>
        <div id="f-term" class="term hidden h-36 rounded-lg p-3 mt-3"></div>
      </div>
      <p id="f-err" class="hidden text-sm text-red-600 dark:text-red-400 font-medium"></p>
    </div>
    <div class="flex justify-end gap-2 p-4 sm:p-5 border-t border-slate-100 dark:border-slate-800">
      <button type="button" data-act="close-modal" class="btn btn-outline">Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button>
    </div>
  </form>
</div>

<!-- MODAL: FOLDER BROWSER -->
<div id="modal-browse" data-modal class="fixed inset-0 z-[75] flex items-center justify-center p-3 sm:p-4 opacity-0 pointer-events-none transition-opacity duration-200">
  <div class="absolute inset-0 bg-slate-900/60" data-act="close-modal"></div>
  <div class="modal-panel relative card w-full max-w-md max-h-[86vh] flex flex-col transition duration-200 scale-95 translate-y-2">
    <div class="flex items-center justify-between p-4 border-b border-slate-100 dark:border-slate-800"><div><h3 class="font-bold">Choose folder</h3><p class="text-[11px] text-slate-500 dark:text-slate-400">Local Server = the device running KratomPM. My device = upload from the device you are using now.</p></div><button data-act="close-modal" class="ghost-btn" aria-label="Close"><i data-icon="x" class="w-5 h-5"></i></button></div>
    <div id="brPlaces" class="flex flex-wrap gap-1.5 px-4 pt-3"></div>
    <div class="px-4 py-2 border-b border-slate-100 dark:border-slate-800"><input id="brPath" class="input !py-1.5 !text-xs font-mono" autocomplete="off" spellcheck="false"></div>
    <div id="brList" class="flex-1 overflow-y-auto p-2 min-h-[200px]"></div>
    <div class="flex justify-end gap-2 p-4 border-t border-slate-100 dark:border-slate-800"><button data-act="close-modal" class="btn btn-outline">Cancel</button><button data-act="br-select" class="btn btn-primary">Select this folder</button></div>
  </div>
</div>

<!-- MODAL: DELETE CONFIRMATION -->
<div id="modal-delete" data-modal class="fixed inset-0 z-[70] flex items-center justify-center p-4 opacity-0 pointer-events-none transition-opacity duration-200">
  <div class="absolute inset-0 bg-slate-900/60" data-act="close-modal"></div>
  <div class="modal-panel relative card w-full max-w-sm p-6 text-center transition duration-200 scale-95 translate-y-2">
    <div class="w-12 h-12 rounded-full bg-red-100 dark:bg-red-500/15 text-red-600 dark:text-red-400 flex items-center justify-center mx-auto"><i data-icon="trash" class="w-6 h-6"></i></div>
    <h3 class="text-lg font-bold mt-4">Delete project?</h3>
    <p class="text-sm text-slate-500 dark:text-slate-400 mt-1.5">This stops and removes <b id="delName" class="text-slate-800 dark:text-slate-200"></b> from KratomPM. Your files are not deleted.</p>
    <div class="flex gap-2 mt-6"><button data-act="close-modal" class="btn btn-outline flex-1">Cancel</button><button data-act="confirm-delete" class="btn btn-danger flex-1">Delete</button></div>
  </div>
</div>

<div id="floatMenu" class="hidden fixed z-[55] w-44 card shadow-xl p-1.5 fade-in">
  <button data-act="detail" class="menu-item"><i data-icon="info" class="w-4 h-4"></i>Details &amp; settings</button>
  <button data-act="delete" class="menu-item text-red-600 dark:text-red-400"><i data-icon="trash" class="w-4 h-4"></i>Delete</button>
</div>
<div id="toasts" class="fixed z-[80] bottom-4 left-4 right-4 sm:left-auto sm:right-5 sm:w-80 flex flex-col gap-2 pointer-events-none"></div>

<script>
/* ======================= HELPERS ======================= */
const $  = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];
const pad = n => String(n).padStart(2,'0');
const clamp = (v,a,b) => Math.min(b, Math.max(a, v));
const clock = t => { const d=new Date(t); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ago = t => { const s=Math.floor((Date.now()-t)/1000); if(s<60) return 'just now'; const m=Math.floor(s/60); if(m<60) return m+'m ago'; const h=Math.floor(m/60); return h<24 ? h+'h ago' : Math.floor(h/24)+'d ago'; };
function download(name, text, type='text/plain'){
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text],{type})); a.download = name;
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}

/* ======================= ICONS ======================= */
const ICONS = {
  home:'<path d="M3 11l9-8 9 8"/><path d="M5 10v10h5v-6h4v6h5V10"/>',
  cube:'<path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M12 12l9-5M12 12v10M12 12L3 7"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  file:'<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
  sliders:'<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.01"/>',
  play:'<path d="M7 4.5v15l13-7.5z" fill="currentColor"/>',
  stop:'<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor"/>',
  restart:'<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>',
  terminal:'<path d="M4 17l6-6-6-6M12 19h8"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  trash:'<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14M10 11v5M14 11v5"/>',
  dots:'<circle cx="12" cy="5" r="1.6" fill="currentColor"/><circle cx="12" cy="12" r="1.6" fill="currentColor"/><circle cx="12" cy="19" r="1.6" fill="currentColor"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  bell:'<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 01-3.4 0"/>',
  user:'<path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  chevron:'<path d="M6 9l6 6 6-6"/>',
  x:'<path d="M18 6L6 18M6 6l12 12"/>',
  menu:'<path d="M3 6h18M3 12h18M3 18h18"/>',
  sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon:'<path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/>',
  download:'<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
  cpu:'<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
  ram:'<rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 11v2M10 11v2M14 11v2M18 11v2M6 17v2M18 17v2"/>',
  wifi:'<path d="M5 12.5a10 10 0 0114 0M8.5 16a5 5 0 017 0M2 9a15 15 0 0120 0"/><circle cx="12" cy="19.5" r="1" fill="currentColor"/>',
  monitor:'<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
  check:'<path d="M20 6L9 17l-5-5"/>',
  folder:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  up:'<path d="M12 19V5M5 12l7-7 7 7"/>',
  activity:'<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  logout:'<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>',
  signal:'<path d="M4 20v-4M10 20v-8M16 20V8M22 20V4"/>',
  box:'<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/>',
  shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  edit:'<path d="M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z"/>'
};
const ic = (n, cls='w-4 h-4') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]}</svg>`;
function hydrateIcons(){
  $$('i[data-icon]').forEach(i => { const t = document.createElement('template'); t.innerHTML = ic(i.dataset.icon, i.getAttribute('class') || 'w-5 h-5'); i.replaceWith(t.content.firstChild); });
}
const langIcon = (lang, cls='w-9 h-9') => lang==='python'
  ? `<svg class="${cls} shrink-0" viewBox="0 0 32 32"><rect x="3" y="3" width="17" height="17" rx="5" fill="#3776AB"/><rect x="12" y="12" width="17" height="17" rx="5" fill="#FFD43B"/><circle cx="9" cy="9" r="1.6" fill="#fff"/><circle cx="23" cy="23" r="1.6" fill="#3776AB"/></svg>`
  : `<svg class="${cls} shrink-0" viewBox="0 0 32 32"><path d="M16 2.5l11.7 6.75v13.5L16 29.5 4.3 22.75V9.25z" fill="#3c873a"/><text x="16" y="20.5" text-anchor="middle" font-size="10" font-weight="800" fill="#fff" font-family="Inter,Arial,sans-serif">JS</text></svg>`;

/* ======================= API ======================= */
async function api(path, body){
  const o = body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)};
  const r = await fetch(path, o);
  if(r.status === 401){ location.href = '/login'; throw new Error('Not signed in'); }
  let j = {}; try{ j = await r.json(); }catch(e){}
  if(!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
async function act(path, body={}){
  try{ const r = await api(path, body); kick(); return r; }
  catch(e){ toast(e.message, 'error'); throw e; }
}

/* ======================= STATE ======================= */
const LANG = { python:{label:'Python', mgr:'pip'}, node:{label:'Node.js', mgr:'npm'} };
const verOpt = (lang, v) => lang==='python' ? `Python ${v}` : `Node ${v}`;
let projects = [], sys = {cpu:0, mem:0, used:0, total:0}, ping = null, pingHist = [], info = {settings:{}}, runtimes = {python:[], node:[], def:{}};
let fetchedAt = Date.now(), lastSig = '', lastStats = '', lastHist = 0, lastTop = '', lastTun = '', fastUntil = 0, evSince = 0, evFirst = true;
let page = 'dashboard', isDesktop = true;
let dashSel = null, dashLive = true, detailId = null, termId = null, delId = null, menuId = null;
let pkgMgr = 'pip', pkgQ = '', pkgBusy = false, pkgData = [], pkgChecked = false, brTarget = null, brState = null;
const filters = { dash:{q:'',status:'all'}, page:{q:'',status:'all',lang:'all',sort:'name'} };
const logsState = { proj:'all', lvl:'all', q:'', live:true, auto:true };
const hist = { total:[], run:[], stop:[], cpu:[], mem:[] };
const get = id => projects.find(p => p.id === id);

/* ======================= SMALL UI PIECES ======================= */
function toast(msg, type='info'){
  const c = {success:'bg-emerald-500', error:'bg-red-500', info:'bg-sky-500'}[type] || 'bg-sky-500';
  const el = document.createElement('div');
  el.className = 'toast pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl bg-slate-900 text-white text-sm shadow-lg border border-slate-700';
  el.innerHTML = `<span class="w-2 h-2 rounded-full ${c} shrink-0"></span><span class="flex-1">${esc(msg)}</span>`;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 280); }, 3000);
}
const notifs = [];
function renderNotifs(){
  const unread = notifs.filter(n => !n.read).length;
  $('#notifBadge').textContent = unread; $('#notifBadge').classList.toggle('hidden', !unread);
  const dot = { error:'bg-red-500', warn:'bg-amber-500', success:'bg-emerald-500', info:'bg-sky-500' };
  $('#notifList').innerHTML = notifs.length ? notifs.slice(0,30).map(n => `<div class="flex gap-3 px-4 py-3 border-b border-slate-100 dark:border-slate-800 ${n.read?'':'bg-emerald-50/60 dark:bg-emerald-500/5'}"><span class="mt-1.5 w-2 h-2 rounded-full shrink-0 ${dot[n.type]||dot.info}"></span><div class="min-w-0"><p class="text-sm">${esc(n.text)}</p><p class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${ago(n.t)}</p></div></div>`).join('')
    : '<p class="p-6 text-center text-sm text-slate-500">No notifications</p>';
}
const ST = {
  running:   { t:'Running',       c:'bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400', d:'bg-emerald-500' },
  stopped:   { t:'Stopped',       c:'bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300',        d:'bg-slate-400' },
  crashed:   { t:'Crashed',       c:'bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400',                 d:'bg-red-500' },
  restarting:{ t:'Restarting...', c:'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400',         d:'bg-amber-500 animate-pulse' },
  installing:{ t:'Installing...', c:'bg-sky-50 text-sky-700 dark:bg-sky-500/10 dark:text-sky-300',                 d:'bg-sky-500 animate-pulse' }
};
const statusBadge = p => { const s = ST[p.status] || ST.stopped; return `<span class="badge ${s.c}"><span class="w-1.5 h-1.5 rounded-full ${s.d}"></span>${s.t}</span>`; };
const typeBadge = p => p.lang==='python'
  ? '<span class="badge bg-blue-50 text-blue-700 dark:bg-blue-500/10 dark:text-blue-300">Python</span>'
  : '<span class="badge bg-green-50 text-green-700 dark:bg-green-500/10 dark:text-green-400">Node.js</span>';
const verLabel = p => p.runtime || p.version || '-';
const upSecs = p => p.status==='running' ? p.uptime + (Date.now()-fetchedAt)/1000 : 0;
function uptimeTxt(p, full){
  if(p.status !== 'running') return '-';
  let s = Math.floor(upSecs(p));
  const d = Math.floor(s/86400); s %= 86400; const h = Math.floor(s/3600); s %= 3600; const m = Math.floor(s/60); s %= 60;
  if(full) return `${d?d+'d ':''}${(h||d)?h+'h ':''}${m}m ${pad(s)}s`;
  if(d) return `${d}d ${h}h ${m}m`;
  if(h) return `${h}h ${m}m ${pad(s)}s`;
  return `${m}m ${pad(s)}s`;
}
const cpuTxt = p => (p.status==='running' ? p.cpu : 0).toFixed(1) + '%';
const ramTxt = p => (p.status==='running' ? p.ram : 0) + ' MB';

/* ======================= PROJECT LIST ======================= */
function visibleProjects(f){
  const q = (f.q||'').toLowerCase();
  const list = projects.filter(p => (f.status==='all' || p.status===f.status) && (!f.lang || f.lang==='all' || p.lang===f.lang) && (!q || (p.name+' '+p.folder).toLowerCase().includes(q)));
  const key = f.sort || 'name', ord = { running:0, restarting:1, installing:1, crashed:2, stopped:3 };
  list.sort((a,b) => key==='cpu' ? b.cpu-a.cpu : key==='ram' ? b.ram-a.ram : key==='status' ? ord[a.status]-ord[b.status] : a.name.localeCompare(b.name));
  return list;
}
function actionBtns(p, labeled, withLogs=true){
  const busy = p.status==='restarting' ? 'disabled' : '';
  const b = (a, icon, bg, label) => `<button data-act="${a}" data-id="${p.id}" title="${label}" ${busy} class="abtn ${bg}">${ic(icon,'w-4 h-4')}${labeled?`<span>${label}</span>`:''}</button>`;
  let h = p.status==='running' || p.status==='restarting'
    ? b('restart','restart','bg-amber-500','Restart') + b('stop','stop','bg-red-500','Stop')
    : p.status==='installing' ? b('stop','stop','bg-red-500','Stop') : b('start','play','bg-emerald-500','Start');
  if(withLogs) h += `<button data-act="termopen" data-id="${p.id}" title="Logs" class="abtn border border-slate-300 dark:border-slate-700 !text-slate-700 dark:!text-slate-200 bg-white dark:bg-slate-900">${ic('terminal','w-4 h-4')}<span>Logs</span></button>`;
  return h;
}
function rowHTML(p, i){
  const td = 'px-4 py-3';
  return `<tr class="border-t border-slate-100 dark:border-slate-800 hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors">
    <td class="${td} hidden 2xl:table-cell text-slate-500">${i+1}</td>
    <td class="${td}"><div class="flex items-center gap-3">${langIcon(p.lang)}<div class="min-w-0">
      <button data-act="detail" data-id="${p.id}" class="block font-semibold text-slate-900 dark:text-white hover:text-emerald-600 dark:hover:text-emerald-400 truncate max-w-[170px] text-left">${esc(p.name)}</button>
      <div class="text-xs text-slate-500 dark:text-slate-400 truncate max-w-[170px]">${esc(p.folder)}</div></div></div></td>
    <td class="${td}">${typeBadge(p)}</td>
    <td class="${td} tabular-nums">${esc(verLabel(p))}</td>
    <td class="${td}">${statusBadge(p)}</td>
    <td class="${td} tabular-nums" data-cpu="${p.id}">${cpuTxt(p)}</td>
    <td class="${td} tabular-nums" data-ram="${p.id}">${ramTxt(p)}</td>
    <td class="${td} tabular-nums whitespace-nowrap" data-uptime="${p.id}">${uptimeTxt(p)}</td>
    <td class="${td}"><div class="flex items-center gap-1.5">${actionBtns(p)}<button data-act="menu" data-id="${p.id}" class="ghost-btn !w-8 !h-8" aria-label="More">${ic('dots','w-4 h-4')}</button></div></td>
  </tr>`;
}
function tableHTML(list){
  const th = 'px-4 py-3 text-left font-semibold';
  return `<div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-slate-50 dark:bg-slate-800/50 text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400"><tr>
    <th class="${th} hidden 2xl:table-cell">#</th><th class="${th}">Project</th><th class="${th}">Type</th><th class="${th}">Version</th><th class="${th}">Status</th><th class="${th}">CPU</th><th class="${th}">RAM</th><th class="${th}">Uptime</th><th class="${th}">Actions</th>
  </tr></thead><tbody>${list.map(rowHTML).join('')}</tbody></table></div>`;
}
function cardHTML(p){
  const tile = (label, val, attr) => `<div class="rounded-lg bg-slate-50 dark:bg-slate-800/50 px-2 py-2 text-center"><div class="text-[10px] uppercase tracking-wide text-slate-500">${label}</div><div class="text-sm font-semibold tabular-nums mt-0.5" ${attr}>${val}</div></div>`;
  return `<div class="border-t border-slate-100 dark:border-slate-800 p-4">
    <div class="flex items-start gap-3">${langIcon(p.lang,'w-10 h-10')}
      <div class="min-w-0 flex-1">
        <button data-act="detail" data-id="${p.id}" class="block font-semibold text-slate-900 dark:text-white hover:text-emerald-600 truncate max-w-full text-left">${esc(p.name)}</button>
        <div class="text-xs text-slate-500 dark:text-slate-400 truncate">${esc(p.folder)}</div>
        <div class="flex flex-wrap gap-1.5 mt-2">${typeBadge(p)}<span class="badge bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">${esc(verLabel(p))}</span>${statusBadge(p)}</div>
      </div>
      <button data-act="menu" data-id="${p.id}" class="ghost-btn !w-8 !h-8 shrink-0" aria-label="More">${ic('dots','w-4 h-4')}</button>
    </div>
    <div class="grid grid-cols-3 gap-2 mt-3">${tile('CPU',cpuTxt(p),`data-cpu="${p.id}"`)}${tile('RAM',ramTxt(p),`data-ram="${p.id}"`)}${tile('Uptime',uptimeTxt(p),`data-uptime="${p.id}"`)}</div>
    <div class="flex flex-wrap gap-2 mt-3">${actionBtns(p,true)}</div>
  </div>`;
}
function emptyState(){
  return `<div class="p-10 text-center border-t border-slate-100 dark:border-slate-800"><div class="w-12 h-12 mx-auto rounded-full bg-slate-100 dark:bg-slate-800 text-slate-400 flex items-center justify-center">${ic('cube','w-6 h-6')}</div><p class="mt-3 font-semibold">No projects found</p><p class="text-sm text-slate-500 mt-1">Add your first Python or Node.js project.</p><button data-act="add" class="btn btn-primary mt-4">${ic('plus')}Add Project</button></div>`;
}
function renderList(el, f){
  const list = visibleProjects(f);
  el.innerHTML = list.length ? (isDesktop ? tableHTML(list) : `<div>${list.map(cardHTML).join('')}</div>`) : emptyState();
}
function renderLists(){
  renderList($('#list-dash'), filters.dash); renderList($('#list-page'), filters.page);
  $('#pageCount').textContent = `${projects.length} projects · ${projects.filter(p => p.status==='running').length} running`;
}

/* ======================= STATS / GAUGES / PING ======================= */
function smooth(vals, w, h, min, max){
  if(vals.length < 2) vals = [vals[0] ?? 0, vals[0] ?? 0];
  min = min ?? Math.min(...vals); max = max ?? Math.max(...vals); const span = (max-min) || 1;
  const pts = vals.map((v,i) => [i/(vals.length-1)*w, h-2-(v-min)/span*(h-4)]);
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for(let i=1;i<pts.length;i++){ const [x0,y0]=pts[i-1], [x1,y1]=pts[i], cx=(x0+x1)/2; d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`; }
  return { line:d, area:d+` L${w},${h} L0,${h} Z` };
}
function spark(id, vals, color){
  const s = smooth(vals, 100, 36, 0);
  return `<svg viewBox="0 0 100 36" preserveAspectRatio="none" class="w-full h-9 block"><defs><linearGradient id="sg-${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".25"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs><path d="${s.area}" fill="url(#sg-${id})"/><path d="${s.line}" fill="none" stroke="${color}" stroke-width="1.6" vector-effect="non-scaling-stroke"/></svg>`;
}
function bars(vals, color){
  const max = Math.max(...vals, 1)*1.1;
  return `<div class="flex items-end gap-1 h-9 px-4">${vals.map(v => `<div class="flex-1 rounded-t" style="height:${Math.max(10,v/max*100)}%;background:${color};opacity:.75"></div>`).join('')}</div>`;
}
function statCard(o){
  return `<div class="card relative overflow-hidden pt-4 ${o.cls||''}">
    <div class="flex items-center gap-3 px-4"><div class="w-11 h-11 rounded-full flex items-center justify-center shrink-0 ${o.iconCls}">${ic(o.icon,'w-5 h-5')}</div>
      <div class="min-w-0"><div class="text-sm text-slate-500 dark:text-slate-400">${o.label}</div><div class="text-xl font-bold tracking-tight tabular-nums leading-tight">${o.value}</div><div class="text-[11px] text-slate-500 dark:text-slate-400 h-4 truncate">${o.sub||''}</div></div></div>
    <div class="mt-1">${o.viz}</div></div>`;
}
function pushHist(a, v){ a.push(v); while(a.length > 24) a.shift(); }
function renderStats(){
  const run = projects.filter(p => p.status==='running').length, crashed = projects.filter(p => p.status==='crashed').length;
  const stopped = projects.filter(p => p.status==='stopped' || p.status==='crashed').length;
  const sh =
    statCard({label:'Total Projects', value:projects.length, icon:'cube', iconCls:'bg-blue-100 text-blue-600 dark:bg-blue-500/15 dark:text-blue-400', viz:spark('t',hist.total,'#3b82f6')}) +
    statCard({label:'Running', value:run, icon:'play', iconCls:'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400', viz:spark('r',hist.run,'#10b981')}) +
    statCard({label:'Stopped', value:stopped, sub:crashed?`<span class="text-red-500 font-medium">${crashed} crashed</span>`:'', icon:'stop', iconCls:'bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-300', viz:spark('s',hist.stop,'#94a3b8')}) +
    statCard({label:'CPU Usage', value:sys.cpu.toFixed(1)+'%', icon:'cpu', iconCls:'bg-purple-100 text-purple-600 dark:bg-purple-500/15 dark:text-purple-400', viz:bars(hist.cpu,'#8b5cf6')}) +
    statCard({label:'Memory Usage', value:sys.mem.toFixed(1)+'%', sub:sys.total?`${(sys.used/1024).toFixed(1)} GB / ${(sys.total/1024).toFixed(1)} GB`:'', icon:'ram', iconCls:'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-400', viz:bars(hist.mem,'#10b981'), cls:'col-span-2 lg:col-span-1'});
  if(sh !== lastStats){ lastStats = sh; $('#statsRow').innerHTML = sh; }
  const C = 301.59;
  $('#gCpuArc').style.strokeDashoffset = C*(1 - clamp(sys.cpu,0,100)/100); $('#gCpuTxt').textContent = sys.cpu.toFixed(1) + '%';
  $('#gMemArc').style.strokeDashoffset = C*(1 - clamp(sys.mem,0,100)/100); $('#gMemTxt').textContent = sys.mem.toFixed(1) + '%';
}
function renderTopUse(){
  const run = projects.filter(p => p.status==='running').sort((a,b) => b.cpu-a.cpu);
  const h = run.length ? run.map(p => {
    const w = clamp(p.cpu, 0, 100), pct = sys.total ? (p.ram/sys.total*100).toFixed(1) : '0.0';
    return `<div><div class="flex items-center justify-between gap-3 text-xs mb-1"><span class="font-semibold truncate">${esc(p.name)}</span><span class="tabular-nums text-slate-500 dark:text-slate-400 shrink-0">CPU ${p.cpu.toFixed(1)}% · RAM ${p.ram} MB (${pct}%)</span></div><div class="h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden"><div class="h-full rounded-full ${w>70?'bg-red-500':w>35?'bg-amber-500':'bg-emerald-500'}" style="width:${Math.max(w,1)}%"></div></div></div>`;
  }).join('') : '<p class="text-xs text-slate-500">No running projects.</p>';
  if(h !== lastTop){ lastTop = h; $('#topUse').innerHTML = h; }
}
function renderTunnel(t){
  const key = JSON.stringify(t); if(key === lastTun) return; lastTun = key;
  const el = $('#tunnelCard');
  const dim = x => `<span class="text-slate-500 dark:text-slate-400">${x}</span>`;
  const bd = (c, txt) => `<span class="badge ${c}">${txt}</span>`;
  const amber = 'bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400';
  let badge, body = '', btns = '';
  if(t.status === 'online'){
    badge = bd('bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400', 'Online');
    body = `<a href="${esc(t.url)}" target="_blank" rel="noopener" class="font-mono text-emerald-700 dark:text-emerald-400 hover:underline">${esc(t.url)}</a><div class="text-xs text-slate-500 dark:text-slate-400 mt-1">Running for <b id="tunUp" data-since="${t.since}" class="tabular-nums"></b></div>`;
    btns = `<div class="flex gap-2"><button data-act="tun-copy" data-url="${esc(t.url)}" class="btn btn-outline !py-1.5">Copy</button><a href="${esc(t.url)}" target="_blank" rel="noopener" class="btn btn-primary !py-1.5">Open</a></div>`;
  } else if(t.status === 'missing'){
    badge = bd('bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300', 'Not installed');
    body = dim('cloudflared was not found. Install it, then it opens by itself. Termux: <b class="font-mono">pkg install cloudflared</b>');
  } else if(t.status === 'installing'){
    badge = bd(amber, 'Installing'); body = dim('Installing cloudflared, please wait...');
  } else if(t.status === 'restarting'){
    badge = bd(amber, 'Reconnecting'); body = dim(esc(t.err || 'Making a new link...'));
  } else { badge = bd(amber, 'Opening...'); body = dim('The link appears here in a few seconds.'); }
  const warn = t.weak ? '<div class="text-xs text-red-600 dark:text-red-400 font-medium mt-1.5">Your password is still 123. Anyone with this link can try it - change it in Settings.</div>' : '';
  el.classList.remove('hidden');
  el.innerHTML = `<div class="card p-4 flex flex-wrap items-center gap-3"><span class="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">${ic('wifi','w-5 h-5')}</span><div class="min-w-0 flex-1"><div class="flex flex-wrap items-center gap-2"><span class="font-bold">Public link</span>${badge}</div><div class="text-sm mt-1 break-all">${body}</div>${warn}</div>${btns}</div>`;
}
function setPing(ms){
  const t = ms == null ? '--' : ms;
  $('#pingTop').textContent = ms == null ? 'Ping: --' : `Ping: ${ms}ms`; $('#sidePing').textContent = ms == null ? 'Ping: --' : `Ping: ${ms} ms`; $('#netMs').textContent = ms == null ? '--' : `${ms} ms`;
  const col = ms == null ? 'bg-slate-400' : ms < 80 ? 'bg-emerald-500' : ms < 200 ? 'bg-amber-500' : 'bg-red-500';
  $('#pingDot').className = `w-2.5 h-2.5 rounded-full ${col}`;
  if(pingHist.length > 1){ const s = smooth(pingHist, 200, 60, 0, Math.max(60, ...pingHist)); $('#pingLine').setAttribute('d', s.line); $('#pingArea').setAttribute('d', s.area); }
}
function renderSelects(){
  const opts = projects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if(!get(dashSel)) dashSel = (projects.find(p => p.status==='running') || projects[0] || {}).id ?? null;
  const ds = $('#dashSelect'); ds.innerHTML = opts || '<option>No projects</option>'; if(dashSel != null) ds.value = dashSel;
  if(logsState.proj !== 'all' && !get(+logsState.proj)) logsState.proj = 'all';
  const lp = $('#lg-proj'); lp.innerHTML = '<option value="all">All projects</option>' + opts; lp.value = logsState.proj;
}

/* ======================= STATE POLLING ======================= */
function applyState(s){
  projects = s.projects; sys = s.sys; fetchedAt = Date.now(); pingHist = s.pingHist; ping = s.ping;
  setPing(ping);
  s.events.forEach(ev => {
    evSince = Math.max(evSince, ev.id);
    const on = {crash:info.settings.notifyCrash, status:info.settings.notifyStatus, pkg:info.settings.notifyPkg}[ev.cat];
    if(on === false) return;
    notifs.unshift({text:ev.text, type:ev.type, t:ev.t*1000, read:evFirst});
    if(!evFirst && ev.type === 'error') toast(ev.text, 'error');
  });
  evFirst = false; renderNotifs();
  if(Date.now() - lastHist > 1900){
    lastHist = Date.now();
    pushHist(hist.total, projects.length); pushHist(hist.run, projects.filter(p => p.status==='running').length);
    pushHist(hist.stop, projects.filter(p => p.status!=='running' && p.status!=='restarting').length); pushHist(hist.cpu, sys.cpu); pushHist(hist.mem, sys.mem);
  }
  const sig = JSON.stringify(projects.map(p => [p.id,p.name,p.status,p.runtime,p.folder,p.entry,p.pid,p.lang,p.port]));
  renderStats(); renderTopUse(); if(s.tunnel) renderTunnel(s.tunnel);
  if(sig !== lastSig){
    lastSig = sig; renderLists(); renderDetail(); renderTermHead(); renderSelects();
    if(page === 'packages') renderPkgPills();
  } else updateMetricCells();
}
function updateMetricCells(){
  $$('[data-cpu]').forEach(e => { const p = get(+e.dataset.cpu); if(p) e.textContent = cpuTxt(p); });
  $$('[data-ram]').forEach(e => { const p = get(+e.dataset.ram); if(p) e.textContent = ramTxt(p); });
}
function tunTick(){
  const e = document.getElementById('tunUp'); if(!e) return;
  let s = Math.max(0, Math.floor(Date.now()/1000 - +e.dataset.since)); const d = Math.floor(s/86400); s %= 86400; const h = Math.floor(s/3600); s %= 3600; const m = Math.floor(s/60);
  e.textContent = `${d?d+'d ':''}${(h||d)?h+'h ':''}${m}m ${pad(s%60)}s`;
}
function updateLive(){ tunTick(); $$('[data-uptime]').forEach(e => { const p = get(+e.dataset.uptime); if(p) e.textContent = uptimeTxt(p, e.dataset.full==='1'); }); }
let polling = false;
async function poll(){
  if(polling) return; polling = true;
  try{ applyState(await api('/api/state?ev=' + evSince)); }
  catch(e){ if(e.message !== 'Not signed in'){ $('#pingTop').textContent = 'Server offline'; $('#pingDot').className = 'w-2.5 h-2.5 rounded-full bg-red-500'; } }
  finally{ polling = false; }
}
function kick(){ fastUntil = Date.now() + 5000; poll(); }
(function loop(){ poll().finally(() => setTimeout(loop, (Date.now() < fastUntil || projects.some(p => p.status==='restarting')) ? 600 : 2000)); })();

/* ======================= LOG VIEWS (real output, polled) ======================= */
function lvlOf(e){
  if(e.k === 'sys') return 'SYS';
  const m = e.m;
  if(/\b(error|exception|traceback|fatal|critical)\b/i.test(m)) return 'ERROR';
  if(/\bwarn(ing)?\b/i.test(m)) return 'WARN';
  if(/\bdebug\b/i.test(m)) return 'DEBUG';
  return 'INFO';
}
const LCOL = { ERROR:'text-red-400', WARN:'text-amber-400', DEBUG:'text-slate-500', INFO:'text-slate-200', SYS:'text-sky-400' };
function lineHTML(e, showName){
  const l = lvlOf(e), nm = (get(e.p) || {}).name || ('#' + e.p);
  return `<div class="whitespace-pre-wrap break-words">${showName?`<span class="text-emerald-400">${esc(nm)}</span> `:''}${l==='SYS'?'<span class="text-sky-400 font-semibold">[kratompm]</span> ':''}<span class="${LCOL[l]}">${esc(e.m)}</span></div>`;
}
const views = {
  term:   { el:'#termBody',   proj:() => termId,   auto:true, name:false, active:() => termId != null },
  detail: { el:'#detailTerm', proj:() => detailId, auto:true, name:false, active:() => detailId != null },
  dash:   { el:'#dashTerm',   proj:() => dashSel,  auto:true, name:false, active:() => page==='dashboard' && dashLive },
  logs:   { el:'#logsTerm',   proj:() => logsState.proj, auto:true, name:true, active:() => page==='logs' && logsState.live, filter:true }
};
function resetView(k){ views[k].key = null; }
function viewKeep(v, e){ if(!v.filter) return true; const s = logsState, q = s.q.toLowerCase(); return (s.lvl==='all' || lvlOf(e)===s.lvl) && (!q || (e.m+' '+((get(e.p)||{}).name||'')).toLowerCase().includes(q)); }
async function pullView(k){
  const v = views[k]; if(!v.active() || v.busy) return;
  const proj = v.proj(); if(proj == null) return;
  const el = $(v.el), key = String(proj) + (v.filter ? logsState.lvl + '|' + logsState.q : '');
  if(v.key !== key){ v.key = key; v.after = 0; el.innerHTML = ''; }
  v.busy = true;
  try{
    const r = await api(`/api/logs?proj=${proj}&after=${v.after}&limit=${v.after ? 500 : (v.filter ? 500 : 300)}`);
    if(v.key !== key) return;
    const lines = r.lines.filter(e => viewKeep(v, e));
    if(lines.length){
      const f = el.firstElementChild; if(f && f.dataset.empty !== undefined) f.remove();
      el.insertAdjacentHTML('beforeend', lines.map(e => lineHTML(e, v.name)).join(''));
      while(el.childElementCount > 500) el.firstElementChild.remove();
      if(v.auto) el.scrollTop = el.scrollHeight;
    } else if(!el.childElementCount) el.innerHTML = '<div data-empty class="text-slate-600">No log output yet...</div>';
    v.after = r.next;
    if(k === 'logs') $('#lgCount').textContent = el.querySelectorAll(':scope > div:not([data-empty])').length + ' lines';
  }catch(e){} finally{ v.busy = false; }
}
setInterval(() => Object.keys(views).forEach(pullView), 1200);
function clearView(k){ const el = $(views[k].el); if(el) el.innerHTML = '<div data-empty class="text-slate-600">No log output yet...</div>'; }
async function downloadLogs(proj, name){
  try{ const r = await api(`/api/logs?proj=${proj}&after=0&limit=5000`); download(`${name}-logs.txt`, r.lines.map(e => `[${clock(e.t*1000)}] ${proj==='all'?((get(e.p)||{}).name||e.p)+': ':''}${e.k==='sys'?'[kratompm] ':''}${e.m}`).join('\n') || '(no logs)'); toast('Logs downloaded','success'); }
  catch(e){ toast(e.message,'error'); }
}
const chipCls = on => on ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' : 'bg-slate-800 text-slate-400 border-slate-700';
function setChip(btn, on){ btn.className = `px-2 py-1 rounded-md text-[11px] font-semibold border ${chipCls(on)}`; btn.textContent = `Auto-scroll: ${on?'ON':'OFF'}`; }

/* ======================= MODALS ======================= */
function openModal(id){
  const m = $('#'+id); m.classList.remove('opacity-0','pointer-events-none');
  m.querySelector('.modal-panel').classList.remove('scale-95','translate-y-2'); document.body.classList.add('overflow-hidden');
}
function closeModal(id){
  const m = $('#'+id); m.classList.add('opacity-0','pointer-events-none');
  m.querySelector('.modal-panel').classList.add('scale-95','translate-y-2');
  if(id==='modal-detail') detailId = null;
  if(id==='modal-term') termId = null;
  if(id==='modal-form'){ const t = $('#f-term'); t._tok = (t._tok||0)+1; }
  if(!$$('[data-modal]').some(x => !x.classList.contains('pointer-events-none'))) document.body.classList.remove('overflow-hidden');
}

/* --- terminal popup (Logs button) --- */
function openTerm(id){
  if(!get(id)) return;
  termId = id; views.term.auto = true; resetView('term'); renderTermHead(); setChip($('[data-autobtn="term"]'), true);
  openModal('modal-term'); pullView('term');
}
function renderTermHead(){
  const p = get(termId); if(!p) return;
  $('#termHead').innerHTML = `<div class="flex items-center gap-3 min-w-0">${langIcon(p.lang,'w-8 h-8')}<div class="min-w-0"><div class="font-bold truncate">${esc(p.name)}</div><div class="text-xs text-slate-500 dark:text-slate-400 font-mono truncate">${esc(p.folder)}</div></div>${statusBadge(p)}</div>
    <div class="flex items-center gap-2 shrink-0">${actionBtns(p,false,false)}<button data-act="close-modal" class="ghost-btn" aria-label="Close">${ic('x','w-5 h-5')}</button></div>`;
}

/* --- project detail + settings --- */
function openDetail(id){
  const p = get(id); if(!p) return;
  detailId = id; views.detail.auto = true; resetView('detail'); renderDetail(); renderDetailForm(); setChip($('[data-autobtn="detail"]'), true);
  openModal('modal-detail'); pullView('detail');
}
function renderDetail(){
  if(detailId == null) return;
  const p = get(detailId); if(!p){ closeModal('modal-detail'); return; }
  $('#detailHead').innerHTML = `<div class="flex items-center gap-3 min-w-0">${langIcon(p.lang,'w-11 h-11')}<div class="min-w-0"><h3 class="text-lg font-bold truncate">${esc(p.name)}</h3><div class="mt-1 flex flex-wrap gap-1.5">${typeBadge(p)}${statusBadge(p)}</div></div></div><button data-act="close-modal" class="ghost-btn shrink-0" aria-label="Close">${ic('x','w-5 h-5')}</button>`;
  const tile = (l, v) => `<div class="rounded-xl bg-slate-50 dark:bg-slate-800/50 p-3"><div class="text-[11px] uppercase tracking-wide text-slate-500 dark:text-slate-400">${l}</div><div class="mt-1 text-sm font-semibold break-all tabular-nums">${v}</div></div>`;
  $('#detailInfo').innerHTML = tile('Status', ST[p.status].t) + tile('PID', p.pid ?? '-') +
    tile('CPU', `<span data-cpu="${p.id}">${cpuTxt(p)}</span>`) + tile('RAM', `<span data-ram="${p.id}">${ramTxt(p)}</span>`) +
    tile('Uptime', `<span data-uptime="${p.id}" data-full="1">${uptimeTxt(p,true)}</span>`);
  const busy = (p.status==='restarting'||p.status==='installing') ? 'disabled' : '', run = p.status==='running'||p.status==='installing';
  $('#detailActions').innerHTML =
    (run ? `<button data-act="stop" data-id="${p.id}" ${p.status==='restarting'?'disabled':''} class="btn btn-danger">${ic('stop')}Stop</button>` : `<button data-act="start" data-id="${p.id}" ${busy} class="btn btn-success">${ic('play')}Start</button>`) +
    `<button data-act="restart" data-id="${p.id}" ${busy} class="btn btn-warn">${ic('restart',p.status==='restarting'?'w-4 h-4 spin':'w-4 h-4')}Restart</button>
     <span class="flex-1"></span><button data-act="delete" data-id="${p.id}" class="btn btn-danger-outline">${ic('trash')}Delete</button>`;
}
function versionOptions(lang, cur){
  const list = (runtimes[lang] || []).map(r => ({v:r.v, label:`${verOpt(lang,r.v)}${r.full?' ('+r.full+')':''}`}));
  if(cur && !list.some(x => x.v === cur)) list.push({v:cur, label:`${verOpt(lang,cur)} (not found)`});
  if(!list.length) list.push({v:'', label:'Default'});
  const sel = cur || (runtimes.def || {})[lang] || list[list.length-1].v;
  return list.map(x => `<option value="${esc(x.v)}" ${x.v===sel?'selected':''}>${esc(x.label)}</option>`).join('');
}
function renderDetailForm(){
  const p = get(detailId); if(!p) return;
  $('#d-name').value = p.name; $('#d-lang').value = p.lang; $('#d-ver').innerHTML = versionOptions(p.lang, p.version);
  $('#d-folder').value = p.folder; $('#d-entry').value = p.entry; $('#d-port').value = p.port ?? '';
  $('#d-err').classList.add('hidden');
}
async function saveDetail(){
  const err = m => { const e = $('#d-err'); e.textContent = m; e.classList.remove('hidden'); };
  const body = { name:$('#d-name').value, lang:$('#d-lang').value, version:$('#d-ver').value, folder:$('#d-folder').value, entry:$('#d-entry').value, port:$('#d-port').value };
  try{ await api(`/api/project/${detailId}/update`, body); $('#d-err').classList.add('hidden'); toast('Settings saved','success'); kick(); }
  catch(e){ err(e.message); }
}

/* --- add project --- */
function openForm(){
  $('#f-name').value = ''; $('#f-lang').value = info.settings.defLang || 'python'; $('#f-ver').innerHTML = versionOptions($('#f-lang').value);
  zipDir = ''; $('#f-folder').value = ''; $('#f-entry').value = ''; $('#f-port').value = ''; $('#f-entry').placeholder = $('#f-lang').value==='python' ? 'main.py' : 'index.js';
  $('#f-install').checked = false; $('#f-installBtn').disabled = true;
  const t = $('#f-term'); t.classList.add('hidden'); t.innerHTML = ''; $('#f-err').classList.add('hidden');
  openModal('modal-form'); setTimeout(() => $('#f-name').focus(), 80);
}
let zipDir = '';
async function saveForm(){
  try{                                  // uploaded folder: name it like the project title
    const nm = $('#f-name').value.trim(), fo = $('#f-folder').value.trim();
    if(zipDir && fo === zipDir && nm){ const r = await api('/api/fs', {op:'rename', path:fo, name:nm}); $('#f-folder').value = zipDir = r.path; }
  }catch(e){ const el = $('#f-err'); el.textContent = e.message; el.classList.remove('hidden'); return; }
  const body = { name:$('#f-name').value, lang:$('#f-lang').value, version:$('#f-ver').value, folder:$('#f-folder').value, entry:$('#f-entry').value, port:$('#f-port').value };
  try{ await api('/api/project', body); closeModal('modal-form'); toast(`${body.name.trim()} added`,'success'); kick(); }
  catch(e){ const el = $('#f-err'); el.textContent = e.message; el.classList.remove('hidden'); }
}
async function uploadZip(file){
  if(!/\.(zip|py|m?js|cjs)$/i.test(file.name)){ toast('Choose a ZIP, .py or .js file','error'); $('#f-zip').value = ''; return; }
  const btn = $('#f-zipBtn'), err = $('#f-err'); err.classList.add('hidden');
  const name = $('#f-name').value.trim() || file.name.replace(/\.(zip|py|m?js|cjs)$/i, '');
  btn.disabled = true; btn.textContent = 'Uploading...';
  try{
    const r = await fetch('/api/upload?name=' + encodeURIComponent(name) + '&file=' + encodeURIComponent(file.name), {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:file});
    if(r.status === 401){ location.href = '/login'; return; }
    const j = await r.json().catch(() => ({}));
    if(!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    $('#f-folder').value = zipDir = j.folder; $('#f-entry').value = j.entry;
    if(!$('#f-name').value.trim()) $('#f-name').value = j.name;
    if($('#f-lang').value !== j.lang){ $('#f-lang').value = j.lang; $('#f-lang').dispatchEvent(new Event('change')); }
    closeModal('modal-browse'); toast(j.entry ? 'Uploaded' : 'Uploaded - choose the entry file', 'success');
  }catch(e){ err.textContent = e.message; err.classList.remove('hidden'); }
  finally{ btn.disabled = false; btn.innerHTML = ic('box','w-4 h-4') + 'Upload from this device (ZIP or .py / .js file)'; $('#f-zip').value = ''; }
}
function shellLine(s){
  let c = 'text-slate-300';
  if(s.startsWith('$')) c = 'text-emerald-400'; else if(/^(Successfully|added|up to date|Requirement already)/.test(s)) c = 'text-sky-300';
  else if(/WARN/.test(s)) c = 'text-amber-300'; else if(/ERROR/i.test(s)) c = 'text-red-400';
  return `<div class="${c} whitespace-pre-wrap break-words">${esc(s)}</div>`;
}
function followJob(jid, el, onDone){
  const tok = el._tok = (el._tok||0) + 1; let after = 0;
  const tick = async () => {
    if(el._tok !== tok) return;
    try{
      const r = await api(`/api/job?id=${jid}&after=${after}`);
      if(el._tok !== tok) return;
      if(r.lines.length){ el.insertAdjacentHTML('beforeend', r.lines.map(shellLine).join('')); el.scrollTop = el.scrollHeight; }
      after = r.next;
      if(r.done){ onDone && onDone(r.code); return; }
    }catch(e){ onDone && onDone(-1); return; }
    setTimeout(tick, 500);
  };
  tick();
}
async function runInstall(){
  const t = $('#f-term'), btn = $('#f-installBtn');
  t.classList.remove('hidden'); t.innerHTML = ''; btn.disabled = true;
  try{
    const r = await api('/api/pkg/run', { op:'requirements', lang:$('#f-lang').value, version:$('#f-ver').value, folder:$('#f-folder').value });
    followJob(r.job, t, code => { btn.disabled = !$('#f-install').checked; toast(code===0 ? 'Dependencies installed' : 'Install failed', code===0 ? 'success' : 'error'); });
  }catch(e){ t.innerHTML = shellLine('ERROR: ' + e.message); btn.disabled = !$('#f-install').checked; }
}

/* --- folder browser --- */
async function openBrowse(t){
  brTarget = t; await loadBrowse($('#' + t + '-folder').value.trim()); openModal('modal-browse');
}
let brMode = '';
const brPill = (label, attrs, on) => `<button ${attrs} class="px-2.5 py-1 rounded-full text-xs font-semibold border transition ${on?'bg-emerald-600 border-emerald-600 text-white':'border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800'}">${label}</button>`;
async function loadBrowse(path){
  try{ brState = await api('/api/browse?path=' + encodeURIComponent(path || '')); brMode = ''; $('#brPath').value = brState.path; renderBrowse(); }
  catch(e){ toast(e.message,'error'); }
}
function renderBrowse(){
  const dev = brMode === 'dev';
  $('#brPlaces').innerHTML = brState.places.map((x,i) => brPill(esc(x.n), `data-act="br-go" data-path="${esc(x.p)}"`, !dev && (i===0 ? brState.kpm : !brState.kpm))).join('') +
    (brTarget === 'f' ? brPill('My device', 'data-act="br-dev"', dev) : '');
  $('#brPath').parentElement.classList.toggle('hidden', dev);
  $('[data-act="br-select"]').classList.toggle('hidden', dev);
  if(dev){
    $('#brList').innerHTML = `<button data-act="zip" class="w-full flex flex-col items-center justify-center gap-1.5 rounded-xl border border-dashed border-slate-300 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition py-8 px-4 text-center">${ic('up','w-6 h-6 text-emerald-600')}<span class="text-sm font-semibold">Upload from your device</span><span class="text-[11px] text-slate-500">ZIP, .py or .js</span></button>`;
    return;
  }
  const edit = brState.kpm, sep = brState.path.includes('\\') ? '\\' : '/', full = n => brState.path.replace(/[\\/]$/, '') + sep + n;
  const row = (btn, p) => edit ? `<div class="flex items-center gap-1">${btn}<button data-act="br-ren" data-path="${esc(p)}" class="ghost-btn !w-8 !h-8 shrink-0" title="Rename">${ic('edit','w-4 h-4')}</button><button data-act="br-del" data-path="${esc(p)}" class="ghost-btn !w-8 !h-8 shrink-0 text-red-500" title="Delete">${ic('trash','w-4 h-4')}</button></div>` : btn;
  const mi = edit ? 'menu-item flex-1 min-w-0' : 'menu-item';
  const list = (brState.parent ? `<button data-act="br-go" data-path="${esc(brState.parent)}" class="menu-item">${ic('up','w-4 h-4')}.. (parent folder)</button>` : '') +
    brState.dirs.map(d => row(`<button data-act="br-go" data-path="${esc(d.p)}" class="${mi}">${ic('folder','w-4 h-4 text-amber-500 shrink-0')}<span class="truncate">${esc(d.n)}</span></button>`, d.p)).join('') +
    (brState.files.length ? `<div class="px-3 pt-3 pb-1 text-[11px] uppercase tracking-wide text-slate-500">Tap a script to use it</div>` + brState.files.map(f => row(`<button data-act="br-file" data-name="${esc(f)}" class="${mi}">${ic('file','w-4 h-4 text-sky-500 shrink-0')}<span class="font-mono text-xs truncate">${esc(f)}</span></button>`, full(f))).join('') : '');
  $('#brList').innerHTML = (brState.note ? `<p class="p-3 text-sm text-amber-600 dark:text-amber-400">${esc(brState.note)}</p>` : '') + (list || '<p class="p-4 text-sm text-slate-500">No sub-folders</p>');
}
function brFile(name){
  const t = brTarget; if(!t || !brState) return;
  $('#' + t + '-folder').value = brState.path; $('#' + t + '-entry').value = name;
  const lang = /\.(m?js|cjs)$/.test(name) ? 'node' : 'python', sel = $('#' + t + '-lang');
  if(sel.value !== lang){ sel.value = lang; sel.dispatchEvent(new Event('change')); }
  closeModal('modal-browse');
}
function brSelect(){
  const t = brTarget; if(!t || !brState) return;
  $('#' + t + '-folder').value = brState.path;
  const entry = $('#' + t + '-entry'), lang = $('#' + t + '-lang').value;
  const want = lang==='python' ? ['main.py','app.py','server.py','bot.py','run.py'] : ['index.js','server.js','app.js','main.js'];
  const hit = want.find(w => brState.files.includes(w)) || brState.files.find(f => lang==='python' ? f.endsWith('.py') : !f.endsWith('.py'));
  if(hit && (t==='f' ? !entry.value.trim() : !brState.files.includes(entry.value.trim()))) entry.value = hit;
  closeModal('modal-browse');
}

/* --- delete --- */
function openDelete(id){ const p = get(id); if(!p) return; delId = id; $('#delName').textContent = p.name; openModal('modal-delete'); }
async function confirmDelete(){
  const p = get(delId); closeModal('modal-delete'); if(!p) return;
  if(detailId === p.id) closeModal('modal-detail'); if(termId === p.id) closeModal('modal-term');
  try{ await act(`/api/project/${p.id}/delete`); toast(`${p.name} deleted`,'info'); }catch(e){}
}

/* ======================= PAGE: PACKAGES ======================= */
let pkgRev = 0, pkgChecking = false, pkgAt = 0, pkgErr = null;
function renderPkgPills(){
  const t = (m, label, icon) => `<button data-act="pkgsel" data-mgr="${m}" class="shrink-0 flex items-center gap-2 px-3.5 py-2 rounded-full text-sm font-medium border transition ${m===pkgMgr?'bg-emerald-600 border-emerald-600 text-white':'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800'}">${langIcon(icon,'w-4 h-4')}${label}</button>`;
  $('#pkgPills').innerHTML = t('pip','Python (pip)','python') + t('npm','Node.js (npm)','node');
}
async function loadPkgs(check){
  const m = pkgMgr;
  try{
    const r = await api(`/api/pkg/list?mgr=${m}&rev=${pkgRev}${check?'&outdated=1':''}`);
    if(m !== pkgMgr || r.same) return;
    if(r.loading){ if(!pkgData.length) $('#pkgTable').innerHTML = '<p class="p-8 text-center text-sm text-slate-500">Reading packages...</p>'; return; }
    pkgRev = r.rev; pkgData = r.packages; pkgChecked = r.checked > 0; pkgAt = r.checked; pkgChecking = r.checking; pkgErr = r.err;
    renderPkgTable();
  }catch(e){}
}
setInterval(() => { if(page === 'packages' && !document.hidden) loadPkgs(); }, 2000);
function renderPkgTable(){
  const q = pkgQ.toLowerCase(), out = pkgData.filter(k => k.latest && k.latest !== k.ver).length;
  $('#pkgMeta').textContent = `${pkgMgr} (global) · ${pkgData.length} packages` + (pkgChecked ? ` · ${out} outdated · checked ${ago(pkgAt*1000)}` : '') + (pkgChecking ? ' · checking for updates...' : '');
  if(pkgErr && !pkgData.length){ $('#pkgTable').innerHTML = `<p class="p-8 text-center text-sm text-red-500 break-words">${esc(pkgErr)}</p>`; return; }
  const rows = pkgData.filter(k => !q || k.name.toLowerCase().includes(q)).map(k => {
    const old = k.latest && k.latest !== k.ver;
    return `<tr class="border-t border-slate-100 dark:border-slate-800"><td class="px-4 py-3 font-semibold">${esc(k.name)}</td><td class="px-4 py-3 tabular-nums">${esc(k.ver)}</td>
      <td class="px-4 py-3">${old?`<span class="badge bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-400">${esc(k.latest)} available</span>`:pkgChecked?'<span class="badge bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-400">Up to date</span>':'<span class="text-slate-400">-</span>'}</td>
      <td class="px-4 py-3"><div class="flex justify-end gap-1.5">${old?`<button data-act="pkgupdate" data-name="${esc(k.name)}" class="btn btn-outline !py-1 !px-2.5 !text-xs">Update</button>`:''}<button data-act="pkguninstall" data-name="${esc(k.name)}" class="btn btn-danger-outline !py-1 !px-2.5 !text-xs">${ic('trash','w-3.5 h-3.5')}</button></div></td></tr>`;
  }).join('');
  $('#pkgTable').innerHTML = `<table class="w-full text-sm"><thead class="bg-slate-50 dark:bg-slate-800/50 text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400"><tr><th class="px-4 py-3 text-left font-semibold">Package</th><th class="px-4 py-3 text-left font-semibold">Version</th><th class="px-4 py-3 text-left font-semibold">Latest</th><th class="px-4 py-3"></th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="p-8 text-center text-slate-500">No packages.</td></tr>'}</tbody></table>`;
}
async function pkgRun(body){
  if(pkgBusy) return toast('Another package task is still running','info');
  pkgBusy = true; const t = $('#pkgTerm'), st = $('#pkgState'); t.innerHTML = ''; st.textContent = '· running...';
  t.scrollIntoView({behavior:'smooth', block:'center'});
  try{
    const r = await api('/api/pkg/run', Object.assign({mgr:pkgMgr}, body));
    followJob(r.job, t, code => { pkgBusy = false; st.textContent = code===0 ? '· finished' : '· failed'; toast(code===0 ? 'Done' : 'Task failed', code===0 ? 'success' : 'error'); });
  }catch(e){ pkgBusy = false; st.textContent = '· failed'; toast(e.message,'error'); }
}

/* ======================= PAGE: LOGS ======================= */
function setToggleLabels(){
  $('#lgLiveTxt').textContent = logsState.live ? 'Live' : 'Paused';
  $('#lgLiveDot').className = `w-2 h-2 rounded-full ${logsState.live?'bg-emerald-500 animate-pulse':'bg-slate-400'}`;
  $('#lgAutoBtn').textContent = `Auto-scroll: ${logsState.auto?'ON':'OFF'}`;
}

/* ======================= PAGE: SETTINGS + ABOUT ======================= */
const sw = (id,on) => `<label class="relative inline-flex items-center cursor-pointer shrink-0"><input id="${id}" type="checkbox" class="peer sr-only" ${on?'checked':''}><span class="w-11 h-6 rounded-full bg-slate-300 dark:bg-slate-700 peer-checked:bg-emerald-600 transition-colors"></span><span class="absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform peer-checked:translate-x-5"></span></label>`;
function renderSettings(){
  const S = info.settings;
  const trow = (id,t,d,on) => `<div class="flex items-center justify-between gap-4 py-3"><div><div class="text-sm font-medium">${t}</div><div class="text-xs text-slate-500 dark:text-slate-400">${d}</div></div>${sw(id,on)}</div>`;
  const sec = (icon,title,body) => `<div class="card p-5"><h2 class="flex items-center gap-2.5 font-bold text-lg mb-4"><span class="text-emerald-600">${ic(icon,'w-5 h-5')}</span>${title}</h2>${body}</div>`;
  const opt = (v,l,cur) => `<option value="${v}" ${String(cur)===String(v)?'selected':''}>${l}</option>`;
  const div = 'divide-y divide-slate-100 dark:divide-slate-800';
  $('#settingsBody').innerHTML = `<div class="grid lg:grid-cols-2 gap-5">
    ${sec('server' in ICONS ? 'server' : 'monitor','Server',`<div class="grid sm:grid-cols-2 gap-4"><div><label class="label">Host</label><input id="s-host" class="input" value="${esc(S.host)}"></div><div><label class="label">Port</label><input id="s-port" type="number" class="input" value="${S.port}"></div></div><p class="text-xs text-slate-500 mt-2">Currently running on <b>${esc(info.host)}:${info.port}</b>. Host and port changes apply after KratomPM is restarted. Use 0.0.0.0 only behind a reverse proxy with HTTPS.</p><div class="mt-4"><label class="label">Default language for new projects</label><select id="s-lang" class="input">${opt('python','Python',S.defLang)}${opt('node','Node.js',S.defLang)}</select></div>`)}
    ${sec('sun','Appearance',`<div class="${div}">${trow('s-dark','Dark mode','Switch the whole dashboard to a dark theme',document.documentElement.classList.contains('dark'))}</div>`)}
    ${sec('restart','Process control',`<label class="label">Memory limit per project (MB)</label><input id="s-mem" type="number" min="0" class="input" value="${S.maxMem}"><p class="text-xs text-slate-500 mt-2">0 means no limit. A project that goes over the limit is restarted. Crashed projects are never restarted automatically.</p>`)}
    ${sec('bell','Notifications',`<div class="${div}">${trow('s-ncrash','Crash alerts','Notify when a project crashes',S.notifyCrash)}${trow('s-nstatus','Status changes','Notify on start, stop and restart',S.notifyStatus)}${trow('s-npkg','Package tasks','Notify when package installs finish',S.notifyPkg)}</div>`)}
    ${sec('file','Logs',`<label class="label">Lines kept in memory per project</label><select id="s-ret" class="input">${opt(200,'200',S.retention)}${opt(500,'500',S.retention)}${opt(1000,'1000',S.retention)}${opt(3000,'3000',S.retention)}</select>`)}
    ${sec('shield','Security',`<label class="label">New password</label><input id="s-pw" type="password" autocomplete="new-password" class="input" placeholder="Leave empty to keep the current password"><p class="text-xs text-slate-500 mt-2">At least 6 characters.</p>`)}
    ${sec('box','Data',`<p class="text-sm text-slate-500 dark:text-slate-400 mb-4">Download your settings and project list as JSON.</p><a href="/api/export" class="btn btn-outline">${ic('download')}Export config</a>`)}
  </div>`;
  $('#s-dark').addEventListener('change', e => setTheme(e.target.checked));
}
async function saveSettings(){
  const body = { host:$('#s-host').value, port:$('#s-port').value, defLang:$('#s-lang').value, maxMem:$('#s-mem').value,
    notifyCrash:$('#s-ncrash').checked, notifyStatus:$('#s-nstatus').checked, notifyPkg:$('#s-npkg').checked, retention:$('#s-ret').value, password:$('#s-pw').value };
  try{ info = await api('/api/settings', body); $('#s-pw').value = ''; toast('Settings saved','success'); }
  catch(e){ toast(e.message,'error'); }
}
async function renderAbout(){
  try{ info = await api('/api/info'); }catch(e){}
  const feat = [['activity','Live monitoring','Real CPU, RAM, uptime and internet ping.'],['terminal','Real terminals','Live output of every process, in a popup.'],['restart','Process control','Start, stop and restart one project or all of them.'],['grid','Package manager','Run pip and npm for each project.'],['download','Auto-install','Installs missing pip / npm packages when a project needs them.'],['shield','Password login','Only you can control your processes.']];
  const row = (k,v) => `<div class="flex justify-between gap-4 py-2.5 text-sm"><span class="text-slate-500 dark:text-slate-400">${k}</span><span class="font-medium text-right break-all">${esc(v)}</span></div>`;
  $('#aboutBody').innerHTML = `<div class="grid lg:grid-cols-3 gap-5">
    <div class="card p-6 lg:col-span-3 flex flex-wrap items-center gap-5">
      <span class="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-green-700 text-white flex items-center justify-center shadow-lg text-3xl font-extrabold">K</span>
      <div class="flex-1 min-w-[220px]"><h2 class="text-xl font-extrabold tracking-tight"><span class="text-emerald-600">Kratom</span><span class="text-amber-500">PM</span> <span class="ml-1 align-middle badge bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300">v${esc(info.version)}</span></h2>
      <p class="text-sm text-slate-500 dark:text-slate-400 mt-1">A PM2-style process manager for Python and Node.js projects, written in a single Python file.</p></div>
    </div>
    <div class="card p-5 lg:col-span-2"><h3 class="font-bold text-lg mb-4">Features</h3><div class="grid sm:grid-cols-2 gap-4">${feat.map(([i,t,d]) => `<div class="flex gap-3"><span class="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0">${ic(i,'w-5 h-5')}</span><div><div class="font-semibold text-sm">${t}</div><div class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${d}</div></div></div>`).join('')}</div></div>
    <div class="card p-5"><h3 class="font-bold text-lg mb-2">System information</h3><div class="divide-y divide-slate-100 dark:divide-slate-800">
      ${row('Operating system',info.os)}${row('Python',info.python)}${row('Node.js',info.node)}${row('Address',info.host+':'+info.port)}${row('Projects',projects.length)}${row('Metrics from',info.psutil?'psutil':'system files')}<div class="flex justify-between gap-4 py-2.5 text-sm"><span class="text-slate-500 dark:text-slate-400">KratomPM uptime</span><span id="aboutUp" class="font-medium tabular-nums"></span></div></div></div>
  </div>`;
  tickAbout();
}
function tickAbout(){
  const u = $('#aboutUp'); if(!u || !info.uptime) return;
  let s = info.uptime + Math.floor((Date.now()-aboutAt)/1000); const d = Math.floor(s/86400); s %= 86400; const h = Math.floor(s/3600); s %= 3600; const m = Math.floor(s/60);
  u.textContent = `${d?d+'d ':''}${h}h ${m}m ${pad(s%60)}s`;
}
let aboutAt = Date.now();

/* ======================= PAGE: SYSTEM ======================= */
let lastSys = '';
const GB = v => (v/1073741824).toFixed(2) + ' GB';
async function renderSystem(){
  if(page !== 'system') return;
  try{
    const d = await api('/api/device');
    const row = (k,v) => `<div class="flex justify-between gap-4 py-2.5 text-sm"><span class="text-slate-500 dark:text-slate-400">${k}</span><span class="font-medium text-right break-all">${esc(v)}</span></div>`;
    const bar = (label, pct, text, color) => `<div><div class="flex justify-between gap-3 text-sm mb-1.5"><span class="font-medium">${label}</span><span class="tabular-nums text-slate-500 dark:text-slate-400">${text}</span></div><div class="h-2 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden"><div class="h-full rounded-full ${color}" style="width:${clamp(pct,0,100).toFixed(1)}%"></div></div></div>`;
    const ramT = d.ramTotal/1024, ramU = d.ramUsed/1024, stPct = d.stTotal ? d.stUsed/d.stTotal*100 : 0;
    const html = `<div class="grid lg:grid-cols-2 gap-5">
      <div class="card p-5 min-w-0"><h2 class="font-bold text-lg mb-2">Device information</h2><div class="divide-y divide-slate-100 dark:divide-slate-800">
        ${row(d.android?'Android':'OS', d.os)}${row('Brand', d.brand)}${row(d.android?'Model':'Model / Host', d.model)}${row('Device', d.device)}${row('CPU ABI', d.abi)}${row('Kernel', d.kernel)}${row('CPU cores', d.cores)}${row('Python', d.python)}${row('Node.js', d.node)}</div></div>
      <div class="card p-5 min-w-0"><h2 class="font-bold text-lg mb-4">Live resources</h2><div class="space-y-5">
        ${bar('CPU usage', d.cpu, d.cpu.toFixed(1)+'%'+(d.cpuPartial?' (our processes only)':''), 'bg-blue-500')}
        ${bar('RAM', d.ramPct, `${ramU.toFixed(2)} / ${ramT.toFixed(2)} GB (${d.ramPct.toFixed(1)}%) · free ${(ramT-ramU).toFixed(2)} GB`, 'bg-emerald-500')}
        ${bar('Storage ' + esc(d.stPath), stPct, `${GB(d.stUsed)} / ${GB(d.stTotal)} (${stPct.toFixed(1)}%) · free ${GB(d.stFree)}`, stPct>90?'bg-red-500':'bg-purple-500')}
      </div></div></div>`;
    if(html !== lastSys){ lastSys = html; $('#sysBody').innerHTML = html; }
  }catch(e){}
}
setInterval(renderSystem, 3000);

/* ======================= THEME / NAV ======================= */
function setTheme(dark){
  document.documentElement.classList.toggle('dark', dark);
  try{ localStorage.setItem('kpm-theme', dark ? 'dark' : 'light'); }catch(e){}
  $('#themeBtn').innerHTML = ic(dark ? 'sun' : 'moon', 'w-5 h-5');
  const s = $('#s-dark'); if(s) s.checked = dark;
}
const PAGES = ['dashboard','projects','packages','logs','system','settings','about'];
function showPage(name){
  if(!PAGES.includes(name)) name = 'dashboard'; page = name;
  $$('[data-page]').forEach(s => s.classList.toggle('hidden', s.dataset.page !== name));
  $$('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === name));
  if(name==='packages'){ renderPkgPills(); pkgRev = 0; loadPkgs(); }
  if(name==='logs'){ resetView('logs'); setToggleLabels(); pullView('logs'); }
  if(name==='dashboard'){ resetView('dash'); pullView('dash'); }
  if(name==='about'){ aboutAt = Date.now(); renderAbout(); }
  if(name==='settings') renderSettings();
  if(name==='system'){ lastSys = ''; renderSystem(); }
  toggleSidebar(false); window.scrollTo(0,0);
}
function toggleSidebar(force){
  const open = force ?? $('#sidebar').classList.contains('-translate-x-full');
  $('#sidebar').classList.toggle('-translate-x-full', !open);
  $('#overlay').classList.toggle('opacity-0', !open); $('#overlay').classList.toggle('pointer-events-none', !open);
}
function closeDropdowns(){ $$('#notifMenu,#adminMenu').forEach(m => m.classList.add('hidden')); }
function hideMenu(){ $('#floatMenu').classList.add('hidden'); }
function openMenu(btn, id){
  const m = $('#floatMenu'); if(!m.classList.contains('hidden') && menuId===id){ hideMenu(); return; }
  menuId = id; $$('[data-act]', m).forEach(b => b.dataset.id = id); m.classList.remove('hidden');
  const r = btn.getBoundingClientRect(), w = 176, h = m.offsetHeight || 90;
  m.style.left = clamp(r.right - w, 8, window.innerWidth - w - 8) + 'px';
  m.style.top = (r.bottom + h + 12 > window.innerHeight ? r.top - h - 6 : r.bottom + 6) + 'px';
}

/* ======================= EVENTS ======================= */
document.addEventListener('click', async e => {
  const t = e.target;
  if(!t.closest('#floatMenu') && !t.closest('[data-act="menu"]')) hideMenu();
  if(!t.closest('.dd')) closeDropdowns();
  const el = t.closest('[data-act]'); if(!el) return;
  const a = el.dataset.act, id = el.dataset.id ? +el.dataset.id : null;
  try{
  switch(a){
    case 'menu-toggle': toggleSidebar(); break;
    case 'theme': setTheme(!document.documentElement.classList.contains('dark')); break;
    case 'dd': { const m = $('#'+el.dataset.target); const was = m.classList.contains('hidden'); closeDropdowns(); m.classList.toggle('hidden', !was); break; }
    case 'notif-read': notifs.forEach(n => n.read = true); renderNotifs(); break;
    case 'notif-clear': notifs.length = 0; renderNotifs(); break;
    case 'logout': await api('/api/logout', {}); location.href = '/login'; break;
    case 'add': openForm(); break;
    case 'restartall': await act('/api/all/restart'); toast('Restarting all projects...','info'); break;
    case 'stopall': await act('/api/all/stop'); toast('Stopping all projects...','info'); break;
    case 'start': await act(`/api/project/${id}/start`); break;
    case 'stop': await act(`/api/project/${id}/stop`); break;
    case 'restart': await act(`/api/project/${id}/restart`); break;
    case 'termopen': openTerm(id); break;
    case 'term-auto': views.term.auto = !views.term.auto; setChip(el, views.term.auto); if(views.term.auto){ const x = $('#termBody'); x.scrollTop = x.scrollHeight; } break;
    case 'term-clear': await act(`/api/project/${termId}/clear`); clearView('term'); break;
    case 'term-dl': downloadLogs(termId, get(termId).name); break;
    case 'menu': openMenu(el, id); break;
    case 'detail': hideMenu(); openDetail(id); break;
    case 'delete': hideMenu(); openDelete(id); break;
    case 'confirm-delete': await confirmDelete(); break;
    case 'close-modal': closeModal(el.closest('[data-modal]').id); break;
    case 'detail-auto': views.detail.auto = !views.detail.auto; setChip(el, views.detail.auto); if(views.detail.auto){ const x = $('#detailTerm'); x.scrollTop = x.scrollHeight; } break;
    case 'detail-clear': await act(`/api/project/${detailId}/clear`); clearView('detail'); break;
    case 'detail-reset': renderDetailForm(); toast('Changes reverted','info'); break;
    case 'browse': openBrowse(el.dataset.t); break;
    case 'zip': $('#f-zip').click(); break;
    case 'tun-copy': { const u = el.dataset.url; let ok = false;
      try{ await navigator.clipboard.writeText(u); ok = true; }catch(x){}
      if(!ok){ const ta = document.createElement('textarea'); ta.value = u; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0'; document.body.appendChild(ta); ta.focus(); ta.select(); try{ ok = document.execCommand('copy'); }catch(x){} ta.remove(); }
      toast(ok ? 'Link copied' : 'Could not copy, select the link and copy it by hand', ok ? 'success' : 'error'); break; }
    case 'br-go': loadBrowse(el.dataset.path); break;
    case 'br-dev': brMode = 'dev'; renderBrowse(); break;
    case 'br-ren': { const old = el.dataset.path.split(/[\\/]/).pop(), nn = prompt('New name', old);
      if(nn && nn.trim() && nn.trim() !== old){ await api('/api/fs', {op:'rename', path:el.dataset.path, name:nn}); toast('Renamed','success'); loadBrowse(brState.path); } break; }
    case 'br-del': { const nm = el.dataset.path.split(/[\\/]/).pop();
      if(confirm('Delete "' + nm + '" and everything inside it?')){ await api('/api/fs', {op:'delete', path:el.dataset.path}); toast('Deleted','success'); loadBrowse(brState.path); } break; }
    case 'br-select': brSelect(); break;
    case 'br-file': brFile(el.dataset.name); break;
    case 'install': runInstall(); break;
    case 'dash-live': dashLive = !dashLive; $('#dashLiveTxt').textContent = dashLive ? 'Live Logs' : 'Paused'; $('#dashLiveDot').className = `w-2 h-2 rounded-full ${dashLive?'bg-emerald-500 animate-pulse':'bg-slate-500'}`; break;
    case 'dash-clear': if(dashSel!=null){ await act(`/api/project/${dashSel}/clear`); clearView('dash'); } break;
    case 'dash-dl': if(dashSel!=null) downloadLogs(dashSel, get(dashSel).name); break;
    case 'pkgsel': pkgMgr = el.dataset.mgr; pkgData = []; pkgRev = 0; $('#pkgTable').innerHTML = ''; renderPkgPills(); loadPkgs(); break;
    case 'pkgcheck': loadPkgs(true); break;
    case 'pkginstall': { const n = $('#pkgInput').value.trim(); if(!n) return toast('Enter a package name','error'); await pkgRun({op:'install', name:n}); $('#pkgInput').value = ''; break; }
    case 'pkgupdateall': { const names = pkgData.filter(k => k.latest && k.latest !== k.ver).map(k => k.name); if(!names.length) return toast(pkgChecked ? 'Everything is up to date' : 'Press "Check updates" first','info'); pkgRun({op:'updateall', names}); break; }
    case 'pkgupdate': pkgRun({op:'update', name:el.dataset.name}); break;
    case 'pkguninstall': pkgRun({op:'uninstall', name:el.dataset.name}); break;
    case 'pkgclear': $('#pkgTerm').innerHTML = ''; break;
    case 'lg-live': logsState.live = !logsState.live; setToggleLabels(); break;
    case 'lg-auto': logsState.auto = !logsState.auto; views.logs.auto = logsState.auto; setToggleLabels(); break;
    case 'lg-clear': if(logsState.proj==='all'){ for(const p of projects) await api(`/api/project/${p.id}/clear`, {}); } else await api(`/api/project/${logsState.proj}/clear`, {}); clearView('logs'); $('#lgCount').textContent = '0 lines'; toast('Logs cleared','info'); break;
    case 'lg-dl': downloadLogs(logsState.proj, logsState.proj==='all' ? 'all-projects' : get(+logsState.proj).name); break;
    case 'save-settings': await saveSettings(); break;
  }
  }catch(err){ if(err && err.message && err.message !== 'Not signed in') toast(err.message,'error'); }
});
document.addEventListener('keydown', e => {
  if(e.key !== 'Escape') return;
  const open = $$('[data-modal]').filter(m => !m.classList.contains('pointer-events-none')).pop();
  if(open) closeModal(open.id); else { hideMenu(); closeDropdowns(); toggleSidebar(false); }
});
window.addEventListener('hashchange', () => showPage(location.hash.slice(1)));
window.addEventListener('resize', hideMenu);
$('#fDashQ').addEventListener('input', e => { filters.dash.q = e.target.value; renderList($('#list-dash'), filters.dash); });
$('#fDashStatus').addEventListener('change', e => { filters.dash.status = e.target.value; renderList($('#list-dash'), filters.dash); });
$('#fPageQ').addEventListener('input', e => { filters.page.q = e.target.value; renderList($('#list-page'), filters.page); });
$('#fPageStatus').addEventListener('change', e => { filters.page.status = e.target.value; renderList($('#list-page'), filters.page); });
$('#fPageLang').addEventListener('change', e => { filters.page.lang = e.target.value; renderList($('#list-page'), filters.page); });
$('#fPageSort').addEventListener('change', e => { filters.page.sort = e.target.value; renderList($('#list-page'), filters.page); });
$('#dashSelect').addEventListener('change', e => { dashSel = +e.target.value; resetView('dash'); pullView('dash'); });
$('#lg-proj').addEventListener('change', e => { logsState.proj = e.target.value; pullView('logs'); });
$('#lg-lvl').addEventListener('change', e => { logsState.lvl = e.target.value; pullView('logs'); });
$('#lg-q').addEventListener('input', e => { logsState.q = e.target.value; pullView('logs'); });
$('#brPath').addEventListener('keydown', e => { if(e.key==='Enter') loadBrowse(e.target.value.trim()); });
$('#pkgQ').addEventListener('input', e => { pkgQ = e.target.value; renderPkgTable(); });
$('#pkgInput').addEventListener('keydown', e => { if(e.key==='Enter') $('[data-act="pkginstall"]').click(); });
$('#f-lang').addEventListener('change', () => { $('#f-ver').innerHTML = versionOptions($('#f-lang').value); $('#f-entry').placeholder = $('#f-lang').value==='python' ? 'main.py' : 'index.js'; });
$('#d-lang').addEventListener('change', () => { $('#d-ver').innerHTML = versionOptions($('#d-lang').value); });
$('#f-zip').addEventListener('change', e => { if(e.target.files[0]) uploadZip(e.target.files[0]); });
$('#f-install').addEventListener('change', e => { $('#f-installBtn').disabled = !e.target.checked; });
$('#projForm').addEventListener('submit', e => { e.preventDefault(); saveForm(); });
$('#detailForm').addEventListener('submit', e => { e.preventDefault(); saveDetail(); });
const mq = window.matchMedia('(min-width:1280px)');
isDesktop = mq.matches; mq.addEventListener('change', () => { isDesktop = mq.matches; renderLists(); });
setInterval(() => { updateLive(); tickAbout(); if($('#notifMenu').classList.contains('hidden')) renderNotifs(); }, 1000);

/* ======================= INIT ======================= */
hydrateIcons();
setTheme(document.documentElement.classList.contains('dark'));
renderNotifs(); renderStats();
(async () => {
  try{
    info = await api('/api/info'); runtimes = await api('/api/runtimes');
    $('#pillHost').textContent = `${info.host}:${info.port}`; $('#sideHost').textContent = `${info.host}:${info.port}`;
  }catch(e){}
  showPage(location.hash.slice(1));
})();
</script>
</body>
</html>
'''


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------
def main():
    load()
    first_pw = None
    if not DATA['pw']:
        first_pw = '123'
        set_pw(first_pw)
    else:
        WEAK[0] = check_pw('123')
    save()

    s = DATA['settings']
    srv = None
    for port in range(int(s['port']), int(s['port']) + 20):
        try:
            srv = Server((s['host'], port), Handler)
            break
        except OSError:
            continue
    if not srv:
        print('Could not open a port starting at %s. Change it in kratompm_data.json.' % s['port'])
        return
    ACTUAL['host'], ACTUAL['port'] = s['host'], srv.server_address[1]

    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=pinger, daemon=True).start()
    for m in PKG:
        threading.Thread(target=pkg_watch, args=(m,), daemon=True).start()
    threading.Thread(target=tunnel_loop, daemon=True).start()
    threading.Thread(target=tunnel_watch, daemon=True).start()

    def resume():                       # start projects that were running last time
        for p in list(PROJECTS.values()):
            if p.cfg.get('run'):
                start_project(p, user=False)
                time.sleep(0.3)
    bg(resume)

    shown = '127.0.0.1' if s['host'] in ('0.0.0.0', '') else s['host']
    url = 'http://%s:%d' % (shown, ACTUAL['port'])
    print('\n  KratomPM %s is running' % VERSION)
    print('  Open:      %s' % url)
    if first_pw:
        print('  Password:  %s   (default - change it in Settings)' % first_pw)
    print('  Press Ctrl+C to stop KratomPM (managed projects are stopped too and resume next start)\n')
    if WIN or sys.platform == 'darwin' or os.environ.get('DISPLAY'):
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def on_term(*a):
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGTERM, on_term)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        print('\n  Stopping projects...')
        if TUN['proc']:
            kill_tree(TUN['proc'], True)
        shutdown_all()
        save()


if __name__ == '__main__':
    main()
