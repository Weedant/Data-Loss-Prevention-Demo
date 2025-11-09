# main.py -- Mini DLP agent + Flask dashboard with whitelist & policy modes
import re
import os
import threading
import time
import json
import shutil
import csv
from io import StringIO
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, render_template_string, jsonify, redirect, url_for, Response, make_response

try:
    from pystray import Icon, Menu, MenuItem
    from PIL import Image, ImageDraw

    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("[WARN] pystray not installed. System tray icon disabled. Install with: pip install pystray pillow")

# ========== Config ==========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# original watch folder (ingress / monitored folder)
WATCH_FOLDER = r"C:\Users\VEDANT\Desktop\Data_Exfiltration\watch"
# add your USB drive here (D:\ as requested)
USB_DRIVE = r"D:\\"

# IMPORTANT: Enable USB monitoring only if you're sure D:\ is your USB drive
# and not a system partition. Check in File Explorer first!
ENABLE_USB_MONITORING = True  # Set to True to enable USB monitoring

# Build watch paths based on config
WATCH_PATHS = [WATCH_FOLDER]
if ENABLE_USB_MONITORING and os.path.exists(USB_DRIVE):
    WATCH_PATHS.append(USB_DRIVE)
    print(f"[CONFIG] USB monitoring ENABLED for: {USB_DRIVE}")
else:
    print(f"[CONFIG] USB monitoring DISABLED (set ENABLE_USB_MONITORING=True to enable)")

QUARANTINE_FOLDER = os.path.join(BASE_DIR, "quarantine")
STATE_FILE = os.path.join(BASE_DIR, "dlp_state.json")
TEMP_TEST_FOLDER = os.path.join(BASE_DIR, "temp_test_files")  # Ignore test file generation folder

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
for p in WATCH_PATHS:
    try:
        if not os.path.exists(p):
            os.makedirs(p, exist_ok=True)
    except Exception as e:
        # if path is a root drive (like D:\) os.makedirs will raise; ignore
        print(f"[WARN] Cannot create {p}: {e}")

PATTERNS = {
    "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Confidential": r"\b(confidential|secret|restricted)\b"
}

# Default state
default_state = {
    "policy_mode": "block",  # "block" or "warn"
    "whitelist": [],  # list of file paths or directory paths
    "alerts": [],  # stored alerts (most recent first)
    "last_scan_time": None  # timestamp of last manual scan
}

# Thread lock for state access
state_lock = threading.Lock()

# Global for system tray icon
tray_icon = None


# ========== Load / Save state ==========
def load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Could not load state: {e}")
    return default_state.copy()


def save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"[WARN] Could not save state: {e}")


state = load_state()


# Helper to add alert (keeps newest at front)
def add_alert(entry):
    with state_lock:
        state_alerts = state.get("alerts", [])
        state_alerts.insert(0, entry)
        # keep only recent 200 alerts
        state["alerts"] = state_alerts[:200]
        save_state(state)

    # Show system tray notification
    show_tray_notification(entry)


# ========== Processed cache & helpers ==========
_processed_cache = {}  # path -> last_handled_time (float)
_cache_lock = threading.Lock()
PROCESSED_TTL = 10.0  # increased to 10 seconds to handle slower operations


def _is_recently_processed(path):
    with _cache_lock:
        now = time.time()
        abs_path = os.path.abspath(path).lower()  # normalize case for Windows
        last = _processed_cache.get(abs_path)
        if last and (now - last) < PROCESSED_TTL:
            return True
        # garbage collect old keys occasionally
        for p, t in list(_processed_cache.items()):
            if now - t > PROCESSED_TTL * 5:
                _processed_cache.pop(p, None)
        return False


def _mark_processed(path):
    with _cache_lock:
        _processed_cache[os.path.abspath(path).lower()] = time.time()


def _is_quarantine_path(path):
    try:
        abs_path = os.path.abspath(path)
        abs_quar = os.path.abspath(QUARANTINE_FOLDER)
        common = os.path.commonpath([abs_path, abs_quar])
        return common == abs_quar
    except Exception:
        return False


def _is_temp_test_path(path):
    """Check if file is in the temp test folder (should be ignored)"""
    try:
        abs_path = os.path.abspath(path)
        abs_temp = os.path.abspath(TEMP_TEST_FOLDER)
        if os.path.exists(abs_temp):
            common = os.path.commonpath([abs_path, abs_temp])
            return common == abs_temp
    except Exception:
        pass
    return False


def _looks_like_quarantine_name(path):
    return re.match(r"^\d+_", os.path.basename(path)) is not None


def get_file_size(filepath):
    """Get file size in human-readable format"""
    try:
        size = os.path.getsize(filepath)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except:
        return "N/A"


# ========== Detection ==========
def is_whitelisted(filepath):
    # ignore anything inside quarantine folder explicitly
    if _is_quarantine_path(filepath):
        return True

    with state_lock:
        whitelist = state.get("whitelist", [])

    # check if filepath or its parent directories are whitelisted
    for w in whitelist:
        try:
            abs_w = os.path.abspath(w)
            abs_f = os.path.abspath(filepath)
            # Check if file is under whitelisted directory
            common = os.path.commonpath([abs_w, abs_f])
            if common == abs_w:
                return True
        except Exception:
            continue
    return False


def wait_for_file_stable(path, timeout=8.0, poll=0.5):
    """Wait until file size is stable or timeout. Returns True if stable."""
    start = time.time()
    try:
        last_size = -1
        stable_count = 0
        while time.time() - start <= timeout:
            if not os.path.exists(path):
                time.sleep(poll)
                continue
            try:
                # Try to open file exclusively to check if it's still being written
                with open(path, 'rb') as f:
                    size = os.path.getsize(path)
                    if size == last_size and size > 0:
                        stable_count += 1
                        if stable_count >= 3:  # Need 3 consecutive stable reads
                            return True
                    else:
                        stable_count = 0
                    last_size = size
            except (OSError, PermissionError) as e:
                # File might be locked, wait a bit more
                print(f"[DEBUG] File locked, waiting: {path} ({e})")
                stable_count = 0
            time.sleep(poll)
    except Exception as e:
        print(f"[DEBUG] wait_for_file_stable error: {e}")
        return False
    return last_size > 0  # Return True if we at least saw some content


def contains_sensitive_data(filepath):
    # ensure we don't scan quarantined files, temp test files, or files we just handled
    if _is_quarantine_path(filepath) or _is_temp_test_path(filepath) or _looks_like_quarantine_name(filepath):
        return None

    # Check if file exists
    if not os.path.exists(filepath):
        return None

    # wait for copy to complete (helps avoid partial reads & duplicate events)
    print(f"[DEBUG] Waiting for file to stabilize: {filepath}")
    if not wait_for_file_stable(filepath, timeout=8.0):
        print(f"[WARN] File did not stabilize, attempting to scan anyway: {filepath}")

    try:
        # Check file size first
        file_size = os.path.getsize(filepath)
        print(f"[DEBUG] Scanning file ({file_size} bytes): {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5 * 1024 * 1024)  # Read max 5MB to handle larger files
            print(f"[DEBUG] Read {len(content)} characters from {filepath}")

            for label, pat in PATTERNS.items():
                matches = re.findall(pat, content, re.IGNORECASE)
                if matches:
                    print(f"[DEBUG] Found {len(matches)} match(es) for {label} in {filepath}")
                    print(f"[DEBUG] First match: {matches[0][:50]}")
                    return label

            print(f"[DEBUG] No sensitive patterns found in {filepath}")
    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}")
        return None
    return None


class DLPHandler(FileSystemEventHandler):
    def __init__(self, watch_path):
        super().__init__()
        self.watch_path = watch_path
        print(f"[DEBUG] DLPHandler initialized for: {watch_path}")

    def on_created(self, event):
        if event.is_directory:
            return
        print(f"[DEBUG] on_created event: {event.src_path}")
        self._handle_file(event.src_path)

    def on_modified(self, event):
        # Handle modifications too (for when files are written in place)
        if event.is_directory:
            return
        print(f"[DEBUG] on_modified event: {event.src_path}")
        self._handle_file(event.src_path)

    def on_moved(self, event):
        # handle move events similarly (src->dest)
        if event.is_directory:
            return
        print(f"[DEBUG] on_moved event: {event.src_path} -> {event.dest_path}")

        # Mark source as processed to avoid duplicate handling
        _mark_processed(event.src_path)

        # Only handle the destination
        self._handle_file(event.dest_path)

    def _handle_file(self, path):
        print(f"[DEBUG] _handle_file called for: {path}")

        # CRITICAL SAFETY CHECK: Only process files within our watched directories
        abs_path = os.path.abspath(path).lower()
        is_in_watched_dir = False

        for watch_path in WATCH_PATHS:
            try:
                abs_watch = os.path.abspath(watch_path).lower()
                common = os.path.commonpath([abs_watch, abs_path])
                if common == abs_watch:
                    is_in_watched_dir = True
                    break
            except Exception:
                continue

        if not is_in_watched_dir:
            print(f"[CRITICAL] File outside watched directories, IGNORING: {path}")
            return

        # ignore temp test folder
        if _is_temp_test_path(path):
            print(f"[DEBUG] Ignoring temp test folder: {path}")
            return

        # ignore anything in quarantine folder
        if _is_quarantine_path(path):
            print(f"[DEBUG] Ignoring quarantine path: {path}")
            return

        # drop events we already processed recently
        if _is_recently_processed(path):
            print(f"[DEBUG] Already processed recently: {path}")
            return

        # short delay to allow writes
        time.sleep(0.5)

        # Check if file still exists (might have been quickly deleted/moved)
        if not os.path.exists(path):
            print(f"[DEBUG] File no longer exists: {path}")
            _mark_processed(path)  # Mark as processed to avoid re-checking
            return

        if is_whitelisted(path):
            print(f"[INFO] Whitelisted path, ignoring: {path}")
            _mark_processed(path)
            return

        # also skip if the filename looks like quarantine output (prevents loop)
        if _looks_like_quarantine_name(path):
            print(f"[DEBUG] Skipping quarantine-named file: {path}")
            _mark_processed(path)
            return

        print(f"[DEBUG] Starting sensitive data scan for: {path}")
        rule = contains_sensitive_data(path)
        if rule:
            # mark it as processed early to avoid duplicate handling
            _mark_processed(path)

            fname = os.path.basename(path)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # include origin info (which watched path likely triggered this)
            origin = _identify_origin(path)
            file_size = get_file_size(path)

            with state_lock:
                policy_mode = state.get("policy_mode", "block")

            alert = {
                "file": path,
                "rule": rule,
                "time": ts,
                "status": policy_mode,
                "origin": origin,
                "original_path": path,  # Store original path before quarantine
                "file_size": file_size
            }
            add_alert(alert)
            print(f"[ALERT] {path} matched {rule} (policy: {policy_mode}) origin:{origin}")

            if policy_mode == "block":
                # move to quarantine
                try:
                    dest = os.path.join(QUARANTINE_FOLDER, f"{int(time.time())}_{fname}")
                    shutil.move(path, dest)
                    print(f"[ACTION] Moved to quarantine: {dest}")
                    # update last alert file path to quarantine location
                    with state_lock:
                        if state["alerts"]:
                            state["alerts"][0]["file"] = dest
                        save_state(state)
                    # mark quarantined file processed so future events are ignored
                    _mark_processed(dest)
                except Exception as e:
                    print(f"[ERROR] Could not quarantine file: {e}")
            else:
                # warn mode: leave file but mark alert
                print("[ACTION] Warn mode - file left in place")
        else:
            print(f"[DEBUG] No sensitive data detected in: {path}")


# utility: try to give a hint whether event came from watch folder or USB
def _identify_origin(path):
    try:
        path_abs = os.path.abspath(path).lower()
        for p in WATCH_PATHS:
            try:
                abs_p = os.path.abspath(p).lower()
                common = os.path.commonpath([abs_p, path_abs])
                if common == abs_p:
                    return p
            except Exception:
                continue
    except Exception:
        pass
    return "unknown"


# ========== Watcher thread ==========
def start_watcher_for_path(path):
    if not os.path.exists(path):
        print(f"[ERROR] Cannot watch non-existent path: {path}")
        return

    # SAFETY CHECK: Ensure we're only watching approved directories
    abs_path = os.path.abspath(path)
    print(f"[SAFETY] Verifying watch path: {abs_path}")

    # Verify path is in our approved list
    approved = False
    for approved_path in [WATCH_FOLDER, USB_DRIVE]:
        try:
            if abs_path.lower() == os.path.abspath(approved_path).lower():
                approved = True
                break
        except:
            pass

    if not approved:
        print(f"[CRITICAL] Refusing to watch unauthorized path: {abs_path}")
        return

    handler = DLPHandler(path)
    observer = Observer()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print(f"[INFO] ✓ Actively watching: {path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


# ========== System Tray Icon ==========
def create_tray_image():
    """Create a simple icon for system tray"""
    image = Image.new('RGB', (64, 64), color='white')
    draw = ImageDraw.Draw(image)
    # Draw a shield
    draw.rectangle([10, 10, 54, 54], fill='blue', outline='darkblue')
    draw.text((20, 22), "DLP", fill='white')
    return image


def show_tray_notification(alert):
    """Show system tray notification"""
    global tray_icon
    if tray_icon and TRAY_AVAILABLE:
        try:
            title = f"🚨 DLP Alert: {alert['rule']}"
            message = f"File: {os.path.basename(alert['file'])}\nAction: {alert['status']}"
            tray_icon.notify(title, message)
        except Exception as e:
            print(f"[WARN] Could not show tray notification: {e}")


def on_tray_quit(icon, item):
    """Quit from system tray"""
    icon.stop()
    os._exit(0)


def on_tray_open_dashboard(icon, item):
    """Open dashboard in browser"""
    import webbrowser
    webbrowser.open('http://127.0.0.1:5000')


def start_system_tray():
    """Start system tray icon"""
    global tray_icon
    if not TRAY_AVAILABLE:
        return

    try:
        icon_image = create_tray_image()
        menu = Menu(
            MenuItem('Open Dashboard', on_tray_open_dashboard),
            MenuItem('Quit', on_tray_quit)
        )
        tray_icon = Icon("DLP Agent", icon_image, "DLP Agent Running", menu)
        tray_icon.run()
    except Exception as e:
        print(f"[WARN] Could not start system tray: {e}")


# ========== Flask dashboard ==========
app = Flask(__name__)
TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mini DLP Dashboard</title>
  <style>
    body{font-family:Arial;margin:20px;background:#f5f5f5}
    .container{background:white;padding:20px;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{padding:8px;border:1px solid #ccc;text-align:left;font-size:0.9em}
    th{background:#333;color:#fff;position:sticky;top:0}
    tr:nth-child(even){background:#f8f8f8}
    .small{font-size:0.9em;color:#555}
    .btn{padding:6px 10px;border:none;border-radius:4px;cursor:pointer;margin:2px;font-size:0.85em}
    .btn-allow{background:#4CAF50;color:white}
    .btn-delete{background:#f44336;color:white}
    .btn-scan{background:#2196F3;color:white;padding:8px 16px;font-size:14px}
    .btn-export{background:#FF9800;color:white;padding:8px 16px;font-size:14px}
    .btn-bulk{background:#9C27B0;color:white;padding:8px 16px;font-size:14px}
    .policy-block{color:#f44336;font-weight:bold}
    .policy-warn{color:#ff9800;font-weight:bold}
    input[type="text"]{padding:6px;border:1px solid #ccc;border-radius:4px}
    .status-box{background:#e3f2fd;padding:10px;border-radius:4px;margin:10px 0;border-left:4px solid #2196F3}
    .debug-info{background:#fff3cd;padding:10px;border-radius:4px;margin:10px 0;font-family:monospace;font-size:12px}
    .search-box{margin:15px 0;padding:10px;background:#f5f5f5;border-radius:4px}
    .search-box input{width:300px;padding:8px;margin-right:10px}
    .bulk-actions{background:#f3e5f5;padding:10px;border-radius:4px;margin:10px 0;display:none}
    .bulk-actions.show{display:block}
    .checkbox-cell{width:30px;text-align:center}
    .stats{display:flex;gap:20px;margin:15px 0}
    .stat-card{flex:1;padding:15px;background:#f5f5f5;border-radius:4px;text-align:center}
    .stat-value{font-size:24px;font-weight:bold;color:#2196F3}
    .stat-label{font-size:12px;color:#666;margin-top:5px}
  </style>
  <script>
    let selectedAlerts = new Set();

    function scanExisting() {
      if(confirm('This will scan all existing files in watched folders. Continue?')) {
        fetch('/scan_existing', {method: 'POST'})
          .then(r => r.json())
          .then(data => {
            alert('Scan complete! Found ' + data.scanned + ' files, ' + data.detected + ' with sensitive data.');
            location.reload();
          })
          .catch(e => alert('Error: ' + e));
      }
    }

    function exportToCSV() {
      window.location.href = '/export_alerts';
    }

    function filterAlerts() {
      const query = document.getElementById('searchBox').value.toLowerCase();
      const rows = document.querySelectorAll('#alertsTable tbody tr');

      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
      });
    }

    function toggleSelection(checkbox, file) {
      if (checkbox.checked) {
        selectedAlerts.add(file);
      } else {
        selectedAlerts.delete(file);
      }
      updateBulkActions();
    }

    function selectAll(checkbox) {
      const checkboxes = document.querySelectorAll('.alert-checkbox');
      checkboxes.forEach(cb => {
        cb.checked = checkbox.checked;
        toggleSelection(cb, cb.dataset.file);
      });
    }

    function updateBulkActions() {
      const bulkDiv = document.getElementById('bulkActions');
      const count = document.getElementById('selectedCount');
      count.textContent = selectedAlerts.size;
      bulkDiv.className = selectedAlerts.size > 0 ? 'bulk-actions show' : 'bulk-actions';
    }

    function bulkAllow() {
      if (selectedAlerts.size === 0) return;
      if (!confirm(`Allow ${selectedAlerts.size} selected file(s)?`)) return;

      const files = Array.from(selectedAlerts);
      fetch('/bulk_allow', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({files: files})
      })
      .then(r => r.json())
      .then(data => {
        alert(`Processed ${data.success} file(s)`);
        location.reload();
      });
    }

    function bulkDismiss() {
      if (selectedAlerts.size === 0) return;
      if (!confirm(`Dismiss ${selectedAlerts.size} selected alert(s)?`)) return;

      const files = Array.from(selectedAlerts);
      fetch('/bulk_dismiss', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({files: files})
      })
      .then(r => r.json())
      .then(data => {
        alert(`Dismissed ${data.success} alert(s)`);
        location.reload();
      });
    }

    // Auto-refresh alerts every 10 seconds
    setInterval(() => {
      fetch('/alerts')
        .then(r => r.json())
        .then(data => {
          const count = data.length;
          document.title = count > 0 ? '(' + count + ') Mini DLP Dashboard' : 'Mini DLP Dashboard';
        });
    }, 10000);

    // Play sound on new alert (optional)
    let lastAlertCount = {{ alerts|length }};
    setInterval(() => {
      fetch('/alerts')
        .then(r => r.json())
        .then(data => {
          if (data.length > lastAlertCount) {
            playAlertSound();
          }
          lastAlertCount = data.length;
        });
    }, 5000);

    function playAlertSound() {
      // Create a simple beep sound using Web Audio API
      try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);

        oscillator.frequency.value = 800;
        oscillator.type = 'sine';

        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);

        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.5);
      } catch(e) {
        console.log('Could not play alert sound');
      }
    }
  </script>
</head>
<body>
  <div class="container">
    <h1>🛡️ Mini DLP Dashboard</h1>

    <div class="status-box">
      <strong>Status:</strong> Active monitoring enabled<br>
      <strong>Policy Mode:</strong> <span class="policy-{{ policy }}">{{ policy.upper() }}</span> — 
      <a href="{{ url_for('toggle_policy') }}">[Toggle to {{ 'WARN' if policy == 'block' else 'BLOCK' }}]</a><br>
      <strong>Watched Paths:</strong> {{ watch_paths|join(', ') }}<br>
      <strong>Last Manual Scan:</strong> {{ last_scan if last_scan else 'Never' }}<br>
      <div style="margin-top:8px;font-size:0.9em;color:#666">
        {% if policy == 'block' %}
          🚫 <strong>BLOCK mode:</strong> Files with sensitive data are quarantined immediately.
        {% else %}
          ⚠️ <strong>WARN mode:</strong> Files with sensitive data trigger alerts but remain in place.
        {% endif %}
      </div>
    </div>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-value">{{ alerts|length }}</div>
        <div class="stat-label">Total Alerts</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ whitelist|length }}</div>
        <div class="stat-label">Whitelisted Paths</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ watch_paths|length }}</div>
        <div class="stat-label">Monitored Locations</div>
      </div>
    </div>

    <button class="btn btn-scan" onclick="scanExisting()">🔍 Scan Existing Files</button>
    <button class="btn btn-export" onclick="exportToCSV()">📥 Export to CSV</button>

    <h3>Whitelist Management</h3>
    <form method="post" action="{{ url_for('add_whitelist') }}">
      <input type="text" name="path" style="width:70%" placeholder="Path to whitelist (file or folder)" required/>
      <button type="submit" class="btn btn-allow">Add to Whitelist</button>
    </form>
    <ul>
    {% if whitelist %}
      {% for w in whitelist %}
        <li class="small">{{ w }} <a href="{{ url_for('remove_whitelist') }}?path={{ w|urlencode }}">[remove]</a></li>
      {% endfor %}
    {% else %}
      <li class="small"><em>No whitelisted paths</em></li>
    {% endif %}
    </ul>

    <h3>Security Alerts — Total: {{ alerts|length }}</h3>

    {% if alerts %}
    <div class="search-box">
      <input type="text" id="searchBox" placeholder="Search alerts (file name, rule, origin...)" onkeyup="filterAlerts()">
      <span class="small">💡 Type to filter alerts in real-time</span>
    </div>

    <div id="bulkActions" class="bulk-actions">
      <strong><span id="selectedCount">0</span> selected</strong> — 
      <button class="btn btn-allow" onclick="bulkAllow()">✓ Allow Selected</button>
      <button class="btn btn-delete" onclick="bulkDismiss()">✗ Dismiss Selected</button>
    </div>

    <p class="small" style="background:#e8f5e9;padding:8px;border-radius:4px;border-left:3px solid #4CAF50">
      💡 <strong>Tip:</strong> "Allow" restores the file to its original location and whitelists it. "Dismiss" removes the alert but keeps the file in quarantine.
    </p>

    <table id="alertsTable">
      <thead>
        <tr>
          <th class="checkbox-cell"><input type="checkbox" onchange="selectAll(this)" title="Select all"></th>
          <th>File</th>
          <th>Size</th>
          <th>Rule</th>
          <th>Time</th>
          <th>Status</th>
          <th>Origin</th>
          <th>Original Location</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
      {% for a in alerts %}
      <tr>
        <td class="checkbox-cell">
          <input type="checkbox" class="alert-checkbox" data-file="{{ a.file }}" onchange="toggleSelection(this, '{{ a.file }}')">
        </td>
        <td style="word-break:break-all;max-width:200px">{{ a.file|basename }}</td>
        <td style="white-space:nowrap">{{ a.file_size if a.file_size else 'N/A' }}</td>
        <td><span style="background:#ffeb3b;padding:2px 6px;border-radius:3px;font-weight:bold">{{ a.rule }}</span></td>
        <td style="white-space:nowrap;font-size:0.85em">{{ a.time }}</td>
        <td><span style="color:{{ '#f44336' if a.status == 'block' else '#ff9800' }}">{{ a.status }}</span></td>
        <td style="font-size:0.85em">{{ a.origin if a.origin else "unknown" }}</td>
        <td style="word-break:break-all;max-width:200px;font-size:0.85em">{{ a.original_path if a.original_path else "N/A" }}</td>
        <td style="white-space:nowrap">
          <form style="display:inline" method="post" action="{{ url_for('allow_file') }}">
            <input type="hidden" name="file" value="{{ a.file }}"/>
            <button class="btn btn-allow" type="submit" title="Restore to original location and whitelist">✓</button>
          </form>
          <form style="display:inline" method="post" action="{{ url_for('delete_alert') }}">
            <input type="hidden" name="file" value="{{ a.file }}"/>
            <button class="btn btn-delete" type="submit" title="Remove alert only">✗</button>
          </form>
        </td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="small"><em>No alerts yet. System is monitoring...</em></p>
    {% endif %}

    <div class="debug-info">
      <strong>Debug Info:</strong><br>
      Quarantine folder: {{ quarantine }}<br>
      State file: {{ state_file }}<br>
      Last refresh: {{ now }}
    </div>
  </div>
</body>
</html>
"""


# Custom Jinja2 filter for basename
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)


@app.route("/")
def index():
    with state_lock:
        alerts = state.get("alerts", []).copy()
        whitelist = state.get("whitelist", []).copy()
        policy = state.get("policy_mode", "block")
        last_scan = state.get("last_scan_time")

    return render_template_string(TEMPLATE,
                                  alerts=alerts,
                                  whitelist=whitelist,
                                  policy=policy,
                                  quarantine=QUARANTINE_FOLDER,
                                  state_file=STATE_FILE,
                                  watch_paths=WATCH_PATHS,
                                  now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                  last_scan=last_scan)


@app.route("/toggle_policy")
def toggle_policy():
    with state_lock:
        current = state.get("policy_mode", "block")
        state["policy_mode"] = "warn" if current == "block" else "block"
        save_state(state)
    return redirect(url_for("index"))


@app.route("/add_whitelist", methods=["POST"])
def add_whitelist():
    p = request.form.get("path", "").strip()
    if p and os.path.exists(p):
        with state_lock:
            state.setdefault("whitelist", [])
            abs_p = os.path.abspath(p)
            if abs_p not in state["whitelist"]:
                state["whitelist"].append(abs_p)
                save_state(state)
    return redirect(url_for("index"))


@app.route("/remove_whitelist")
def remove_whitelist():
    p = request.args.get("path", "").strip()
    if p:
        with state_lock:
            if p in state.get("whitelist", []):
                state["whitelist"].remove(p)
                save_state(state)
    return redirect(url_for("index"))


@app.route("/allow_file", methods=["POST"])
def allow_file():
    fpath = request.form.get("file")
    # Find the alert to get original path
    original_path = None

    with state_lock:
        for alert in state.get("alerts", []):
            if alert.get("file") == fpath:
                original_path = alert.get("original_path")
                break

    # if file is in quarantine, move it back to its original location
    try:
        if fpath and os.path.exists(fpath):
            # Determine destination: use original path if available, otherwise default to watch folder
            if original_path and os.path.exists(os.path.dirname(original_path)):
                dest = original_path
                print(f"[INFO] Restoring file to original location: {dest}")
            else:
                # Fallback to watch folder
                dest = os.path.join(WATCH_FOLDER, os.path.basename(fpath))
                print(f"[INFO] Restoring file to watch folder (original path not available): {dest}")

            # Move file back
            shutil.move(fpath, dest)

            # Add the destination to whitelist so it won't be re-blocked
            with state_lock:
                state.setdefault("whitelist", [])
                if dest not in state["whitelist"]:
                    state["whitelist"].append(dest)
                # Remove any alerts that reference this file
                state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") != fpath]
                save_state(state)
            _mark_processed(dest)
            print(f"[INFO] File allowed and whitelisted: {dest}")
    except Exception as e:
        print(f"[ERROR] allow_file failed: {e}")
    return redirect(url_for("index"))


@app.route("/delete_alert", methods=["POST"])
def delete_alert():
    fpath = request.form.get("file")
    with state_lock:
        state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") != fpath]
        save_state(state)
    return redirect(url_for("index"))


@app.route("/bulk_allow", methods=["POST"])
def bulk_allow():
    """Allow multiple files at once"""
    data = request.get_json()
    files = data.get("files", [])
    success = 0

    for fpath in files:
        try:
            # Find original path
            original_path = None
            with state_lock:
                for alert in state.get("alerts", []):
                    if alert.get("file") == fpath:
                        original_path = alert.get("original_path")
                        break

            if fpath and os.path.exists(fpath):
                if original_path and os.path.exists(os.path.dirname(original_path)):
                    dest = original_path
                else:
                    dest = os.path.join(WATCH_FOLDER, os.path.basename(fpath))

                shutil.move(fpath, dest)

                with state_lock:
                    state.setdefault("whitelist", [])
                    if dest not in state["whitelist"]:
                        state["whitelist"].append(dest)
                    state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") != fpath]
                    save_state(state)
                _mark_processed(dest)
                success += 1
                print(f"[INFO] Bulk allowed: {dest}")
        except Exception as e:
            print(f"[ERROR] bulk_allow failed for {fpath}: {e}")

    return jsonify({"success": success})


@app.route("/bulk_dismiss", methods=["POST"])
def bulk_dismiss():
    """Dismiss multiple alerts at once"""
    data = request.get_json()
    files = data.get("files", [])

    with state_lock:
        state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") not in files]
        save_state(state)

    return jsonify({"success": len(files)})


@app.route("/export_alerts")
def export_alerts():
    """Export alerts to CSV"""
    with state_lock:
        alerts = state.get("alerts", []).copy()

    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['File', 'File Size', 'Rule', 'Time', 'Status', 'Origin', 'Original Path'])

    # Write data
    for alert in alerts:
        writer.writerow([
            alert.get('file', ''),
            alert.get('file_size', 'N/A'),
            alert.get('rule', ''),
            alert.get('time', ''),
            alert.get('status', ''),
            alert.get('origin', ''),
            alert.get('original_path', '')
        ])

    # Create response
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers[
        "Content-Disposition"] = f"attachment; filename=dlp_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-Type"] = "text/csv"

    return response


@app.route("/alerts")
def get_alerts():
    with state_lock:
        alerts = state.get("alerts", []).copy()
    return jsonify(alerts)


@app.route("/scan_existing", methods=["POST"])
def scan_existing():
    """Manually scan all existing files in watched directories"""
    scanned = 0
    detected = 0

    print("[INFO] Starting manual scan of existing files...")

    for watch_path in WATCH_PATHS:
        if not os.path.exists(watch_path):
            continue

        # SAFETY: Verify we're only scanning approved directories
        abs_watch = os.path.abspath(watch_path).lower()
        print(f"[SCAN] Scanning directory: {abs_watch}")

        try:
            for root, dirs, files in os.walk(watch_path):
                # Skip quarantine folder
                if QUARANTINE_FOLDER in root:
                    continue

                # SAFETY: Double-check we're still within the watched directory
                abs_root = os.path.abspath(root).lower()
                try:
                    common = os.path.commonpath([abs_watch, abs_root])
                    if common != abs_watch:
                        print(f"[CRITICAL] Attempted to scan outside watch path: {root}")
                        continue
                except:
                    print(f"[CRITICAL] Path validation failed for: {root}")
                    continue

                for filename in files:
                    filepath = os.path.join(root, filename)

                    # Skip if recently processed or quarantined
                    if _is_recently_processed(filepath) or _is_quarantine_path(filepath):
                        continue

                    # Skip if whitelisted
                    if is_whitelisted(filepath):
                        continue

                    print(f"[SCAN] Checking: {filepath}")
                    scanned += 1

                    rule = contains_sensitive_data(filepath)
                    if rule:
                        detected += 1
                        _mark_processed(filepath)

                        fname = os.path.basename(filepath)
                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        origin = _identify_origin(filepath)
                        file_size = get_file_size(filepath)

                        with state_lock:
                            policy_mode = state.get("policy_mode", "block")

                        alert = {
                            "file": filepath,
                            "rule": rule,
                            "time": ts,
                            "status": policy_mode,
                            "origin": origin,
                            "original_path": filepath,
                            "file_size": file_size
                        }
                        add_alert(alert)
                        print(f"[ALERT] Found {rule} in {filepath}")

                        if policy_mode == "block":
                            try:
                                dest = os.path.join(QUARANTINE_FOLDER, f"{int(time.time())}_{fname}")
                                shutil.move(filepath, dest)
                                print(f"[ACTION] Quarantined: {dest}")
                                with state_lock:
                                    if state["alerts"]:
                                        state["alerts"][0]["file"] = dest
                                    save_state(state)
                                _mark_processed(dest)
                            except Exception as e:
                                print(f"[ERROR] Could not quarantine: {e}")
        except Exception as e:
            print(f"[ERROR] Scan error for {watch_path}: {e}")

    # Update last scan time
    with state_lock:
        state["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_state(state)

    print(f"[INFO] Scan complete. Scanned: {scanned}, Detected: {detected}")
    return jsonify({"scanned": scanned, "detected": detected})


def start_flask():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


# ========== Main ==========
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🛡️  DATA LOSS PREVENTION (DLP) AGENT")
    print("=" * 70)

    # Show USB monitoring status prominently
    if ENABLE_USB_MONITORING:
        print(f"\n⚠️  USB MONITORING: ENABLED")
        print(f"   USB Drive: {USB_DRIVE}")
        print("   To disable, set ENABLE_USB_MONITORING = False in code")
    else:
        print(f"\n📌 USB MONITORING: DISABLED")
        print(f"   To enable, set ENABLE_USB_MONITORING = True in code")
        print(f"   USB Drive location: {USB_DRIVE}")

    # sanity checks: ensure watch paths exist (at least log if they don't)
    print("\n[STARTUP] Checking watch paths...")
    for p in WATCH_PATHS:
        if os.path.exists(p):
            print(f"  ✓ {p} - EXISTS")
        else:
            print(f"  ✗ {p} - NOT FOUND (will skip)")

    # start one watcher thread per watched path
    threads = []
    active_watchers = 0
    print("\n[STARTUP] Starting file system watchers...")
    for p in WATCH_PATHS:
        if os.path.exists(p):
            t = threading.Thread(target=start_watcher_for_path, args=(p,), daemon=True)
            t.start()
            threads.append(t)
            active_watchers += 1
        else:
            print(f"[ERROR] Skipping non-existent path: {p}")

    if active_watchers == 0:
        print("\n[ERROR] No valid watch paths found! Please check your configuration.")
        print("Press Ctrl+C to exit...")
    else:
        print(f"\n[STARTUP] Started {active_watchers} watcher(s)")

    # Start Flask in separate thread
    t2 = threading.Thread(target=start_flask, daemon=True)
    t2.start()

    # Start system tray (runs in main thread if available)
    if TRAY_AVAILABLE:
        print("[STARTUP] Starting system tray icon...")
        tray_thread = threading.Thread(target=start_system_tray, daemon=True)
        tray_thread.start()

    print("\n" + "=" * 70)
    print("✓ DLP AGENT READY")
    print("=" * 70)
    print(f"\n📊 Dashboard: http://127.0.0.1:5000")
    print(f"🔍 Monitoring: {active_watchers} path(s)")
    print(f"📁 Quarantine: {QUARANTINE_FOLDER}")
    if TRAY_AVAILABLE:
        print(f"🔔 System tray: Enabled (notifications active)")
    else:
        print(f"🔔 System tray: Disabled (install pystray & pillow to enable)")
    print(f"\nPress Ctrl+C to stop\n")
    print("=" * 70 + "\n")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down gracefully...")