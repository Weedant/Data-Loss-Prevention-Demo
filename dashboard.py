# main.py -- Mini DLP agent + Flask dashboard with whitelist & policy modes
import re
import os
import threading
import time
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, render_template_string, jsonify, redirect, url_for

# ========== Config ==========
BASE_DIR = os.path.dirname(__file__)
WATCH_PATH = r"C:\Users\VEDANT\Desktop\Data_Exfiltration\watch"
QUARANTINE_FOLDER = os.path.join(BASE_DIR, "quarantine")
STATE_FILE = os.path.join(BASE_DIR, "dlp_state.json")
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(WATCH_PATH, exist_ok=True)

PATTERNS = {
    "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Confidential": r"\b(confidential|secret|restricted)\b"
}

# Default state
default_state = {
    "policy_mode": "block",   # "block" or "warn"
    "whitelist": [],         # list of file paths or directory paths
    "alerts": []             # stored alerts (most recent first)
}

# ========== Load / Save state ==========
def load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
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
    state_alerts = state.get("alerts", [])
    state_alerts.insert(0, entry)
    # keep only recent 200 alerts
    state["alerts"] = state_alerts[:200]
    save_state(state)

# ========== Processed cache & helpers ==========
_processed_cache = {}  # path -> last_handled_time (float)
PROCESSED_TTL = 5.0    # seconds to remember a processed file

def _is_recently_processed(path):
    now = time.time()
    last = _processed_cache.get(os.path.abspath(path))
    if last and (now - last) < PROCESSED_TTL:
        return True
    # garbage collect old keys occasionally
    for p, t in list(_processed_cache.items()):
        if now - t > PROCESSED_TTL * 5:
            _processed_cache.pop(p, None)
    return False

def _mark_processed(path):
    _processed_cache[os.path.abspath(path)] = time.time()

def _is_quarantine_path(path):
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(QUARANTINE_FOLDER)]) == os.path.abspath(QUARANTINE_FOLDER)
    except Exception:
        return False

def _looks_like_quarantine_name(path):
    return re.match(r"^\d+_", os.path.basename(path)) is not None

# ========== Detection ==========
def is_whitelisted(filepath):
    # ignore anything inside quarantine folder explicitly
    if _is_quarantine_path(filepath):
        return True

    # check if filepath or its parent directories are whitelisted
    for w in state.get("whitelist", []):
        try:
            if os.path.commonpath([os.path.abspath(w), os.path.abspath(filepath)]) == os.path.abspath(w):
                return True
        except Exception:
            continue
    return False

def wait_for_file_stable(path, timeout=5.0, poll=0.4):
    """Wait until file size is stable or timeout. Returns True if stable."""
    start = time.time()
    try:
        last_size = -1
        while time.time() - start <= timeout:
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            if size == last_size:
                return True
            last_size = size
            time.sleep(poll)
    except Exception:
        return False
    return False

def contains_sensitive_data(filepath):
    # ensure we don't scan quarantined files or files we just handled
    if _is_quarantine_path(filepath) or _looks_like_quarantine_name(filepath):
        return None

    # wait for copy to complete (helps avoid partial reads & duplicate events)
    if not wait_for_file_stable(filepath, timeout=4.0):
        # file never stabilized — skip for now
        return None

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for label, pat in PATTERNS.items():
                if re.search(pat, content, re.IGNORECASE):
                    return label
    except Exception:
        return None
    return None

class DLPHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # ignore anything in quarantine folder
        if _is_quarantine_path(path):
            return

        # drop events we already processed recently
        if _is_recently_processed(path):
            return

        # short delay to allow writes; plus wait_for_file_stable in contains_sensitive_data
        time.sleep(0.2)

        if is_whitelisted(path):
            print(f"[INFO] Whitelisted path, ignoring: {path}")
            _mark_processed(path)
            return

        # also skip if the filename looks like quarantine output (prevents loop)
        if _looks_like_quarantine_name(path):
            _mark_processed(path)
            return

        rule = contains_sensitive_data(path)
        if rule:
            # mark it as processed early to avoid duplicate handling
            _mark_processed(path)

            fname = os.path.basename(path)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = {"file": path, "rule": rule, "time": ts, "status": state.get("policy_mode", "block")}
            add_alert(alert)
            print(f"[ALERT] {path} matched {rule} (policy: {state.get('policy_mode')})")
            if state.get("policy_mode") == "block":
                # move to quarantine
                try:
                    dest = os.path.join(QUARANTINE_FOLDER, f"{int(time.time())}_{fname}")
                    # use os.replace which is atomic on same filesystem
                    os.replace(path, dest)
                    print(f"[ACTION] Moved to quarantine: {dest}")
                    # update last alert file path to quarantine location
                    state["alerts"][0]["file"] = dest
                    save_state(state)
                    # mark quarantined file processed so future events are ignored
                    _mark_processed(dest)
                except Exception as e:
                    print(f"[ERROR] Could not quarantine file: {e}")
            else:
                # warn mode: leave file but mark alert
                print("[ACTION] Warn mode - file left in place")
                save_state(state)

    def on_moved(self, event):
        # handle move events similarly (src->dest)
        if event.is_directory:
            return
        dest = event.dest_path
        # ignore if in quarantine or already processed or looks like quarantine name
        if _is_quarantine_path(dest) or _is_recently_processed(dest) or _looks_like_quarantine_name(dest):
            return

        time.sleep(0.2)
        if is_whitelisted(dest):
            _mark_processed(dest)
            return

        rule = contains_sensitive_data(dest)
        if rule:
            _mark_processed(dest)
            fname = os.path.basename(dest)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            alert = {"file": dest, "rule": rule, "time": ts, "status": state.get("policy_mode", "block")}
            add_alert(alert)
            print(f"[ALERT] {dest} matched {rule} (policy: {state.get('policy_mode')})")
            if state.get("policy_mode") == "block":
                try:
                    qdest = os.path.join(QUARANTINE_FOLDER, f"{int(time.time())}_{fname}")
                    os.replace(dest, qdest)
                    print(f"[ACTION] Moved to quarantine: {qdest}")
                    state["alerts"][0]["file"] = qdest
                    save_state(state)
                    _mark_processed(qdest)
                except Exception as e:
                    print(f"[ERROR] Could not quarantine file (moved): {e}")
            else:
                print("[ACTION] Warn mode - file left in place")
                save_state(state)

# ========== Watcher thread ==========
def start_watcher(path):
    handler = DLPHandler()
    observer = Observer()
    observer.schedule(handler, path=path, recursive=True)
    observer.start()
    print(f"[INFO] Watching: {path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ========== Flask dashboard ==========
app = Flask(__name__)
TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Mini DLP Dashboard</title>
  <style>
    body{font-family:Arial;margin:20px}
    table{width:100%;border-collapse:collapse}
    th,td{padding:8px;border:1px solid #ccc}
    th{background:#333;color:#fff}
    tr:nth-child(even){background:#f8f8f8}
    .small{font-size:0.9em;color:#555}
    .btn{padding:6px 10px;border:none;border-radius:4px;cursor:pointer}
    .btn-allow{background:#4CAF50;color:white}
    .btn-delete{background:#f44336;color:white}
  </style>
</head>
<body>
  <h1>Mini DLP Dashboard</h1>
  <p>Policy Mode: <strong>{{ policy }}</strong> — <a href="{{ url_for('toggle_policy') }}">Toggle</a></p>
  <h3>Whitelist</h3>
  <form method="post" action="{{ url_for('add_whitelist') }}">
    <input name="path" style="width:70%" placeholder="Path to whitelist (file or folder)"/>
    <button type="submit">Add</button>
  </form>
  <ul>
  {% for w in whitelist %}
    <li class="small">{{ w }} <a href="{{ url_for('remove_whitelist') }}?path={{ w }}">[remove]</a></li>
  {% endfor %}
  </ul>

  <h3>Alerts (most recent first) — Total: {{ alerts|length }}</h3>
  <table>
    <tr><th>File</th><th>Rule</th><th>Time</th><th>Status</th><th>Actions</th></tr>
    {% for a in alerts %}
    <tr>
      <td style="word-break:break-all">{{ a.file }}</td>
      <td>{{ a.rule }}</td>
      <td>{{ a.time }}</td>
      <td>{{ a.status }}</td>
      <td>
        <form style="display:inline" method="post" action="{{ url_for('allow_file') }}">
          <input type="hidden" name="file" value="{{ a.file }}"/>
          <button class="btn btn-allow" type="submit">Allow</button>
        </form>
        <form style="display:inline" method="post" action="{{ url_for('delete_alert') }}">
          <input type="hidden" name="file" value="{{ a.file }}"/>
          <button class="btn btn-delete" type="submit">Delete</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </table>

  <p class="small">Quarantine folder: {{ quarantine }}</p>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE,
                                  alerts=state.get("alerts", []),
                                  whitelist=state.get("whitelist", []),
                                  policy=state.get("policy_mode", "block"),
                                  quarantine=QUARANTINE_FOLDER)

@app.route("/toggle_policy")
def toggle_policy():
    current = state.get("policy_mode", "block")
    state["policy_mode"] = "warn" if current == "block" else "block"
    save_state(state)
    return redirect(url_for("index"))

@app.route("/add_whitelist", methods=["POST"])
def add_whitelist():
    p = request.form.get("path", "").strip()
    if p:
        state.setdefault("whitelist", [])
        if p not in state["whitelist"]:
            state["whitelist"].append(p)
            save_state(state)
    return redirect(url_for("index"))

@app.route("/remove_whitelist")
def remove_whitelist():
    p = request.args.get("path", "").strip()
    if p and p in state.get("whitelist", []):
        state["whitelist"].remove(p)
        save_state(state)
    return redirect(url_for("index"))

@app.route("/allow_file", methods=["POST"])
def allow_file():
    fpath = request.form.get("file")
    # if file is in quarantine, move it back to watch and add to whitelist
    try:
        if fpath and os.path.exists(fpath):
            dest = os.path.join(WATCH_PATH, os.path.basename(fpath))
            os.replace(fpath, dest)
            # add the destination to whitelist so it won't be re-blocked
            if dest not in state.get("whitelist", []):
                state.setdefault("whitelist", []).append(dest)
            # remove any alerts that reference this file
            state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") != fpath]
            save_state(state)
    except Exception as e:
        print(f"[ERROR] allow_file failed: {e}")
    return redirect(url_for("index"))

@app.route("/delete_alert", methods=["POST"])
def delete_alert():
    fpath = request.form.get("file")
    state["alerts"] = [a for a in state.get("alerts", []) if a.get("file") != fpath]
    save_state(state)
    return redirect(url_for("index"))

@app.route("/alerts")
def get_alerts():
    return jsonify(state.get("alerts", []))

def start_flask():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

# ========== Main ==========
if __name__ == "__main__":
    # sanity checks
    if not os.path.isdir(WATCH_PATH):
        print(f"[ERROR] Watch folder does not exist: {WATCH_PATH}")
        print("Create it and try again.")
        raise SystemExit(1)

    t1 = threading.Thread(target=start_watcher, args=(WATCH_PATH,), daemon=True)
    t2 = threading.Thread(target=start_flask, daemon=True)
    t1.start()
    t2.start()
    print("[INFO] DLP agent + dashboard started. Open http://127.0.0.1:5000")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Exiting...")
