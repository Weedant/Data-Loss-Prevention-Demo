import re
import os
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# Patterns to detect sensitive data
patterns = {
    "Aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "Confidential": r"\b(confidential|secret|restricted)\b"
}


# Function to check file content
def contains_sensitive_data(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            for label, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    return label
    except:
        return None
    return None


class DLPHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            rule_triggered = contains_sensitive_data(event.src_path)
            if rule_triggered:
                print(f"[ALERT] Sensitive data found in {event.src_path} ({rule_triggered})")

                # Delete/Quarantine file
                os.remove(event.src_path)
                print(f"[ACTION] File deleted: {event.src_path}")

                # Send alert to dashboard
                try:
                    requests.post("http://127.0.0.1:5000/alert", json={
                        "file": event.src_path,
                        "rule": rule_triggered,
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                except:
                    print("[WARN] Could not connect to dashboard.")


# Path to monitor (simulate USB drive or folder)
path_to_watch = "E:\\"  # Windows USB example
event_handler = DLPHandler()
observer = Observer()
observer.schedule(event_handler, path=path_to_watch, recursive=True)
observer.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    observer.stop()
observer.join()
