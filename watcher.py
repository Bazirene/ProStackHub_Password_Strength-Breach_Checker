import hashlib
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from checker import check_pwned_password, evaluate_strength
from database import log_audit, init_db

LOG_FILE = "passwords.log"

class PasswordLogHandler(FileSystemEventHandler):
    def __init__(self, log_path):
        self.log_path = os.path.abspath(log_path)
        if not os.path.exists(self.log_path):
            open(self.log_path, "a").close()
        # Track whether the modification was triggered internally to prevent infinite loops
        self.is_self_modifying = False

    def on_modified(self, event):
        if os.path.abspath(event.src_path) != self.log_path:
            return

        # Ignore changes triggered by our own write operation
        if self.is_self_modifying:
            return

        # Read the file content
        with open(self.log_path, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        updated_lines = []
        file_changed = False

        for entry in lines:
            # Check if line is already a 40-character hexadecimal SHA-1 hash
            if len(entry) == 40 and all(c in "0123456789abcdefABCDEF" for c in entry):
                updated_lines.append(entry)
                continue

            # It's plaintext: compute the SHA-1 hash
            sha1_hash = hashlib.sha1(entry.encode("utf-8")).hexdigest()
            updated_lines.append(sha1_hash)
            file_changed = True

            # Evaluate strength and breach status
            score, _, _ = evaluate_strength(entry)
            breach_count = check_pwned_password(entry)

            if breach_count > 0 or score <= 1:
                severity = "Critical" if breach_count > 0 else "High"
            elif score in [2, 3]:
                severity = "Medium"
            else:
                severity = "Low"

            # Log to SQLite with the SHA-1 hash
            log_audit(
                source="Watchdog_FileWatcher",
                target_analyzed=sha1_hash,
                score=score,
                breach_count=breach_count,
                severity=severity
            )
            print(f"[*] [WATCHDOG EVENT] Anonymized '{entry}' -> {sha1_hash} | Severity: {severity}")

        # If any plaintext was converted, write the hashes back to passwords.log
        if file_changed:
            self.is_self_modifying = True
            with open(self.log_path, "w") as f:
                for h in updated_lines:
                    f.write(h + "\n")
            self.is_self_modifying = False

def start_watcher():
    init_db()
    event_handler = PasswordLogHandler(LOG_FILE)
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=False)
    observer.start()
    print(f"[*] Watchdog active. Append plaintext to '{LOG_FILE}' to see it automatically hashed...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_watcher()
