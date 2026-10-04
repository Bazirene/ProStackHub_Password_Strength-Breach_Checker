import sqlite3

DB_NAME = "breach_history.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT,
            target_analyzed TEXT,
            score INTEGER,
            breach_count INTEGER,
            severity TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_audit(source, target_analyzed, score, breach_count, severity):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (source, target_analyzed, score, breach_count, severity) VALUES (?, ?, ?, ?, ?)",
        (source, target_analyzed, score, breach_count, severity)
    )
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()