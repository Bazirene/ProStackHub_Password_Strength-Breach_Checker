# ProStackHub_Password Strength & Breach Checker

Task 3: Password Strength & Breach Checker with Watchdog Log Anonymization

##  Project Overview

This project implements an enterprise-grade credential auditing system combining real-time file monitoring, entropy-based complexity scoring, privacy-preserving breach detection, and secure credential generation. The application adheres to defensive zero-trust architectural standards by ensuring no cleartext credential leaves the local environment or persists within permanent storage.

## Core Security Controls & Architecture

• Have I Been Pwned (HIBP) k-Anonymity Model: Plaintext passwords are cryptographically hashed using SHA-1. Only the first five characters of the hash (the prefix) are transmitted across the network to the HIBP Range API. The remaining 35 characters (the suffix) are matched strictly in-memory against returned breach records. At no point is the plaintext credential or its full hash transmitted over the network.
• Heuristic Entropy Evaluation (zxcvbn): Replaces static character-class checks with pattern matching, spatial keyboard walks, and l33t-speak dictionary analysis to compute realistic offline crack-time estimates and actionable hardening recommendations.
• Automated Watchdog File Anonymization: A background filesystem event listener monitors passwords.log using the Python Watchdog library. When incoming credentials are appended, the watcher hashes the plain text in memory, evaluates security metrics, overwrites the source file with the computed SHA-1 hash to prevent unencrypted disk leaks, and records the audit metadata to SQLite.
• Zero-Plaintext Audit Trail (SQLite): Event logs are stored in breach_history.db recording timestamps, monitoring source (Web_Interface or Watchdog_FileWatcher), SHA-1 target identifiers, entropy score (0–4), breach occurrence count, and severity classification (Low, Medium, High, Critical).

## Technical Stack

Component	Technology / Framework
Core Language	Python 3.10+
Web User Interface	Streamlit
File System Monitoring	Watchdog
Entropy Scoring Engine	zxcvbn-python
Breach Intelligence	Have I Been Pwned (HIBP) API (SHA-1 Range Query)
Audit Storage	SQLite3 (Relational Embedded DB)
Cryptographic Utilities	hashlib (SHA-1), secrets (Cryptographically Strong RNG)

## Project Directory Layout

ProStackHub_PasswordChecker/
├── app.py                 # Streamlit graphical dashboard
├── checker.py             # Core security engine (zxcvbn, HIBP k-Anonymity, generator)
├── database.py            # SQLite schema initialization and audit logging
├── watcher.py             # Real-time Watchdog event listener and file anonymizer
├── passwords.log          # Monitored credential ingestion log (auto-anonymized to SHA-1)
├── breach_history.db      # Persistent SQLite audit database
└── README.md              # Project documentation

## Operational Workflow & Execution

    • Step 1: Activate Virtual Environment and Launch File Watcher
source venv/bin/activate
python3 watcher.py
    • Step 2: Start Streamlit Interface (in a secondary shell)
source venv/bin/activate
python3 -m streamlit run app.py
    • Step 3: Ingest Simulated Credential to Verify Watchdog
echo "TestSecretPassword123!" >> passwords.log
Observation: passwords.log is immediately sanitized into a 40-character SHA-1 hash, and a new structured audit log appears under the SQLite Audit History tab in the dashboard.


## Internship Deliverables Checklist

    • • Public GitHub Repository: ProStackHub_PasswordStrength_BreachChecker
    • • Rule & Architecture Documentation: Exported PDF detailing the k-Anonymity privacy model and Watchdog loop mitigation.
    • • Walkthrough Video: 2–3 minute technical overview published to LinkedIn tagging @ProStackHub.

    • • Public GitHub Repository: ProStackHub_PasswordStrength_BreachChecker
    • • Rule & Architecture Documentation: Exported PDF detailing the k-Anonymity privacy model and Watchdog loop mitigation.
    • • Walkthrough Video: 2–3 minute technical overview published to LinkedIn tagging @ProStackHub.
