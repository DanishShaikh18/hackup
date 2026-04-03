"""
SOCentinel — Database setup and schema.
Uses plain sqlite3. Call init_db() to create all tables.
"""

import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "./socentinel.db")


def get_connection():
    """Get a sqlite3 connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,          -- CRITICAL, HIGH, MEDIUM, LOW, INFO
            status TEXT NOT NULL DEFAULT 'open',  -- open, triaging, resolved, closed
            rule_name TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            username TEXT,
            asset_id TEXT,
            timestamp TEXT NOT NULL,
            raw_log TEXT,
            ocsf_category TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS log_events (
            id TEXT PRIMARY KEY,
            alert_id TEXT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            username TEXT,
            asset_id TEXT,
            log_line TEXT NOT NULL,
            ocsf_json TEXT,
            metadata TEXT,                   -- JSON string for extra fields
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        );

        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            asset_type TEXT NOT NULL,         -- workstation, server, file_server, network_device
            criticality TEXT NOT NULL,        -- CRITICAL, HIGH, MEDIUM, LOW
            owner TEXT,
            ip_address TEXT,
            autonomy_tier INTEGER DEFAULT 1,  -- 0=auto, 1=one-click, 2=mfa
            metadata TEXT                     -- JSON string
        );

        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            department TEXT,
            role TEXT,
            is_privileged INTEGER DEFAULT 0,
            typical_hours TEXT,               -- e.g. "08:00-18:00"
            typical_ips TEXT,                 -- JSON array of typical IPs
            risk_score REAL DEFAULT 0.0,
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',  -- open, investigating, resolved, closed
            severity TEXT,
            analyst_notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            closed_at TEXT,
            resolution TEXT,
            resolution_time_minutes INTEGER,
            is_true_positive INTEGER,
            attack_type TEXT,
            mitre_techniques TEXT,            -- JSON array
            metadata TEXT
        );

        CREATE TABLE IF NOT EXISTS investigation_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            alert_id TEXT,
            finding TEXT NOT NULL,
            evidence_refs TEXT,               -- JSON array of log_event IDs
            confidence REAL DEFAULT 0.0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        );
    """)

    conn.commit()
    conn.close()
    print("[db] All tables created successfully.")


if __name__ == "__main__":
    init_db()
    print(f"[db] Database initialized at {DB_PATH}")
