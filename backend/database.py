import sqlite3
import json
from datetime import datetime
from backend.config import settings

def get_db_connection():
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            sender TEXT,
            subject TEXT,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            data_json TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

# Auto-initialize database on import
init_db()


def save_analysis(analysis_data: dict):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO analyses (id, created_at, filename, sender, subject, risk_score, classification, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_data["analysis_id"],
        analysis_data.get("timestamp", datetime.utcnow().isoformat()),
        analysis_data.get("filename", "unknown.eml"),
        analysis_data.get("email", {}).get("from", ""),
        analysis_data.get("email", {}).get("subject", ""),
        analysis_data["risk_score"],
        analysis_data["classification"],
        json.dumps(analysis_data)
    ))
    conn.commit()
    conn.close()

def get_analysis_by_id(analysis_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT data_json FROM analyses WHERE id = ?", (analysis_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row["data_json"])
    return None

def get_recent_analyses(limit: int = 10):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, created_at, filename, sender, subject, risk_score, classification 
        FROM analyses 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
