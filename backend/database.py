"""
Database Storage Module for SOC Tier-1 Triage Tool
Stores analysis history, full incident reports, and extracted IOCs in SQLite.
"""
import json
import sqlite3
import os
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "triage_history.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_history (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        analysis_type TEXT NOT NULL,
        target_summary TEXT NOT NULL,
        threat_score INTEGER NOT NULL,
        threat_verdict TEXT NOT NULL,
        mitre_techniques TEXT,
        findings_summary TEXT,
        full_report_json TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        defanged_value TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        context TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analysis_history (id) ON DELETE CASCADE
    );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_timestamp ON analysis_history(timestamp DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_history_verdict ON analysis_history(threat_verdict);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_analysis ON iocs(analysis_id);")

    conn.commit()
    conn.close()


def save_analysis_record(report: Dict[str, Any]) -> str:
    """Save an incident triage report and its extracted IOCs"""
    conn = get_connection()
    cursor = conn.cursor()

    case_id = report.get("case_id")
    timestamp = report.get("timestamp")
    analysis_type = report.get("analysis_type", "URL")
    target_summary = report.get("target_summary", "")
    threat_score = report.get("threat_score", 0)
    threat_verdict = report.get("threat_verdict", "SAFE")

    mitre_list = [m.get("id") for m in report.get("mitre_mapping", [])]
    mitre_techniques = json.dumps(mitre_list)
    findings_summary = json.dumps([b.get("description") for b in report.get("score_breakdown", [])[:5]])
    full_report_json = json.dumps(report)

    cursor.execute("""
    INSERT OR REPLACE INTO analysis_history 
    (id, timestamp, analysis_type, target_summary, threat_score, threat_verdict, mitre_techniques, findings_summary, full_report_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, timestamp, analysis_type, target_summary, threat_score, threat_verdict, mitre_techniques, findings_summary, full_report_json))

    # Save extracted IOCs
    iocs = report.get("iocs", [])
    for ioc in iocs:
        cursor.execute("""
        INSERT INTO iocs (analysis_id, ioc_type, raw_value, defanged_value, threat_level, context)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            ioc.get("ioc_type", "IOC"),
            ioc.get("raw_value", ""),
            ioc.get("defanged_value", ""),
            threat_verdict,
            ioc.get("context", "")
        ))

    conn.commit()
    conn.close()
    return case_id


def get_analysis_history(limit: int = 50, verdict_filter: Optional[str] = None, type_filter: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve history list with optional filters"""
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, timestamp, analysis_type, target_summary, threat_score, threat_verdict, mitre_techniques, findings_summary FROM analysis_history WHERE 1=1"
    params = []

    if verdict_filter and verdict_filter.upper() != "ALL":
        query += " AND threat_verdict = ?"
        params.append(verdict_filter.upper())

    if type_filter and type_filter.upper() != "ALL":
        query += " AND analysis_type = ?"
        params.append(type_filter.upper())

    if search:
        query += " AND (target_summary LIKE ? OR id LIKE ?)"
        s_term = f"%{search}%"
        params.extend([s_term, s_term])

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "analysis_type": r["analysis_type"],
            "target_summary": r["target_summary"],
            "threat_score": r["threat_score"],
            "threat_verdict": r["threat_verdict"],
            "mitre_techniques": json.loads(r["mitre_techniques"]) if r["mitre_techniques"] else [],
            "findings_summary": json.loads(r["findings_summary"]) if r["findings_summary"] else []
        })

    conn.close()
    return history


def get_analysis_by_id(case_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full incident report by Case ID"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT full_report_json FROM analysis_history WHERE id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return json.loads(row["full_report_json"])
    return None


def get_all_iocs(limit: int = 200) -> List[Dict[str, Any]]:
    """Retrieve aggregated list of all defanged IOCs"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT DISTINCT ioc_type, raw_value, defanged_value, threat_level, context, analysis_id 
    FROM iocs 
    ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [dict(r) for r in rows]


def clear_all_history():
    """Clear all records from history and IOCs"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM iocs;")
    cursor.execute("DELETE FROM analysis_history;")
    conn.commit()
    conn.close()
