from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Iterable

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "virus_detector.db"
UPLOAD_FOLDER = BASE_DIR / "uploads"

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.secret_key = "virus-detector-secret"

UPLOAD_FOLDER.mkdir(exist_ok=True)

MONITOR_STATE = {
    "thread": None,
    "stop_event": None,
    "folder": None,
    "interval": 20,
    "status": "stopped",
}


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS virus_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            signature_type TEXT NOT NULL,
            signature_value TEXT NOT NULL,
            fix_instructions TEXT NOT NULL,
            UNIQUE(signature_type, signature_value)
        );

        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_path TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            infected_files INTEGER NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            detection_level TEXT NOT NULL,
            detected_signatures TEXT,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
        );

        CREATE TABLE IF NOT EXISTS monitor_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            folder_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    default_signatures = [
        (
            "EICAR Test File",
            "Standard anti-malware test signature.",
            "hash",
            "275a021bbfb6489e54d471899f7db9d9ad1c6eb44639007287e6ea28b55d9c12",
            "Quarantine the file and verify endpoint protection is active.",
        ),
        (
            "Meterpreter Payload Indicator",
            "Potential reverse shell payload string.",
            "pattern",
            r"meterpreter",
            "Isolate host, terminate malicious process, and rotate credentials.",
        ),
        (
            "PowerShell Obfuscation",
            "Suspicious use of encoded PowerShell command execution.",
            "pattern",
            r"powershell\s+.*-enc",
            "Block script execution, inspect scheduled tasks, and run full scan.",
        ),
        (
            "Netcat Remote Execution",
            "Netcat command with command execution flag.",
            "pattern",
            r"nc\s+-e",
            "Kill active socket processes and remove unauthorized binaries.",
        ),
        (
            "Remote Thread Injection",
            "Common API used for code injection in malware.",
            "pattern",
            r"createremotethread",
            "Inspect parent-child process tree and reimage machine if needed.",
        ),
    ]

    conn.executemany(
        """
        INSERT OR IGNORE INTO virus_signatures
        (name, description, signature_type, signature_value, fix_instructions)
        VALUES (?, ?, ?, ?, ?)
        """,
        default_signatures,
    )
    conn.commit()
    conn.close()


def get_signatures() -> list[sqlite3.Row]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM virus_signatures ORDER BY name ASC").fetchall()
    conn.close()
    return list(rows)


def get_recent_scans(limit: int = 10) -> list[sqlite3.Row]:
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return list(rows)


def get_recent_detections(limit: int = 20) -> list[sqlite3.Row]:
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT d.*, s.target_type, s.target_path
        FROM detections d
        JOIN scan_runs s ON s.id = d.scan_run_id
        ORDER BY d.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return list(rows)


def iter_files(target_path: Path) -> Iterable[Path]:
    if target_path.is_file():
        yield target_path
        return

    for root, _, files in os.walk(target_path):
        for filename in files:
            yield Path(root) / filename


def analyze_file(file_path: Path, signatures: list[sqlite3.Row]) -> dict:
    try:
        content = file_path.read_bytes()
    except Exception as exc:
        return {
            "file_path": str(file_path),
            "hash": "N/A",
            "level": "error",
            "matched": [],
            "error": str(exc),
        }

    sha256_hash = hashlib.sha256(content).hexdigest()
    text_content = content.decode(errors="ignore").lower()

    matches: list[dict] = []
    for signature in signatures:
        sig_type = signature["signature_type"]
        sig_value = signature["signature_value"]

        if sig_type == "hash" and sha256_hash == sig_value:
            matches.append(dict(signature))
        elif sig_type == "pattern" and re.search(sig_value, text_content):
            matches.append(dict(signature))

    if matches:
        level = "infected"
    else:
        level = "clean"

    return {
        "file_path": str(file_path),
        "hash": sha256_hash,
        "level": level,
        "matched": matches,
        "error": None,
    }


def store_scan_results(target_type: str, target_path: str, results: list[dict], status: str) -> int:
    infected_count = sum(1 for result in results if result["level"] == "infected")
    scanned_at = datetime.utcnow().isoformat(timespec="seconds")

    conn = get_db_connection()
    cursor = conn.execute(
        """
        INSERT INTO scan_runs
        (target_type, target_path, scanned_at, files_scanned, infected_files, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (target_type, target_path, scanned_at, len(results), infected_count, status),
    )
    scan_run_id = cursor.lastrowid

    for result in results:
        detected_names = ", ".join(match["name"] for match in result["matched"]) if result["matched"] else ""
        conn.execute(
            """
            INSERT INTO detections
            (scan_run_id, file_path, file_hash, detection_level, detected_signatures, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                result["file_path"],
                result["hash"],
                result["level"],
                detected_names,
                scanned_at,
            ),
        )

    conn.commit()
    conn.close()
    return scan_run_id


def run_scan(target: Path, target_type: str) -> tuple[int, list[dict], str]:
    signatures = get_signatures()

    if not target.exists():
        return -1, [], "Target path does not exist"

    results: list[dict] = []
    for file_path in iter_files(target):
        results.append(analyze_file(file_path, signatures))

    if not results:
        return -1, [], "No files found to scan"

    scan_run_id = store_scan_results(target_type, str(target), results, "completed")
    return scan_run_id, results, ""


def add_monitor_event(folder_path: str, event_type: str, details: str) -> None:
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO monitor_events (folder_path, event_type, details, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (folder_path, event_type, details, datetime.utcnow().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def monitor_folder_worker(folder_path: str, interval: int, stop_event: threading.Event) -> None:
    seen_modification_times: dict[str, float] = {}
    add_monitor_event(folder_path, "monitor_started", "Automatic monitoring started")

    while not stop_event.is_set():
        target = Path(folder_path)
        if not target.exists():
            add_monitor_event(folder_path, "monitor_error", "Folder no longer exists")
            time.sleep(interval)
            continue

        changed_files: list[Path] = []
        for file_path in iter_files(target):
            try:
                mod_time = file_path.stat().st_mtime
            except FileNotFoundError:
                continue

            path_key = str(file_path)
            if path_key not in seen_modification_times:
                seen_modification_times[path_key] = mod_time
                changed_files.append(file_path)
            elif mod_time > seen_modification_times[path_key]:
                seen_modification_times[path_key] = mod_time
                changed_files.append(file_path)

        if changed_files:
            signatures = get_signatures()
            results = [analyze_file(path, signatures) for path in changed_files]
            store_scan_results("auto-monitor", folder_path, results, "completed")
            infected = [r for r in results if r["level"] == "infected"]
            if infected:
                names = "; ".join(f"{r['file_path']} => {', '.join(m['name'] for m in r['matched'])}" for r in infected)
                add_monitor_event(folder_path, "threat_detected", names)

        time.sleep(interval)

    add_monitor_event(folder_path, "monitor_stopped", "Automatic monitoring stopped")


@app.route("/")
def home():
    return render_template(
        "index.html",
        recent_scans=get_recent_scans(),
        recent_detections=get_recent_detections(),
        signatures=get_signatures(),
        monitor_state=MONITOR_STATE,
    )


@app.route("/scan/file", methods=["POST"])
def scan_file_route():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please choose a file to scan.", "error")
        return redirect(url_for("home"))

    filename = secure_filename(uploaded_file.filename)
    save_path = UPLOAD_FOLDER / filename
    uploaded_file.save(save_path)

    scan_run_id, _, error = run_scan(save_path, "file")
    if scan_run_id < 0:
        flash(error, "error")
        return redirect(url_for("home"))

    return redirect(url_for("scan_result", scan_run_id=scan_run_id))


@app.route("/scan/folder", methods=["POST"])
def scan_folder_route():
    folder_path = request.form.get("folder_path", "").strip()
    if not folder_path:
        flash("Please provide a folder path.", "error")
        return redirect(url_for("home"))

    target = Path(folder_path)
    scan_run_id, _, error = run_scan(target, "folder")
    if scan_run_id < 0:
        flash(error, "error")
        return redirect(url_for("home"))

    return redirect(url_for("scan_result", scan_run_id=scan_run_id))


@app.route("/monitor/start", methods=["POST"])
def start_monitor():
    folder_path = request.form.get("monitor_folder_path", "").strip()
    interval = int(request.form.get("interval", 20))

    if not folder_path:
        flash("Provide a folder path to monitor.", "error")
        return redirect(url_for("home"))

    target = Path(folder_path)
    if not target.exists() or not target.is_dir():
        flash("Monitor path must be an existing directory.", "error")
        return redirect(url_for("home"))

    if MONITOR_STATE["thread"] and MONITOR_STATE["thread"].is_alive():
        flash("A monitor is already running. Stop it first.", "error")
        return redirect(url_for("home"))

    stop_event = threading.Event()
    thread = threading.Thread(
        target=monitor_folder_worker,
        args=(folder_path, max(interval, 5), stop_event),
        daemon=True,
    )
    thread.start()

    MONITOR_STATE["thread"] = thread
    MONITOR_STATE["stop_event"] = stop_event
    MONITOR_STATE["folder"] = folder_path
    MONITOR_STATE["interval"] = max(interval, 5)
    MONITOR_STATE["status"] = "running"
    flash("Automatic monitoring started.", "success")
    return redirect(url_for("home"))


@app.route("/monitor/stop", methods=["POST"])
def stop_monitor():
    thread = MONITOR_STATE.get("thread")
    stop_event = MONITOR_STATE.get("stop_event")

    if not thread or not thread.is_alive() or stop_event is None:
        flash("No active monitor found.", "error")
        return redirect(url_for("home"))

    stop_event.set()
    thread.join(timeout=1)
    MONITOR_STATE["status"] = "stopped"
    flash("Automatic monitoring stopped.", "success")
    return redirect(url_for("home"))


@app.route("/result/<int:scan_run_id>")
def scan_result(scan_run_id: int):
    conn = get_db_connection()
    scan_run = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_run_id,)).fetchone()
    detections = conn.execute(
        "SELECT * FROM detections WHERE scan_run_id = ? ORDER BY id DESC", (scan_run_id,)
    ).fetchall()
    conn.close()

    if scan_run is None:
        flash("Scan run not found.", "error")
        return redirect(url_for("home"))

    return render_template("result.html", scan_run=scan_run, detections=detections)


init_db()


if __name__ == "__main__":
    app.run(debug=True)
