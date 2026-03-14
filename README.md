# CyberShield Advanced Virus Detector

A Flask-based malware detection dashboard with:
- File and folder scanning
- SQLite database for virus signatures and remediation guidance
- Detection history for every scan run
- Automatic folder monitoring for near real-time threat detection

## Run

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## Database

The app creates `virus_detector.db` automatically with these tables:
- `virus_signatures`: known signatures and fix instructions
- `scan_runs`: each scan execution summary
- `detections`: file-level scan outcome
- `monitor_events`: automatic monitor activity log
