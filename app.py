from flask import Flask, render_template, request
import os
import hashlib
import re

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"

# Ensure uploads folder exists
if not os.path.exists("uploads"):
    os.makedirs("uploads")

def scan_file(filepath):
    try:
        with open(filepath, "rb") as f:
            content = f.read()

        file_hash = hashlib.sha256(content).hexdigest()
        text_content = content.decode(errors="ignore").lower()

        suspicious_patterns = [
            r"cmd\.exe",
            r"powershell",
            r"createremotethread",
            r"virtualalloc",
            r"meterpreter",
            r"reverse\s+shell",
            r"nc\s+-e"
        ]

        threat_score = 0
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, text_content)
            threat_score += len(matches)

        risk_percentage = min(threat_score * 25, 100)

        if risk_percentage >= 50:
            level = "🚨 HIGH RISK THREAT"
        elif risk_percentage > 0:
            level = "⚠️ SUSPICIOUS FILE"
        else:
            level = "✅ SAFE FILE"

        return {
            "hash": file_hash,
            "score": threat_score,
            "risk": risk_percentage,
            "level": level
        }

    except Exception as e:
        return {
            "hash": "Error",
            "score": 0,
            "risk": 0,
            "level": f"Error: {str(e)}"
        }

@app.route("/", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        file = request.files["file"]
        if file.filename == "":
            return "No file selected"

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        result = scan_file(filepath)
        return render_template("result.html", result=result)

    return render_template("scan.html")

if __name__ == "__main__":
    app.run(debug=True)
