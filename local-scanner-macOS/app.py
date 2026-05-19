"""
Local Mac Scanner - Flask backend.

  GET  /             render the single-page UI
  POST /api/scan     run the selected scans; returns a JSON report
  GET  /api/healthz  liveness probe

Listens on 127.0.0.1 only.  This tool runs READ-only commands on your own
machine - nothing in here ever modifies system state.
"""

from flask import Flask, jsonify, render_template, request

from scanner import run_scan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/healthz")
def healthz():
    return jsonify({"ok": True})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    scans = data.get("scans") or []
    secrets_path = (data.get("secrets_path") or "").strip()

    if not isinstance(scans, list):
        return jsonify({"error": "`scans` must be a list."}), 400

    try:
        report = run_scan(scans, secrets_path=secrets_path)
    except Exception as exc:  # noqa: BLE001 - surface unexpected errors
        return jsonify({"error": f"Unexpected scanner error: {exc}"}), 500

    if "error" in report:
        return jsonify(report), 400
    return jsonify(report)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)
