"""
Local Mac Scanner - Flask backend.

  GET  /                 render the single-page UI
  POST /api/scan         run the selected scans synchronously; returns JSON
  GET  /api/scan/stream  run the selected scans and stream progress via SSE
  GET  /api/healthz      liveness probe

Listens on 127.0.0.1 only.  This tool runs READ-only commands on your own
machine - nothing in here ever modifies system state.
"""

import json

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from scanner import run_scan, run_scan_streaming

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


@app.route("/api/scan/stream", methods=["GET"])
def api_scan_stream():
    """
    Server-Sent Events endpoint.  EventSource is GET-only, so options come
    in via the querystring (this is a localhost-only tool).

      ?scans=secrets,ports,config&secrets_path=~/Projects
    """
    raw_scans = request.args.get("scans", "")
    secrets_path = (request.args.get("secrets_path") or "").strip()
    scans = [s.strip() for s in raw_scans.split(",") if s.strip()]

    def event_stream():
        try:
            for event in run_scan_streaming(scans, secrets_path=secrets_path):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:  # noqa: BLE001
            err = {"type": "error", "message": f"Unexpected scanner error: {exc}"}
            yield f"data: {json.dumps(err)}\n\n"

    # Disable proxy buffering and gzip so events flush promptly.
    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(stream_with_context(event_stream()),
                    mimetype="text/event-stream",
                    headers=headers)


if __name__ == "__main__":
    # Threaded=True so the SSE stream doesn't block other requests during a long scan.
    app.run(host="127.0.0.1", port=5002, debug=True, threaded=True)
