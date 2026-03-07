"""
Flask routes for the SecFlow Orchestrator service.

Exposes:
  POST /api/smart-analyze          — main pipeline entry point
  GET  /api/health                 — health check
  GET  /api/report/<job_id>/json   — download JSON report
  GET  /api/report/<job_id>/html   — view HTML report
"""

import hashlib
import os
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

from app.orchestrator import run_pipeline
from app.reporter.report_generator import generate_report

bp = Blueprint("orchestrator", __name__)

_ALLOWED_PASSES = {3, 4, 5}


@bp.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "secflow-orchestrator"}), 200


@bp.route("/api/smart-analyze", methods=["POST"])
def smart_analyze():
    """
    Main analysis endpoint.

    Accepts one of:
      - multipart/form-data with field "file"  (any file: image, binary, etc.)
      - application/json with {"target": "<url|ip|domain>"}

    Query parameters:
      - passes: int (3, 4, or 5)  — default 3
    """
    try:
        passes = int(request.args.get("passes", 3))
    except (TypeError, ValueError):
        passes = 3

    if passes not in _ALLOWED_PASSES:
        return jsonify({"error": "passes must be 3, 4, or 5"}), 400

    # ── Resolve user_input ─────────────────────────────────────────────────────
    tmp_path: str | None = None

    if "file" in request.files:
        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"error": "Uploaded file has no filename"}), 400

        suffix = f"_{uploaded.filename}"
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            uploaded.save(tmp.name)
            tmp.close()
            tmp_path = tmp.name
            user_input = tmp_path
        except Exception as e:
            return jsonify({"error": f"Failed to save uploaded file: {e}"}), 500

    elif request.is_json:
        body = request.get_json(silent=True) or {}
        target = body.get("target") or body.get("url") or body.get("query")
        if not target:
            return jsonify({"error": "JSON body must contain 'target', 'url', or 'query' field"}), 400
        user_input = str(target).strip()

    else:
        return jsonify({
            "error": "Provide 'file' (multipart/form-data) or 'target' (application/json)"
        }), 400

    # ── Run the pipeline ───────────────────────────────────────────────────────
    try:
        store = run_pipeline(user_input, max_passes=passes)

        if store.is_empty():
            return jsonify({"error": "Pipeline produced no findings"}), 500

        job_id = hashlib.sha256(user_input.encode()).hexdigest()[:16]
        output_dir = f"/app/reports/{job_id}"

        report_paths = generate_report(
            findings_json=store.to_json(),
            job_id=job_id,
            output_dir=output_dir,
            base_name="report",
        )

        all_findings = store.get_all()
        overall_risk = max(p.get("risk_score", 0.0) for p in all_findings)

        return jsonify({
            "job_id": job_id,
            "passes_completed": len(all_findings),
            "overall_risk_score": round(overall_risk, 2),
            "findings_summary": all_findings,
            "report_paths": report_paths,
            "report_urls": {
                "json": f"/api/report/{job_id}/json",
                "html": f"/api/report/{job_id}/html",
            },
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        # Clean up temp file if we created one
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


_REPORT_MIME = {
    "json": "application/json",
    "html": "text/html",
}


@bp.route("/api/report/<job_id>/<fmt>", methods=["GET"])
def get_report(job_id: str, fmt: str):
    """
    Retrieve a generated report by job_id and format.

    GET /api/report/<job_id>/json
    GET /api/report/<job_id>/html
    """
    if fmt not in _REPORT_MIME:
        return jsonify({"error": f"Unknown format '{fmt}'. Use json or html."}), 400

    # Sanitize job_id — only allow lowercase hex chars (SHA-256 prefix)
    if not job_id or not all(c in "0123456789abcdef" for c in job_id):
        return jsonify({"error": "Invalid job_id"}), 400

    report_path = Path(f"/app/reports/{job_id}/report.{fmt}")

    if not report_path.exists():
        return jsonify({"error": f"Report not found for job_id '{job_id}'"}), 404

    return send_file(
        str(report_path),
        mimetype=_REPORT_MIME[fmt],
        as_attachment=(fmt == "json"),
        download_name=f"secflow_report_{job_id}.{fmt}",
    )
