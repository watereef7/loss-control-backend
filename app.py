import os
import json
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Разрешаем запросы (на время отладки можно "*")
CORS(app, resources={r"/*": {"origins": "*"}})

# Папка для логов (на некоторых хостингах может быть read-only — учтено)
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "events.jsonl")


def log_event(event_type: str, payload: dict):
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        "payload": payload,
    }
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # Если файловая система недоступна — не валим API
        pass


@app.get("/")
def index():
    return jsonify(
        {
            "ok": True,
            "service": "loss-control-backend",
            "endpoints": [
                "/ (GET)",
                "/health (GET)",
                "/widget/ping (POST)",
                "/widget/install (POST)",
            ],
        }
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/widget/ping")
def widget_ping():
    data = request.get_json(silent=True) or {}
    log_event("ping", data)
    return jsonify({"ok": True, "received": data})


@app.post("/widget/install")
def widget_install():
    data = request.get_json(silent=True) or {}

    consent = bool(data.get("consent"))
    if not consent:
        log_event("install_rejected_no_consent", data)
        return jsonify({"ok": False, "error": "consent_required"}), 400

    required = ["account_id", "subdomain", "user_id", "fio", "email", "phone"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        log_event("install_rejected_missing_fields", {"missing": missing, "data": data})
        return jsonify({"ok": False, "error": "missing_fields", "missing": missing}), 400

    log_event("install", data)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # Render / облака отдают порт через PORT
    port = int(os.environ.get("PORT", "5000"))

    # DEBUG=1 чтобы включить отладку локально, в облаке оставляем выключенным
    debug = os.environ.get("DEBUG", "0") == "1"

    app.run(host="0.0.0.0", port=port, debug=debug)
