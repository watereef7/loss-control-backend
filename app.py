import os
import json
from datetime import datetime
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# ✅ CORS: можно оставить "*" на отладке, но для публикации лучше ограничить amoCRM
# На старте оставим как у тебя (чтобы не словить блокировки), а потом ужесточим.
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "events.jsonl")

# ✅ Берем из Render Environment (ты уже добавил)
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")


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
        pass


def send_telegram(text: str):
    """Отправка сообщения в Telegram (в вашу группу)."""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("❗ Telegram env vars missing: TG_BOT_TOKEN / TG_CHAT_ID")
        return False

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        ok = (r.status_code == 200)
        if not ok:
            print("TG error:", r.status_code, r.text[:300])
        return ok
    except Exception as e:
        print("TG send error:", str(e))
        return False


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

    # ✅ Отправляем лид в Telegram
    text = (
        "🔥 <b>Новая установка Loss Control</b>\n"
        f"👤 ФИО: <b>{data.get('fio') or '—'}</b>\n"
        f"📧 Email: <b>{data.get('email') or '—'}</b>\n"
        f"📞 Телефон: <b>{data.get('phone') or '—'}</b>\n"
        f"🏢 Account ID: <b>{data.get('account_id') or '—'}</b>\n"
        f"🌐 Subdomain: <b>{data.get('subdomain') or '—'}</b>\n"
        f"🧑‍💻 User ID: <b>{data.get('user_id') or '—'}</b>\n"
    )
    tg_ok = send_telegram(text)
    log_event("install_telegram_sent", {"ok": tg_ok})

    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
