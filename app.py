import os
import json
import time
import secrets
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "events.jsonl")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def utc_ts():
    return datetime.utcnow().isoformat() + "Z"


def log_event(event_type: str, payload: dict):
    record = {"ts": utc_ts(), "event": event_type, "payload": payload}
    try:
        ensure_data_dir()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def env_first(*names, default=""):
    """Берет первое непустое значение из env по списку ключей."""
    for n in names:
        v = os.environ.get(n)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default


# --- Telegram env (как у тебя уже настроено) ---
TG_BOT_TOKEN = env_first("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = env_first("TELEGRAM_CHAT_ID")


def send_telegram(text: str) -> bool:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log_event("telegram_skipped_no_env", {"has_token": bool(TG_BOT_TOKEN), "has_chat": bool(TG_CHAT_ID)})
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
        ok = r.status_code == 200
        if not ok:
            log_event("telegram_failed", {"status": r.status_code, "text": r.text[:300]})
        return ok
    except Exception as e:
        log_event("telegram_exception", {"error": str(e)})
        return False


# --- OAuth env ---
# Поддерживаем И "AMO_CLIENT_ID", И твой вариант "AmoClientID", чтобы не переименовывать
AMO_CLIENT_ID = env_first("AMO_CLIENT_ID", "AmoClientID")
AMO_CLIENT_SECRET = env_first("AMO_CLIENT_SECRET", "AmoClientSecret")
AMO_REDIRECT_URI = env_first("AMO_REDIRECT_URI", "AmoRedirectURL", "AmoRedirectURI")


def load_tokens():
    try:
        ensure_data_dir()
        if not os.path.exists(TOKENS_FILE):
            return {}
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_tokens(tokens: dict):
    try:
        ensure_data_dir()
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def parse_subdomain_from_referer(referer: str) -> str:
    if not referer:
        return ""
    host = urlparse(referer).netloc or referer
    # пример host: meawake.amocrm.ru
    return host.split(".(".")[0] if host else ""


@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "loss-control-backend",
        "endpoints": [
            "/health (GET)",
            "/widget/install (POST)",
            "/oauth/start (GET)",
            "/oauth/callback (GET)",
            "/debug/last (GET)"
        ]
    })


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/debug/last")
def debug_last():
    """Последние 50 строк логов (для отладки)."""
    try:
        ensure_data_dir()
        if not os.path.exists(LOG_FILE):
            return jsonify({"ok": True, "lines": []})
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-50:]
        return jsonify({"ok": True, "lines": [l.strip() for l in lines]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------------------------
# Widget lead endpoint
# ---------------------------
@app.post("/widget/install")
def widget_install():
    data = request.get_json(silent=True) or {}
    log_event("widget_install_raw", data)

    # "по-белому": шлем лид только при сохранении настроек (когда есть заполненные контакты)
    required = ["fio", "email", "phone"]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing:
        log_event("widget_install_rejected_missing_fields", {"missing": missing, "data": data})
        return jsonify({"ok": False, "error": "missing_fields", "missing": missing}), 400

    account_id = data.get("account_id")
    subdomain = (data.get("subdomain") or "").strip()
    user_id = data.get("user_id")

    fio = (data.get("fio") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()

    text = "\n".join([
        "✅ <b>Loss Control — новый лид (сохранены настройки)</b>",
        f"Аккаунт: <b>{subdomain or '-'}</b>",
        f"account_id: <code>{account_id}</code>",
        f"user_id: <code>{user_id}</code>",
        "",
        f"ФИО: <b>{fio}</b>",
        f"Email: <b>{email}</b>",
        f"Телефон: <b>{phone}</b>",
    ])

    sent = send_telegram(text)
    log_event("widget_install_sent", {"sent": sent, "subdomain": subdomain, "account_id": account_id})
    return jsonify({"ok": True, "sent": sent})


# ---------------------------
# OAuth endpoints
# ---------------------------
@app.get("/oauth/start")
def oauth_start():
    if not AMO_CLIENT_ID or not AMO_REDIRECT_URI:
        return jsonify({"ok": False, "error": "missing_env_AMO_CLIENT_ID_or_AMO_REDIRECT_URI"}), 500

    state = secrets.token_urlsafe(16)
    url = f"https://www.amocrm.ru/oauth?client_id={AMO_CLIENT_ID}&state={state}&mode=post_message"
    return jsonify({"ok": True, "url": url})


@app.get("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    referer = request.args.get("referer")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        log_event("oauth_denied", {"error": error, "state": state, "referer": referer})
        return "<h3>Доступ не предоставлен</h3>", 400

    if not code or not referer:
        log_event("oauth_bad_callback", {"code": code, "referer": referer, "state": state})
        return "<h3>Некорректный callback (нет code/referer)</h3>", 400

    subdomain = parse_subdomain_from_referer(referer)
    if not subdomain:
        return "<h3>Не удалось определить subdomain</h3>", 400

    if not AMO_CLIENT_ID or not AMO_CLIENT_SECRET or not AMO_REDIRECT_URI:
        return "<h3>На сервере не заданы AMO_* переменные</h3>", 500

    token_url = f"https://{subdomain}.amocrm.ru/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AMO_REDIRECT_URI,
    }

    try:
        r = requests.post(token_url, json=payload, timeout=15)
        data = r.json() if r.content else {}
    except Exception as e:
        log_event("oauth_token_exchange_exception", {"error": str(e), "subdomain": subdomain})
        return "<h3>Ошибка обмена кода на токены</h3>", 500

    if r.status_code != 200 or not data.get("access_token"):
        log_event("oauth_token_exchange_failed", {"status": r.status_code, "resp": data, "subdomain": subdomain})
        return "<h3>Не удалось получить токены</h3>", 400

    tokens = load_tokens()
    tokens[subdomain] = {
        "updated_at": utc_ts(),
        "referer": referer,
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "expires_in": data.get("expires_in"),
        "token_type": data.get("token_type"),
        "server_time": data.get("server_time"),
    }
    save_tokens(tokens)

    log_event("oauth_ok", {"subdomain": subdomain, "referer": referer})

    return """
<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>OAuth OK</title></head>
<body>
  <h3>✅ Аккаунт подключён</h3>
  <p>Можно закрыть это окно и вернуться в amoCRM.</p>
</body>
</html>
"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
