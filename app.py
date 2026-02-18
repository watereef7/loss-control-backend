import os
import json
import secrets
from datetime import datetime, timezone

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

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


def now_epoch() -> int:
    return int(datetime.now(tz=timezone.utc).timestamp())


def log_event(event_type: str, payload: dict):
    record = {"ts": utc_ts(), "event": event_type, "payload": payload}
    try:
        ensure_data_dir()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def env_first(*names, default=""):
    for n in names:
        v = os.environ.get(n)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default


# --- Telegram ---
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
    parsed = urlparse(referer)
    host = parsed.netloc if parsed.netloc else referer
    parts = host.split(".")
    return parts[0] if parts else ""


def ensure_token_expire_ts(token_rec: dict):
    """
    amoCRM дает expires_in + server_time (epoch). Сохраним expires_at, чтобы понимать истек ли токен.
    """
    if not token_rec:
        return
    if token_rec.get("expires_at"):
        return
    expires_in = token_rec.get("expires_in")
    server_time = token_rec.get("server_time")
    if isinstance(expires_in, int) and isinstance(server_time, int):
        token_rec["expires_at"] = int(server_time) + int(expires_in)


def refresh_access_token(subdomain: str, refresh_token: str) -> dict:
    url = f"https://{subdomain}.amocrm.ru/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": AMO_REDIRECT_URI,
    }
    r = requests.post(url, json=payload, timeout=20)
    data = r.json() if r.content else {}
    if r.status_code != 200 or not data.get("access_token"):
        raise RuntimeError(f"refresh_failed status={r.status_code} resp={data}")
    return data


def get_access_token(subdomain: str) -> str:
    tokens = load_tokens()
    rec = tokens.get(subdomain)
    if not rec:
        raise RuntimeError("no_tokens_for_subdomain")

    ensure_token_expire_ts(rec)

    # Обновляем чуть заранее (на 60 сек), чтобы не ловить 401 на границе
    expires_at = rec.get("expires_at")
    if isinstance(expires_at, int) and now_epoch() > (expires_at - 60):
        log_event("token_refresh_start", {"subdomain": subdomain})
        new_data = refresh_access_token(subdomain, rec.get("refresh_token"))
        rec.update({
            "access_token": new_data.get("access_token"),
            "refresh_token": new_data.get("refresh_token"),
            "expires_in": new_data.get("expires_in"),
            "token_type": new_data.get("token_type"),
            "server_time": new_data.get("server_time"),
            "updated_at": utc_ts(),
            "expires_at": int(new_data.get("server_time", now_epoch())) + int(new_data.get("expires_in", 0)),
        })
        tokens[subdomain] = rec
        save_tokens(tokens)
        log_event("token_refresh_ok", {"subdomain": subdomain})

    return rec.get("access_token")


def amo_api_get(subdomain: str, path: str, params=None):
    token = get_access_token(subdomain)
    url = f"https://{subdomain}.amocrm.ru{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=30)
    if r.status_code >= 400:
        try:
            body = r.json()
        except Exception:
            body = {"text": r.text[:500]}
        raise RuntimeError(f"amo_get_failed {r.status_code} {body}")
    return r.json() if r.content else {}


@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "loss-control-backend",
        "endpoints": [
            "/health (GET)",
            "/debug/last (GET)",
            "/widget/install (POST)",
            "/oauth/start (GET)",
            "/oauth/callback (GET)",
            "/report/losses (GET)"
        ]
    })


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/debug/last")
def debug_last():
    try:
        ensure_data_dir()
        if not os.path.exists(LOG_FILE):
            return jsonify({"ok": True, "lines": []})
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-80:]
        return jsonify({"ok": True, "lines": [l.strip() for l in lines]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# --- Widget lead (по-белому: только по кнопке "Сохранить") ---
@app.post("/widget/install")
def widget_install():
    data = request.get_json(silent=True) or {}
    log_event("widget_install_raw", data)

    required = ["fio", "email", "phone"]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing:
        return jsonify({"ok": False, "error": "missing_fields", "missing": missing}), 400

    account_id = data.get("account_id")
    subdomain = (data.get("subdomain") or "").strip()
    user_id = data.get("user_id")

    fio = (data.get("fio") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()

    text = "\n".join([
        "✅ <b>Loss Control — новый лид (нажали Сохранить)</b>",
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


# --- OAuth ---
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

    token_url = f"https://{subdomain}.amocrm.ru/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AMO_REDIRECT_URI,
    }

    r = requests.post(token_url, json=payload, timeout=20)
    data = r.json() if r.content else {}

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
        "expires_at": int(data.get("server_time", now_epoch())) + int(data.get("expires_in", 0)),
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


# ---------------------------
# REPORT: Losses (проигранные сделки)
# ---------------------------
@app.get("/report/losses")
def report_losses():
    """
    Пример:
    /report/losses?subdomain=meawake&date_from=2026-02-01&date_to=2026-02-18
    """
    subdomain = (request.args.get("subdomain") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    if not subdomain:
        return jsonify({"ok": False, "error": "subdomain_required"}), 400
    if not date_from or not date_to:
        return jsonify({"ok": False, "error": "date_from_and_date_to_required"}), 400

    # переводим YYYY-MM-DD в epoch (сек)
    def to_epoch(d: str) -> int:
        dt = datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())

    from_ts = to_epoch(date_from)
    to_ts = to_epoch(date_to) + 86399  # включительно до конца дня

    # В amoCRM сделки: /api/v4/leads
    # Фильтр по updated_at или closed_at зависит от модели.
    # Для MVP берём по updated_at и потом вручную отсеем по status_id "closed lost".
    leads = []
    page = 1

    while True:
        resp = amo_api_get(subdomain, "/api/v4/leads", params={
            "limit": 250,
            "page": page,
            "filter[updated_at][from]": from_ts,
            "filter[updated_at][to]": to_ts,
        })
        chunk = resp.get("_embedded", {}).get("leads", []) or []
        leads.extend(chunk)
        if len(chunk) < 250:
            break
        page += 1
        if page > 20:
            break  # защита от бесконечного цикла

    # Чтобы определить "проиграно", нужно знать статус "закрыто-неуспешно" в воронках.
    # Самый надежный MVP-способ: запросить pipelines и найти status "closed_lost".
    pipelines = amo_api_get(subdomain, "/api/v4/leads/pipelines")
    lost_status_ids = set()

    for p in pipelines.get("_embedded", {}).get("pipelines", []) or []:
        for s in p.get("_embedded", {}).get("statuses", []) or []:
            # В amoCRM у статусов бывает "type": "lost" или "id"/"name"
            if s.get("type") == "lost":
                lost_status_ids.add(s.get("id"))

    lost_leads = []
    total_loss = 0

    for l in leads:
        status_id = l.get("status_id")
        if status_id in lost_status_ids:
            price = int(l.get("price") or 0)
            total_loss += price
            lost_leads.append({
                "id": l.get("id"),
                "name": l.get("name"),
                "price": price,
                "responsible_user_id": l.get("responsible_user_id"),
                "updated_at": l.get("updated_at"),
                "status_id": status_id,
                "pipeline_id": l.get("pipeline_id"),
            })

    result = {
        "ok": True,
        "subdomain": subdomain,
        "date_from": date_from,
        "date_to": date_to,
        "lost_count": len(lost_leads),
        "lost_sum": total_loss,
        "reasons_top": [],  # подключим, когда определим где хранится причина отказа
        "leads": lost_leads[:200],  # ограничим, чтобы не раздувать ответ
    }

    log_event("report_losses_ok", {"subdomain": subdomain, "lost_count": len(lost_leads), "lost_sum": total_loss})
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
