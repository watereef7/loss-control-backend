import os
import json
import time
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# =========================
# Storage (events + tokens)
# =========================
# Чтобы токены не слетали — лучше подключить Render Disk и хранить в /var/data/...
DATA_DIR = os.environ.get("LC_DATA_DIR", "/var/data/loss_control")

EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")
OAUTH_STATE_FILE = os.path.join(DATA_DIR, "oauth_state.json")


def ensure_storage():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        return True
    except Exception:
        return False


def log_event(event_type: str, payload: dict):
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "payload": payload,
    }
    if not ensure_storage():
        return
    try:
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read_last_lines(path: str, n: int = 50):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [line.strip() for line in lines[-n:]]
    except Exception:
        return []


def load_json(path: str, default):
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, obj):
    if not ensure_storage():
        return False
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def load_tokens():
    return load_json(TOKENS_FILE, {})


def save_tokens(tokens: dict):
    return save_json(TOKENS_FILE, tokens)


def load_states():
    return load_json(OAUTH_STATE_FILE, {})


def save_states(states: dict):
    return save_json(OAUTH_STATE_FILE, states)


# =========================
# Telegram lead sender
# =========================
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "").strip()


def tg_send(text: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False, "tg_not_configured"

    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text}, timeout=15)
        ok = (r.status_code == 200)
        return ok, r.text
    except Exception as e:
        return False, str(e)


# =========================
# Basic endpoints
# =========================
@app.get("/")
def index():
    return jsonify(
        {
            "ok": True,
            "service": "loss-control-backend",
            "data_dir": DATA_DIR,
            "endpoints": [
                "/health (GET)",
                "/debug/last (GET)",
                "/debug/tokens (GET)",
                "/widget/ping (POST)",
                "/widget/install (POST)",
                "/oauth/start (GET)",
                "/oauth/redirect (GET)",
                "/oauth/callback (POST)",
                "/report/losses (GET)",
            ],
        }
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/debug/last")
def debug_last():
    return jsonify({"ok": True, "lines": read_last_lines(EVENTS_FILE, 100)})


@app.get("/debug/tokens")
def debug_tokens():
    tokens = load_tokens()
    view = {}
    for sub, t in tokens.items():
        view[sub] = {
            "has_access_token": bool(t.get("access_token")),
            "has_refresh_token": bool(t.get("refresh_token")),
            "expires_at": t.get("expires_at"),
            "saved_at": t.get("saved_at"),
        }
    return jsonify({"ok": True, "storage": DATA_DIR, "subdomains": view})


# =========================
# Widget endpoints
# =========================
@app.post("/widget/ping")
def widget_ping():
    data = request.get_json(silent=True) or {}
    log_event("widget_ping", data)
    return jsonify({"ok": True})


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

    text = (
        "🟦 Новый лид (установка Loss Control)\n"
        f"Аккаунт: {data.get('subdomain')} (account_id={data.get('account_id')})\n"
        f"Пользователь: {data.get('fio')} (user_id={data.get('user_id')})\n"
        f"Email: {data.get('email')}\n"
        f"Телефон: {data.get('phone')}\n"
    )
    ok, resp = tg_send(text)
    log_event("telegram_send", {"ok": ok, "resp": resp})

    return jsonify({"ok": True})


# =========================
# amoCRM OAuth config
# =========================
AMO_CLIENT_ID = os.environ.get("AMO_CLIENT_ID", "").strip()
AMO_CLIENT_SECRET = os.environ.get("AMO_CLIENT_SECRET", "").strip()
AMO_REDIRECT_URL = os.environ.get("AMO_REDIRECT_URL", "").strip()

# Для amocrm.ru:
AMO_OAUTH_BASE = "https://www.amocrm.ru/oauth2"
AMO_AUTHORIZE_URL = "https://www.amocrm.ru/oauth"


def now_ts():
    return int(time.time())


def get_access_token_for(subdomain: str):
    tokens = load_tokens()
    t = tokens.get(subdomain)
    if not t:
        raise RuntimeError(f"no_tokens_for_subdomain:{subdomain}")

    expires_at = int(t.get("expires_at") or 0)
    if expires_at - 60 > now_ts():
        return t["access_token"]

    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": t.get("refresh_token"),
        "redirect_uri": AMO_REDIRECT_URL,
    }
    r = requests.post(f"{AMO_OAUTH_BASE}/access_token", json=payload, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"refresh_failed:{r.status_code}:{r.text}")

    j = r.json()
    t2 = {
        "access_token": j.get("access_token"),
        "refresh_token": j.get("refresh_token"),
        "expires_at": now_ts() + int(j.get("expires_in", 0)),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    tokens[subdomain] = t2
    save_tokens(tokens)
    log_event("token_refreshed", {"subdomain": subdomain})
    return t2["access_token"]


def amo_api_get(subdomain: str, path: str, params: dict | None = None):
    token = get_access_token_for(subdomain)
    url = f"https://{subdomain}.amocrm.ru{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"amo_get_failed:{r.status_code}:{r.text}")
    return r.json()


# =========================
# OAuth flow (post_message)
# =========================
@app.get("/oauth/start")
def oauth_start():
    subdomain = (request.args.get("subdomain") or "").strip()
    if not subdomain:
        return jsonify({"ok": False, "error": "subdomain_required"}), 400

    if not AMO_CLIENT_ID or not AMO_CLIENT_SECRET or not AMO_REDIRECT_URL:
        return jsonify({"ok": False, "error": "oauth_env_not_set"}), 500

    state = secrets.token_urlsafe(16)
    states = load_states()
    states[state] = {"subdomain": subdomain, "ts": now_ts()}
    save_states(states)

    qs = urlencode({"client_id": AMO_CLIENT_ID, "state": state, "mode": "post_message"})
    url = f"{AMO_AUTHORIZE_URL}?{qs}"
    log_event("oauth_start", {"subdomain": subdomain, "state": state})
    return jsonify({"ok": True, "url": url})


@app.get("/oauth/redirect")
def oauth_redirect():
    html = """
<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>Loss Control OAuth</title></head>
<body style="font-family: Arial; padding: 24px;">
<h3>Подключение amoCRM...</h3>
<p>Окно можно закрыть после сообщения об успешном подключении.</p>
<script>
window.addEventListener("message", async function(event) {
  try {
    const data = event.data;
    if (!data || !data.code || !data.state) return;

    const resp = await fetch("/oauth/callback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: data.code, state: data.state, referer: document.referrer })
    });

    const j = await resp.json();
    if (j.ok) {
      document.body.innerHTML = "<h3>✅ Аккаунт подключен</h3><p>Можно закрыть окно.</p>";
    } else {
      document.body.innerHTML = "<h3>❌ Ошибка подключения</h3><pre>" + JSON.stringify(j, null, 2) + "</pre>";
    }
  } catch (e) {
    document.body.innerHTML = "<h3>❌ Ошибка</h3><pre>" + e.toString() + "</pre>";
  }
});
</script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


@app.post("/oauth/callback")
def oauth_callback():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip()
    state = (data.get("state") or "").strip()

    if not code or not state:
        return jsonify({"ok": False, "error": "code_state_required"}), 400

    states = load_states()
    st = states.get(state)
    if not st:
        return jsonify({"ok": False, "error": "bad_state"}), 400

    subdomain = st.get("subdomain")

    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AMO_REDIRECT_URL,
    }

    r = requests.post(f"{AMO_OAUTH_BASE}/access_token", json=payload, timeout=25)
    if r.status_code != 200:
        log_event("oauth_fail", {"status": r.status_code, "text": r.text})
        return jsonify({"ok": False, "error": "token_exchange_failed", "details": r.text}), 400

    j = r.json()
    tokens = load_tokens()
    tokens[subdomain] = {
        "access_token": j.get("access_token"),
        "refresh_token": j.get("refresh_token"),
        "expires_at": now_ts() + int(j.get("expires_in", 0)),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    save_tokens(tokens)

    log_event("oauth_ok", {"subdomain": subdomain, "referer": data.get("referer")})
    return jsonify({"ok": True, "subdomain": subdomain})


# =========================
# Report: losses analytics (MVP)
# =========================
@app.get("/report/losses")
def report_losses():
    try:
        subdomain = (request.args.get("subdomain") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()

        if not subdomain or not date_from or not date_to:
            return jsonify({"ok": False, "error": "subdomain,date_from,date_to_required"}), 400

        dt_from = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
        dt_to = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc)
        ts_from = int(dt_from.timestamp())
        ts_to = int(dt_to.timestamp()) + 86400 - 1

        pipes = amo_api_get(subdomain, "/api/v4/leads/pipelines")
        pipelines = (pipes or {}).get("_embedded", {}).get("pipelines", [])

        status_map = {}
        for p in pipelines:
            for s in (p.get("_embedded", {}).get("statuses") or []):
                status_map[str(s.get("id"))] = {
                    "name": s.get("name"),
                    "pipeline_id": p.get("id"),
                    "pipeline_name": p.get("name"),
                    "type": s.get("type"),
                }

        leads = []
        page = 1
        while True:
            j = amo_api_get(
                subdomain,
                "/api/v4/leads",
                params={
                    "limit": 250,
                    "page": page,
                    "filter[updated_at][from]": ts_from,
                    "filter[updated_at][to]": ts_to,
                },
            )
            batch = (j or {}).get("_embedded", {}).get("leads", [])
            if not batch:
                break
            leads.extend(batch)
            if len(batch) < 250:
                break
            page += 1

        by_reason = {}
        total_lost_sum = 0
        lost_count = 0

        for ld in leads:
            price = int(ld.get("price") or 0)
            status_id = str(ld.get("status_id") or "")
            loss_reason_id = ld.get("loss_reason_id")

            st = status_map.get(status_id, {})
            st_type = (st.get("type") or "").lower()

            is_lost = bool(loss_reason_id) or (st_type == "lost")
            if not is_lost:
                continue

            lost_count += 1
            total_lost_sum += price

            reason_key = str(loss_reason_id) if loss_reason_id else "unknown"
            by_reason.setdefault(reason_key, {"count": 0, "sum": 0})
            by_reason[reason_key]["count"] += 1
            by_reason[reason_key]["sum"] += price

        return jsonify(
            {
                "ok": True,
                "subdomain": subdomain,
                "period": {"from": date_from, "to": date_to},
                "lost": {"count": lost_count, "sum": total_lost_sum},
                "by_reason": by_reason,
                "notes": [
                    "MVP: фильтруем по updated_at. Далее улучшим выборку/фильтры.",
                    "Если токены отсутствуют — пройди /oauth/start?subdomain=.... и проверь /debug/tokens.",
                ],
            }
        )

    except Exception as e:
        log_event("report_error", {"error": str(e)})
        return jsonify(
            {
                "ok": False,
                "error": str(e),
                "hint": "Проверь /debug/tokens — если subdomain пустой, заново пройди /oauth/start?subdomain=....",
            }
        ), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
