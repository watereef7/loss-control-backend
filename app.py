import os
import json
import time
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from flask import Flask, request, jsonify, redirect, Response
from flask_cors import CORS

# -----------------------------
# Config
# -----------------------------
AMO_CLIENT_ID = os.environ.get("AMO_CLIENT_ID", "").strip()
AMO_CLIENT_SECRET = os.environ.get("AMO_CLIENT_SECRET", "").strip()
AMO_REDIRECT_URL = os.environ.get("AMO_REDIRECT_URL", "").strip()

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

# Persistent storage (Render Disk recommended)
DATA_DIR = os.environ.get("DATA_DIR", "/var/data/loss_control").strip() or "/var/data/loss_control"
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")           # per-subdomain tokens
STATES_FILE = os.path.join(DATA_DIR, "oauth_states.json")     # oauth state -> meta
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")          # diagnostics/events

# -----------------------------
# App
# -----------------------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "loss-control-backend/1.0"})

# -----------------------------
# Helpers: storage & logs
# -----------------------------
def _ensure_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass

def log_event(event: str, payload: dict):
    rec = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "payload": payload}
    try:
        _ensure_dir()
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json(path: str, data):
    try:
        _ensure_dir()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False

def _read_last_lines(path: str, limit: int = 50):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        return [ln.rstrip("\n") for ln in lines]
    except Exception:
        return []

# -----------------------------
# Helpers: amo utils
# -----------------------------
def _amo_auth_host():
    # For amocrm.ru accounts authorization host is www.amocrm.ru
    return "https://www.amocrm.ru"

def _amo_base_url(subdomain: str):
    subdomain = (subdomain or "").strip()
    if not subdomain:
        raise ValueError("subdomain_required")
    return f"https://{subdomain}.amocrm.ru"

def _parse_subdomain_from_referer(referer: str):
    # referer like https://meawake.amocrm.ru/...
    if not referer:
        return ""
    try:
        host = referer.split("://", 1)[-1].split("/", 1)[0]
        return host.split(".", 1)[0]
    except Exception:
        return ""

def _require_oauth_env():
    if not AMO_CLIENT_ID or not AMO_CLIENT_SECRET or not AMO_REDIRECT_URL:
        raise RuntimeError("missing_oauth_env: set AMO_CLIENT_ID, AMO_CLIENT_SECRET, AMO_REDIRECT_URL")

def _tokens():
    return _load_json(TOKENS_FILE, {})

def _save_tokens(all_tokens: dict):
    return _save_json(TOKENS_FILE, all_tokens)

def _get_token(subdomain: str):
    return _tokens().get(subdomain)

def _set_token(subdomain: str, token_payload: dict):
    all_t = _tokens()
    all_t[subdomain] = token_payload
    _save_tokens(all_t)

def _is_token_expired(token_payload: dict, skew_sec: int = 60):
    try:
        expires_at = int(token_payload.get("expires_at", 0))
        return time.time() >= (expires_at - skew_sec)
    except Exception:
        return True

def _refresh_token(subdomain: str, token_payload: dict):
    _require_oauth_env()
    refresh_token = token_payload.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("no_refresh_token")
    url = _amo_base_url(subdomain) + "/oauth2/access_token"
    resp = SESSION.post(
        url,
        json={
            "client_id": AMO_CLIENT_ID,
            "client_secret": AMO_CLIENT_SECRET,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "redirect_uri": AMO_REDIRECT_URL,
        },
        timeout=30,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"refresh_failed: {resp.status_code} {resp.text}")
    data = resp.json()
    # amo returns expires_in (seconds)
    expires_at = int(time.time()) + int(data.get("expires_in", 0))
    token_payload = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "expires_at": expires_at,
        "token_type": data.get("token_type", "Bearer"),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _set_token(subdomain, token_payload)
    return token_payload

def _get_valid_token(subdomain: str):
    tok = _get_token(subdomain)
    if not tok:
        raise RuntimeError("not_connected: run /oauth/start and approve access")
    if _is_token_expired(tok):
        tok = _refresh_token(subdomain, tok)
    return tok

def amo_request(subdomain: str, method: str, path: str, params=None):
    tok = _get_valid_token(subdomain)
    base = _amo_base_url(subdomain)
    url = base + path
    headers = {"Authorization": f"Bearer {tok.get('access_token')}"}
    resp = SESSION.request(method, url, headers=headers, params=params, timeout=40)
    return resp

# -----------------------------
# Telegram
# -----------------------------
def send_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "telegram_not_configured"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = SESSION.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=20)
    if resp.status_code >= 400:
        return False, resp.text
    return True, "ok"

# -----------------------------
# Routes
# -----------------------------
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
                "/oauth/status (GET)",
                "/report/losses (GET)",
            ],
        }
    )

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/debug/last")
def debug_last():
    limit = int(request.args.get("limit", "50"))
    limit = max(1, min(500, limit))
    return jsonify({"ok": True, "lines": _read_last_lines(EVENTS_FILE, limit=limit)})

@app.get("/debug/tokens")
def debug_tokens():
    # show minimal info (don’t leak secrets)
    t = _tokens()
    out = {}
    for sub, v in t.items():
        out[sub] = {
            "has_access_token": bool(v.get("access_token")),
            "has_refresh_token": bool(v.get("refresh_token")),
            "expires_at": v.get("expires_at"),
            "updated_at": v.get("updated_at"),
        }
    return jsonify({"ok": True, "tokens": out})

@app.post("/widget/ping")
def widget_ping():
    data = request.get_json(silent=True) or {}
    log_event("ping", data)
    return jsonify({"ok": True})

@app.post("/widget/install")
def widget_install():
    data = request.get_json(silent=True) or {}

    consent = bool(data.get("consent"))
    if not consent:
        log_event("install_rejected_no_consent", data)
        return jsonify({"ok": False, "error": "consent_required"}), 400

    required = ["account_id", "subdomain", "user_id", "fio", "email"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        log_event("install_rejected_missing_fields", {"missing": missing, "data": data})
        return jsonify({"ok": False, "error": "missing_fields", "missing": missing}), 400

    # Send lead to Telegram ONLY after user clicked Save (this endpoint is called from widget onSave)
    msg = (
        "🟦 Loss Control — новая установка\n"
        f"Аккаунт: {data.get('subdomain')} (ID {data.get('account_id')})\n"
        f"Пользователь: {data.get('fio')} (user_id {data.get('user_id')})\n"
        f"Email: {data.get('email')}\n"
        f"Телефон: {data.get('phone') or '-'}\n"
        f"Время: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    ok, info = send_telegram(msg)
    log_event("install", {"data": data, "telegram_ok": ok, "telegram_info": info})
    return jsonify({"ok": True, "telegram_ok": ok})

# -----------------------------
# OAuth connect flow
# -----------------------------
@app.get("/oauth/start")
def oauth_start():
    """
    Returns amoCRM OAuth URL. We use mode=post_message, so amo sends code to redirect_uri and/or postMessage.
    """
    _require_oauth_env()

    # try read subdomain from query or referer
    subdomain = (request.args.get("subdomain") or "").strip()
    if not subdomain:
        subdomain = _parse_subdomain_from_referer(request.headers.get("Referer", ""))

    state = secrets.token_urlsafe(16)
    states = _load_json(STATES_FILE, {})
    states[state] = {"ts": int(time.time()), "subdomain": subdomain}
    _save_json(STATES_FILE, states)

    params = {
        "client_id": AMO_CLIENT_ID,
        "state": state,
        "mode": "post_message",
    }
    url = _amo_auth_host() + "/oauth?" + urlencode(params)
    log_event("oauth_start", {"subdomain": subdomain, "state": state})
    return jsonify({"ok": True, "url": url})

@app.get("/oauth/redirect")
def oauth_redirect():
    """
    redirect_uri endpoint. amo can call it with code & state.
    We'll exchange code to tokens and show simple HTML.
    """
    try:
        _require_oauth_env()
        code = request.args.get("code", "")
        state = request.args.get("state", "")
        referer = request.headers.get("Referer", "")

        states = _load_json(STATES_FILE, {})
        meta = states.get(state) or {}
        subdomain = meta.get("subdomain") or _parse_subdomain_from_referer(referer)

        if not code:
            log_event("oauth_redirect_no_code", {"state": state, "referer": referer})
            return Response("No code", status=400)

        if not subdomain:
            # If we can't detect it - user can pass ?subdomain=...
            subdomain = (request.args.get("subdomain") or "").strip()

        token_url = _amo_base_url(subdomain) + "/oauth2/access_token"
        resp = SESSION.post(
            token_url,
            json={
                "client_id": AMO_CLIENT_ID,
                "client_secret": AMO_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": AMO_REDIRECT_URL,
            },
            timeout=30,
        )
        if resp.status_code >= 400:
            log_event("oauth_exchange_failed", {"subdomain": subdomain, "status": resp.status_code, "body": resp.text})
            return Response("OAuth exchange failed", status=400)

        data = resp.json()
        expires_at = int(time.time()) + int(data.get("expires_in", 0))
        tok = {
            "access_token": data.get("access_token"),
            "refresh_token": data.get("refresh_token"),
            "expires_at": expires_at,
            "token_type": data.get("token_type", "Bearer"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _set_token(subdomain, tok)
        log_event("oauth_ok", {"subdomain": subdomain, "referer": referer})

        html = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Loss Control</title></head>
<body style="font-family: Arial, sans-serif; padding: 24px">
  <h2>✅ Аккаунт подключен</h2>
  <p>Можете закрыть это окно и вернуться в amoCRM.</p>
</body></html>
"""
        return Response(html, mimetype="text/html")
    except Exception as e:
        log_event("oauth_redirect_error", {"error": str(e)})
        return Response("Internal error", status=500)

@app.post("/oauth/callback")
def oauth_callback():
    """
    Optional endpoint if you decide to forward code via JS postMessage from widget.
    For now not required (we use /oauth/redirect flow).
    """
    data = request.get_json(silent=True) or {}
    log_event("oauth_callback", data)
    return jsonify({"ok": True})

@app.get("/oauth/status")
def oauth_status():
    subdomain = (request.args.get("subdomain") or "").strip()
    if not subdomain:
        subdomain = _parse_subdomain_from_referer(request.headers.get("Referer", ""))
    tok = _get_token(subdomain) if subdomain else None
    return jsonify({"ok": True, "subdomain": subdomain, "connected": bool(tok)})

# -----------------------------
# Reports
# -----------------------------
def _date_to_unix_range(date_from: str, date_to: str):
    # date_from / date_to as YYYY-MM-DD in local meaning; convert to UTC range
    try:
        df = datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        dt = datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1) - timedelta(seconds=1)
        return int(df.timestamp()), int(dt.timestamp())
    except Exception:
        raise ValueError("bad_date_format: use YYYY-MM-DD")

def _get_loss_reasons(subdomain: str):
    # returns dict[id] = name
    resp = amo_request(subdomain, "GET", "/api/v4/leads/loss_reasons")
    if resp.status_code >= 400:
        raise RuntimeError(f"loss_reasons_failed: {resp.status_code} {resp.text}")
    data = resp.json()
    items = data.get("_embedded", {}).get("loss_reasons", []) or []
    return {int(it["id"]): it.get("name", "") for it in items if "id" in it}

def _get_pipelines(subdomain: str):
    resp = amo_request(subdomain, "GET", "/api/v4/leads/pipelines")
    if resp.status_code >= 400:
        raise RuntimeError(f"pipelines_failed: {resp.status_code} {resp.text}")
    data = resp.json()
    return data.get("_embedded", {}).get("pipelines", []) or []

def _fetch_lost_leads(subdomain: str, closed_from: int, closed_to: int):
    """
    Fetch lost leads in all pipelines for given closed_at range.
    We first ask pipelines to collect 'lost' statuses, then request leads with filter[statuses] array.
    """
    pipelines = _get_pipelines(subdomain)
    lost_statuses = []
    for p in pipelines:
        for st in (p.get("_embedded", {}).get("statuses", []) or []):
            if st.get("type") == "lost":
                lost_statuses.append({"pipeline_id": p.get("id"), "status_id": st.get("id")})

    if not lost_statuses:
        return []

    # Build filter params for multiple statuses (amo supports filter[statuses][i][pipeline_id]/[status_id])
    params = {
        "limit": 250,
        "filter[closed_at][from]": closed_from,
        "filter[closed_at][to]": closed_to,
    }
    for i, s in enumerate(lost_statuses[:50]):  # sane cap
        params[f"filter[statuses][{i}][pipeline_id]"] = s["pipeline_id"]
        params[f"filter[statuses][{i}][status_id]"] = s["status_id"]

    leads = []
    page = 1
    while True:
        params["page"] = page
        resp = amo_request(subdomain, "GET", "/api/v4/leads", params=params)
        if resp.status_code >= 400:
            raise RuntimeError(f"leads_failed: {resp.status_code} {resp.text}")
        data = resp.json()
        batch = data.get("_embedded", {}).get("leads", []) or []
        leads.extend(batch)

        # pagination: amo returns _links.next
        next_link = (data.get("_links") or {}).get("next")
        if not next_link or not batch:
            break
        page += 1
        if page > 50:
            break
    return leads

@app.get("/report/losses")
def report_losses():
    try:
        subdomain = (request.args.get("subdomain") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        manager_id = (request.args.get("manager_id") or "").strip()

        if not subdomain or not date_from or not date_to:
            return jsonify({"ok": False, "error": "required: subdomain,date_from,date_to"}), 400

        closed_from, closed_to = _date_to_unix_range(date_from, date_to)
        reasons = _get_loss_reasons(subdomain)
        leads = _fetch_lost_leads(subdomain, closed_from, closed_to)

        if manager_id:
            try:
                mid = int(manager_id)
                leads = [l for l in leads if int(l.get("responsible_user_id") or 0) == mid]
            except Exception:
                return jsonify({"ok": False, "error": "manager_id must be int"}), 400

        total = 0
        by_reason = {}
        for l in leads:
            price = int(l.get("price") or 0)
            total += price
            rid = l.get("loss_reason_id")
            rname = reasons.get(int(rid), "Без причины") if rid else "Без причины"
            by_reason[rname] = by_reason.get(rname, 0) + price

        top = sorted(by_reason.items(), key=lambda x: x[1], reverse=True)
        return jsonify(
            {
                "ok": True,
                "subdomain": subdomain,
                "date_from": date_from,
                "date_to": date_to,
                "manager_id": manager_id or None,
                "lost_count": len(leads),
                "lost_amount": total,
                "by_reason": [{"reason": k, "amount": v} for k, v in top],
            }
        )
    except Exception as e:
        log_event("report_losses_error", {"error": str(e)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
