import os
import json
import time
import secrets
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
import uuid
from urllib.parse import urlencode

# =========================
# Config from Environment
# =========================
AMO_CLIENT_ID = (os.environ.get("AMO_CLIENT_ID") or "").strip()
AMO_CLIENT_SECRET = (os.environ.get("AMO_CLIENT_SECRET") or "").strip()
AMO_REDIRECT_URI = (os.environ.get("AMO_REDIRECT_URI") or os.environ.get("AMO_REDIRECT_URL") or "").strip()

# Telegram (accept both naming styles)
TG_BOT_TOKEN = (os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
TG_CHAT_ID = (os.environ.get("TG_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID") or "").strip()

# amo auth page for RU region
AMO_AUTH_URL = "https://www.amocrm.ru/oauth"

# Limits / safeguards (to avoid rate-limit explosions)
DEFAULT_LIMIT = 100
MAX_STALE_ACTIVITY_CHECK = int(os.environ.get("MAX_STALE_ACTIVITY_CHECK") or "200")  # max leads for deep check per request
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT") or "35")
# Event types we consider as 'activity' for stale-deals detection
RELEVANT_EVENT_TYPES = [
  "task_added",
  "task_completed",
  "task_result_added",
  "task_deadline_changed",
  "task_text_changed",
  "task_type_changed",
  "incoming_call",
  "outgoing_call",
  "incoming_chat_message",
  "outgoing_chat_message",
  "entity_direct_message",
  "incoming_sms",
  "outgoing_sms",
  "common_note_added",
  "service_note_added",
  "attachment_note_added",
  "geo_note_added",
  "site_visit_note_added",
  "message_to_cashier_note_added",
  "lead_status_changed",
  "sale_field_changed",
  "name_field_changed",
  "custom_field_value_changed",
  "entity_tag_added",
  "entity_tag_deleted",
  "entity_linked",
  "entity_unlinked",
  "entity_responsible_changed",
  "robot_replied"
]


# =========================
# Storage (Render-friendly)
# =========================
BASE_DIR = os.path.dirname(__file__)

# Use ./data by default (writable). If DATA_DIR is set — use it.
DATA_DIR = (os.environ.get("DATA_DIR") or "").strip()
if not DATA_DIR:
    DATA_DIR = os.path.join(BASE_DIR, "data")
elif not os.path.isabs(DATA_DIR):
    DATA_DIR = os.path.join(BASE_DIR, DATA_DIR)

EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")   # by subdomain
STATES_FILE = os.path.join(DATA_DIR, "states.json")   # oauth states mapping

STATE_TTL_SEC = 15 * 60

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# =========================
# Helpers
# =========================
def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, data):
    _ensure_data_dir()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    return True


def log_event(event_type: str, payload: dict):
    record = {"ts": _now_iso(), "event": event_type, "payload": payload}
    try:
        _ensure_data_dir()
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _states_get(state: str):
    if not state:
        return None
    states = _load_json(STATES_FILE, {})
    item = states.get(state)
    if not item:
        return None
    if int(time.time()) - int(item.get("ts", 0)) > STATE_TTL_SEC:
        try:
            states.pop(state, None)
            _save_json(STATES_FILE, states)
        except Exception:
            pass
        return None
    return item


def _states_put(state: str, subdomain: str):
    states = _load_json(STATES_FILE, {})
    states[state] = {"subdomain": subdomain, "ts": int(time.time())}
    _save_json(STATES_FILE, states)


def _parse_subdomain_from_host(host: str) -> str:
    if not host:
        return ""
    host = host.strip().split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] == "amocrm":
        return parts[0]
    if "." not in host:
        return host
    return parts[0]


def _infer_subdomain_from_request() -> str:
    sd = (request.args.get("subdomain") or "").strip()
    if sd:
        return sd

    ref = (request.args.get("referer") or "").strip()
    if ref:
        return _parse_subdomain_from_host(ref)

    hdr = request.headers.get("Referer")
    if hdr:
        try:
            return _parse_subdomain_from_host(urlparse(hdr).hostname or "")
        except Exception:
            pass

    return ""


def _amo_base_url(subdomain: str) -> str:
    sd = (subdomain or "").strip().replace("https://", "").replace("http://", "")
    sd = sd.split("/")[0]
    if "." in sd:
        sd = sd.split(".")[0]
    return f"https://{sd}.amocrm.ru"


def _tokens_all():
    return _load_json(TOKENS_FILE, {})


def _tokens_get(subdomain: str):
    return _tokens_all().get(subdomain)


def _tokens_set(subdomain: str, token_payload: dict):
    all_tokens = _tokens_all()
    all_tokens[subdomain] = token_payload
    _save_json(TOKENS_FILE, all_tokens)


def _amo_token_exchange(subdomain: str, code: str):
    if not (AMO_CLIENT_ID and AMO_CLIENT_SECRET and AMO_REDIRECT_URI):
        raise RuntimeError("missing_env: AMO_CLIENT_ID/SECRET/REDIRECT_URI")

    base = _amo_base_url(subdomain)
    url = f"{base}/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AMO_REDIRECT_URI,
    }
    r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"token_exchange_failed: {r.status_code} {r.text[:400]}")

    data = r.json()
    expires_in = int(data.get("expires_in", 0) or 0)
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    data["base_url"] = base
    return data


def _amo_refresh_token(subdomain: str, refresh_token: str):
    base = _amo_base_url(subdomain)
    url = f"{base}/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": AMO_REDIRECT_URI,
    }
    r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
    if not r.ok:
        raise RuntimeError(f"token_refresh_failed: {r.status_code} {r.text[:400]}")

    data = r.json()
    expires_in = int(data.get("expires_in", 0) or 0)
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    data["base_url"] = base
    return data


def _amo_get_access_token(subdomain: str) -> str:
    tok = _tokens_get(subdomain)
    if not tok:
        raise RuntimeError("not_connected: run /oauth/start and approve access")

    if int(tok.get("expires_at", 0)) <= int(time.time()):
        refreshed = _amo_refresh_token(subdomain, tok.get("refresh_token"))
        _tokens_set(subdomain, refreshed)
        tok = refreshed

    access_token = tok.get("access_token")
    if not access_token:
        raise RuntimeError("token_missing_access_token")
    return access_token


def _amo_request(subdomain: str, method: str, path: str, params=None, json_body=None):
    base = _amo_base_url(subdomain)
    token = _amo_get_access_token(subdomain)
    url = f"{base}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.request(
        method,
        url,
        headers=headers,
        params=params or {},
        json=json_body,
        timeout=HTTP_TIMEOUT,
    )
    if not r.ok:
        raise RuntimeError(f"amo_api_failed: {r.status_code} {r.text[:500]}")
    if r.status_code == 204:
        return {}
    return r.json() if r.text else {}


def _amo_list_paged(subdomain: str, path: str, params=None, limit=DEFAULT_LIMIT, max_pages=50):
    """Collect pages until no next link. Works with amo HAL responses."""
    out = []
    page = 1
    params = dict(params or {})
    params["limit"] = min(int(limit), 250)
    while page <= max_pages:
        params["page"] = page
        data = _amo_request(subdomain, "GET", path, params=params)
        embedded = (data.get("_embedded") or {})
        key = None
        for k in ("leads", "users", "pipelines", "loss_reasons", "tasks", "notes"):
            if k in embedded:
                key = k
                break
        if not key:
            for k, v in embedded.items():
                if isinstance(v, list):
                    key = k
                    break
        items = embedded.get(key) if key else []
        if items:
            out.extend(items)
        links = data.get("_links") or {}
        if "next" not in links:
            break
        page += 1
    return out


def _tg_send(text: str):
    if not (TG_BOT_TOKEN and TG_CHAT_ID):
        return {"ok": False, "error": "TG_BOT_TOKEN or TG_CHAT_ID is missing"}
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text}, timeout=15)
        try:
            j = r.json()
        except Exception:
            j = {"raw": r.text}
        return {"ok": bool(r.ok and j.get("ok", True)), "status": r.status_code, "response": j}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def send_telegram_message(text: str):
    """Backwards-compatible helper used by install hooks."""
    res = _tg_send(text)
    if not res.get("ok"):
        raise RuntimeError(str(res))
    return res

def _to_ts(date_yyyy_mm_dd: str, end_of_day: bool = False) -> int:
    try:
        dt = datetime.strptime(date_yyyy_mm_dd, "%Y-%m-%d")
        ts = int(time.mktime(dt.timetuple()))
        if end_of_day:
            ts += 24 * 3600 - 1
        return ts
    except Exception:
        return 0


def _days_since(ts: int) -> int:
    if not ts:
        return 0
    return max(0, int((int(time.time()) - int(ts)) / 86400))


def _env_mask(v: str) -> str:
    if not v:
        return ""
    v = str(v)
    if len(v) <= 6:
        return "***"
    return v[:3] + "***" + v[-2:]


# -------- Activity helpers (stale logic v2) --------
def _lead_has_open_tasks(subdomain: str, lead_id: int) -> bool:
    """True if there is at least one unfinished task attached to the lead."""
    try:
        params = {
            "filter[entity_type]": "leads",
            "filter[entity_id]": int(lead_id),
            "filter[is_completed]": 0,
            "limit": 1,
        }
        data = _amo_request(subdomain, "GET", "/api/v4/tasks", params=params)
        tasks = ((data.get("_embedded") or {}).get("tasks") or [])
        return len(tasks) > 0
    except Exception:
        # if tasks api fails, we prefer NOT to mark lead stale
        return True


def _lead_last_task_ts(subdomain: str, lead_id: int) -> int:
    """Returns timestamp (seconds) of the most recently updated task for the lead, or 0."""
    try:
        params = {
            "filter[entity_type]": "leads",
            "filter[entity_id]": int(lead_id),
            "limit": 1,
            "order[updated_at]": "desc",
        }
        data = _amo_request(subdomain, "GET", "/api/v4/tasks", params=params)
        tasks = ((data.get("_embedded") or {}).get("tasks") or [])
        if not tasks:
            return 0
        t = tasks[0] or {}
        return int(t.get("updated_at") or t.get("created_at") or 0)
    except Exception:
        return 0


def _lead_last_note_ts(subdomain: str, lead_id: int) -> int:
    """Returns timestamp (seconds) of the most recent note in the lead, or 0."""
    try:
        # Notes list supports ordering by updated_at.
        params = {"limit": 1, "order[updated_at]": "desc"}
        data = _amo_request(subdomain, "GET", f"/api/v4/leads/{int(lead_id)}/notes", params=params)
        notes = ((data.get("_embedded") or {}).get("notes") or [])
        if not notes:
            return 0
        n = notes[0] or {}
        return int(n.get("updated_at") or n.get("created_at") or 0)
    except Exception:
        return 0

def _lead_last_event_ts(subdomain: str, lead_id: int) -> int:
    """Returns timestamp (seconds) of the most recent relevant event for the lead, or 0.

    We use Events API with a filter by entity + entity_id and a shortlist of event types
    that usually represent real "activity" in the lead timeline.
    """
    try:
        params = {
            "limit": 1,
            "filter[entity]": "lead",
            "filter[entity_id][]": [int(lead_id)],
            "filter[type][]": RELEVANT_EVENT_TYPES,
        }
        data = _amo_request(subdomain, "GET", "/api/v4/events", params=params)
        events = ((data.get("_embedded") or {}).get("events") or [])
        if not events:
            return 0
        e = events[0] or {}
        return int(e.get("created_at") or 0)
    except Exception:
        return 0




def _lead_last_activity_ts(subdomain: str, lead: dict) -> int:
    """
    We treat 'activity' as max of:
    - last note created_at
    - last task updated_at/created_at
    - lead.updated_at (fallback)
    """
    lead_id = int(lead.get("id") or 0)
    ts = int(lead.get("updated_at") or 0)

    lt = _lead_last_task_ts(subdomain, lead_id)
    ln = _lead_last_note_ts(subdomain, lead_id)

    return max(ts, lt, ln)


# =========================
# Routes
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
                "/debug/env (GET)",
                "/debug/tg_test (POST)",
                "/widget/ping (POST)",
                "/widget/install (POST)",
                "/oauth/start (GET)",
                "/oauth/callback (GET/POST)",
                "/api/users (GET)",
                "/api/loss_reasons (GET)",
                "/api/lead/set_loss_reason (POST)",
                "/report/dashboard (GET)",
            ],
        }
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})


# 1x1 transparent GIF (CORS-free install tracking)
GIF_1x1 = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)

@app.get("/widget/install.gif")
def widget_install_gif():
    """
    CORS-free install tracking via <img src="...">.
    Sends Telegram notification best-effort and returns 1x1 gif.
    """
    subdomain = (request.args.get("subdomain") or "").strip()
    contact_name = (request.args.get("name") or "").strip()
    contact_email = (request.args.get("email") or "").strip()
    contact_phone = (request.args.get("phone") or "").strip()
    backend_url = (request.args.get("backend_url") or "").strip()
    payload = {
        "subdomain": subdomain,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "contact_phone": contact_phone,
        "backend_url": backend_url,
        "ts": int(time.time()),
    }
    log_event("install_gif", payload)
    try:
        msg = (
            "✅ Установка виджета 'Контроль потерь'\n"
            f"Subdomain: {subdomain or '-'}\n"
            f"ФИО: {contact_name or '-'}\n"
            f"Email: {contact_email or '-'}\n"
            f"Телефон: {contact_phone or '-'}\n"
            f"Backend URL: {backend_url or '-'}"
        )
        send_telegram_message(msg)
    except Exception as e:
        log_event("install_gif_tg_error", {"error": str(e)})

    from flask import Response
    return Response(GIF_1x1, mimetype="image/gif")


@app.get("/debug/last")
def debug_last():
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-120:]
        return jsonify({"ok": True, "lines": [l.strip() for l in lines]})
    except Exception:
        return jsonify({"ok": True, "lines": []})


@app.get("/debug/tokens")
def debug_tokens():
    all_tokens = _tokens_all()
    connected = []
    for sd, tok in all_tokens.items():
        connected.append(
            {
                "subdomain": sd,
                "has_access_token": bool(tok.get("access_token")),
                "expires_at": tok.get("expires_at"),
            }
        )
    return jsonify({"ok": True, "connected": connected})


@app.get("/debug/env")
def debug_env():
    # Helpful for widget settings diagnostics (do NOT expose full secrets)
    return jsonify(
        {
            "ok": True,
            "has_amo_client_id": bool(AMO_CLIENT_ID),
            "has_amo_client_secret": bool(AMO_CLIENT_SECRET),
            "has_amo_redirect_uri": bool(AMO_REDIRECT_URI),
            "has_tg_bot_token": bool(TG_BOT_TOKEN),
            "has_tg_chat_id": bool(TG_CHAT_ID),
            "amo_client_id_masked": _env_mask(AMO_CLIENT_ID),
            "amo_redirect_uri": AMO_REDIRECT_URI,
            "tg_chat_id": TG_CHAT_ID,
            "max_stale_activity_check": MAX_STALE_ACTIVITY_CHECK,
        }
    )


@app.post("/debug/tg_test")
def debug_tg_test():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip() or "✅ TG test from Loss Control backend"
    ok = _tg_send(text)
    return jsonify({"ok": ok})
@app.get("/debug/tg")
def debug_tg():
    """Send test message to Telegram and return full response."""
    res = _tg_send("🧪 TG test from loss-control backend")
    return jsonify(res)




@app.post("/widget/ping")
def widget_ping():
    data = request.get_json(silent=True) or {}
    log_event("ping", data)
    return jsonify({"ok": True, "received": data})


@app.post("/widget/install")
def widget_install():
    """
    Called by widget on Save (optional). Should NEVER hard-fail because of missing consent/fields.
    Returns JSON.
    """
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    # Normalize fields
    subdomain = (data.get("subdomain") or "").strip()
    contact_name = (data.get("contact_name") or data.get("name") or "").strip()
    contact_email = (data.get("contact_email") or data.get("email") or "").strip()
    contact_phone = (data.get("contact_phone") or data.get("phone") or "").strip()
    backend_url = (data.get("backend_url") or "").strip()

    payload = {
        "subdomain": subdomain,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "contact_phone": contact_phone,
        "backend_url": backend_url,
        "ts": int(time.time()),
    }
    log_event("install", payload)

    # Telegram notify (best-effort)
    try:
        msg = (
            "✅ Установка виджета 'Контроль потерь'\n"
            f"Subdomain: {subdomain or '-'}\n"
            f"ФИО: {contact_name or '-'}\n"
            f"Email: {contact_email or '-'}\n"
            f"Телефон: {contact_phone or '-'}\n"
            f"Backend URL: {backend_url or '-'}"
        )
        send_telegram_message(msg)
    except Exception as e:
        log_event("install_tg_error", {"error": str(e)})

    return jsonify({"ok": True})



@app.get("/oauth/start")
def oauth_start():
    """
    Redirect user to amoCRM OAuth screen.
    Opens amoCRM popup authorization page.
    """
    try:
        subdomain = (request.args.get("subdomain") or "").strip()
        if not subdomain:
            return jsonify({"ok": False, "error": "subdomain is required"}), 400

        if not AMO_CLIENT_ID:
            return jsonify({"ok": False, "error": "AMO_CLIENT_ID is missing on server"}), 500

        nonce = uuid.uuid4().hex
        state = f"{subdomain}:{nonce}"

        # log for debugging
        log_event("oauth_start", {"subdomain": subdomain, "state": state})

        url = "https://www.amocrm.ru/oauth"
        params = {"client_id": AMO_CLIENT_ID, "state": state, "mode": "popup"}
        return redirect(url + "?" + urlencode(params))
    except Exception as e:
        log_event("oauth_start_error", {"error": str(e)})
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/oauth/callback", methods=["GET","POST"])
def oauth_callback():
    code = (request.args.get("code") or "").strip() or (request.form.get("code") or "").strip()
    state = (request.args.get("state") or "").strip() or (request.form.get("state") or "").strip()

    subdomain = ""
    st = _states_get(state)
    if st and st.get("subdomain"):
        subdomain = st["subdomain"]

    if not subdomain:
        subdomain = _infer_subdomain_from_request()

    if not code:
        log_event("oauth_fail", {"reason": "no_code", "args": dict(request.args)})
        return jsonify({"ok": False, "error": "no_code"}), 400

    if not subdomain:
        log_event("oauth_fail", {"reason": "no_subdomain", "args": dict(request.args)})
        return jsonify({"ok": False, "error": "no_subdomain"}), 400

    try:
        tok = _amo_token_exchange(subdomain, code)
        _tokens_set(subdomain, tok)
        log_event("oauth_ok", {"subdomain": subdomain, "referer": request.args.get("referer")})
        return (
            "<html><body style='font-family:Arial'>"
            "<h2>Аккаунт подключен ✅</h2>"
            "Можно закрыть окно.</body></html>",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    except Exception as e:
        log_event("oauth_error", {"subdomain": subdomain, "error": str(e), "args": dict(request.args)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


# ---------- API helpers for widget ----------
@app.get("/api/users")
def api_users():
    subdomain = (request.args.get("subdomain") or "").strip()
    if not subdomain:
        return jsonify({"ok": False, "error": "missing_subdomain"}), 400

    try:
        users = _amo_list_paged(subdomain, "/api/v4/users", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        simplified = [{"id": u.get("id"), "name": u.get("name")} for u in users if u.get("id")]
        return jsonify({"ok": True, "users": simplified})
    except Exception as e:
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


@app.get("/api/loss_reasons")
def api_loss_reasons():
    subdomain = (request.args.get("subdomain") or "").strip()
    if not subdomain:
        return jsonify({"ok": False, "error": "missing_subdomain"}), 400

    try:
        reasons = _amo_list_paged(subdomain, "/api/v4/leads/loss_reasons", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        simplified = [{"id": r.get("id"), "name": r.get("name")} for r in reasons if r.get("id")]
        return jsonify({"ok": True, "reasons": simplified})
    except Exception as e:
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


@app.post("/api/lead/set_loss_reason")
def api_set_loss_reason():
    data = request.get_json(silent=True) or {}
    subdomain = (data.get("subdomain") or "").strip()
    lead_id = data.get("lead_id")
    loss_reason_id = data.get("loss_reason_id")

    if not subdomain or not lead_id or not loss_reason_id:
        return jsonify({"ok": False, "error": "missing_fields", "required": ["subdomain", "lead_id", "loss_reason_id"]}), 400

    try:
        body = {"loss_reason_id": int(loss_reason_id)}
        _amo_request(subdomain, "PATCH", f"/api/v4/leads/{int(lead_id)}", json_body=body)
        log_event("lead_loss_reason_set", {"subdomain": subdomain, "lead_id": lead_id, "loss_reason_id": loss_reason_id})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


# ---------- Reports ----------
@app.get("/report/dashboard")
def report_dashboard():
    """
    Returns:
    - lost deals (status_id=143) for date range, grouped by manager and reason
    - stale deals (risk): NOT closed, NO open tasks, and NO notes/tasks activity within N days
    """
    subdomain = (request.args.get("subdomain") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    stale_days = int(request.args.get("stale_days") or "7")
    manager_id = (request.args.get("manager_id") or "").strip()
    pipeline_id = (request.args.get("pipeline_id") or "").strip()

    if not subdomain:
        return jsonify({"ok": False, "error": "missing_subdomain"}), 400

    ts_from = _to_ts(date_from) if date_from else 0
    ts_to = _to_ts(date_to, end_of_day=True) if date_to else 0
    stale_ts_cutoff = int(time.time()) - stale_days * 86400

    warnings = []

    try:
        # dictionaries for names
        users = _amo_list_paged(subdomain, "/api/v4/users", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        user_name = {u.get("id"): u.get("name") for u in users if u.get("id")}

        reasons = _amo_list_paged(subdomain, "/api/v4/leads/loss_reasons", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        reason_name = {r.get("id"): r.get("name") for r in reasons if r.get("id")}

        # -------- lost leads --------
        params_lost = {}
        if ts_from:
            params_lost["filter[closed_at][from]"] = ts_from
        if ts_to:
            params_lost["filter[closed_at][to]"] = ts_to

        closed = _amo_list_paged(subdomain, "/api/v4/leads", params=params_lost, limit=DEFAULT_LIMIT, max_pages=20)

        lost_leads = []
        for l in closed:
            if int(l.get("status_id") or 0) != 143:
                continue
            if manager_id and str(l.get("responsible_user_id")) != manager_id:
                continue
            if pipeline_id and str(l.get("pipeline_id")) != pipeline_id:
                continue
            lost_leads.append(l)

        # -------- stale candidates --------
        # 1) cheap prefilter: updated_at <= cutoff (same as v1), then we do deep check
        params_stale_prefilter = {"filter[updated_at][to]": stale_ts_cutoff}
        maybe_stale = _amo_list_paged(subdomain, "/api/v4/leads", params=params_stale_prefilter, limit=DEFAULT_LIMIT, max_pages=20)

        candidates = []
        for l in maybe_stale:
            sid = int(l.get("status_id") or 0)
            if sid in (142, 143):  # closed win/loss
                continue
            if manager_id and str(l.get("responsible_user_id")) != manager_id:
                continue
            if pipeline_id and str(l.get("pipeline_id")) != pipeline_id:
                continue
            candidates.append(l)

        # 2) deep check: "нет задач + нет активностей (notes/tasks) > N дней"
        stale_leads = []
        deep = candidates[:MAX_STALE_ACTIVITY_CHECK]
        if len(candidates) > MAX_STALE_ACTIVITY_CHECK:
            warnings.append(
                f"Слишком много потенциально зависших сделок ({len(candidates)}). "
                f"Для точной проверки задач/заметок обработано только первые {MAX_STALE_ACTIVITY_CHECK}. "
                f"Увеличьте MAX_STALE_ACTIVITY_CHECK в Render env, если нужно."
            )

        for l in deep:
            lid = int(l.get("id") or 0)
            # If open tasks exist => NOT stale
            if _lead_has_open_tasks(subdomain, lid):
                continue

            last_basic = _lead_last_activity_ts(subdomain, l)
            if last_basic and last_basic > stale_ts_cutoff:
                continue

            # Extra check: also treat Events as activity (calls/chat/sms/notes/tasks/etc.)
            last_evt = _lead_last_event_ts(subdomain, lid)
            last_act = max(int(last_basic or 0), int(last_evt or 0))

            if last_act and last_act > stale_ts_cutoff:
                continue

            # stale
            l["_lc_last_activity_ts"] = last_act
            stale_leads.append(l)

        # group by manager
        def pack_lead(l, kind: str):
            lid = l.get("id")
            last_act = int(l.get("_lc_last_activity_ts") or l.get("updated_at") or 0)
            return {
                "id": lid,
                "name": l.get("name") or f"Сделка #{lid}",
                "price": int(l.get("price") or 0),
                "responsible_user_id": l.get("responsible_user_id"),
                "responsible_name": user_name.get(l.get("responsible_user_id")) or str(l.get("responsible_user_id")),
                "status_id": l.get("status_id"),
                "pipeline_id": l.get("pipeline_id"),
                "loss_reason_id": l.get("loss_reason_id"),
                "loss_reason": reason_name.get(l.get("loss_reason_id"), "—") if kind == "lost" else None,
                "updated_at": l.get("updated_at"),
                "last_activity_ts": last_act,
                "days_no_activity": _days_since(last_act),
                "url": f"{_amo_base_url(subdomain)}/leads/detail/{lid}",
            }

        per_manager = {}

        # lost aggregation
        for l in lost_leads:
            uid = l.get("responsible_user_id")
            key = str(uid)
            pm = per_manager.setdefault(
                key,
                {
                    "manager_id": uid,
                    "manager_name": user_name.get(uid) or str(uid),
                    "lost_count": 0,
                    "lost_sum": 0,
                    "lost_by_reason": {},  # reason_name -> {count,sum}
                    "lost_leads": [],
                    "stale_count": 0,
                    "stale_sum": 0,
                    "stale_leads": [],
                },
            )
            price = int(l.get("price") or 0)
            pm["lost_count"] += 1
            pm["lost_sum"] += price
            rname = reason_name.get(l.get("loss_reason_id"), "Без причины")
            rb = pm["lost_by_reason"].setdefault(rname, {"count": 0, "sum": 0})
            rb["count"] += 1
            rb["sum"] += price
            pm["lost_leads"].append(pack_lead(l, "lost"))

        # stale aggregation
        for l in stale_leads:
            uid = l.get("responsible_user_id")
            key = str(uid)
            pm = per_manager.setdefault(
                key,
                {
                    "manager_id": uid,
                    "manager_name": user_name.get(uid) or str(uid),
                    "lost_count": 0,
                    "lost_sum": 0,
                    "lost_by_reason": {},
                    "lost_leads": [],
                    "stale_count": 0,
                    "stale_sum": 0,
                    "stale_leads": [],
                },
            )
            price = int(l.get("price") or 0)
            pm["stale_count"] += 1
            pm["stale_sum"] += price
            pm["stale_leads"].append(pack_lead(l, "stale"))

        # format lost_by_reason to list
        managers_list = []
        for pm in per_manager.values():
            reasons_list = [{"reason": k, "count": v["count"], "sum": v["sum"]} for k, v in pm["lost_by_reason"].items()]
            reasons_list.sort(key=lambda x: (-x["sum"], -x["count"], x["reason"]))
            pm["lost_by_reason"] = reasons_list
            pm["lost_leads"].sort(key=lambda x: (-x["price"], x["id"]))
            pm["stale_leads"].sort(key=lambda x: (-x["price"], -x["days_no_activity"], x["id"]))
            managers_list.append(pm)

        managers_list.sort(
            key=lambda x: (
                -(x["lost_sum"] + x["stale_sum"]),
                -(x["lost_count"] + x["stale_count"]),
                x["manager_name"],
            )
        )

        totals = {
            "lost_count": sum(m["lost_count"] for m in managers_list),
            "lost_sum": sum(m["lost_sum"] for m in managers_list),
            "stale_count": sum(m["stale_count"] for m in managers_list),
            "stale_sum": sum(m["stale_sum"] for m in managers_list),
        }
        totals["total_risk_sum"] = totals["lost_sum"] + totals["stale_sum"]

        return jsonify(
            {
                "ok": True,
                "subdomain": subdomain,
                "date_from": date_from,
                "date_to": date_to,
                "stale_days": stale_days,
                "manager_id": manager_id or None,
                "pipeline_id": pipeline_id or None,
                "totals": totals,
                "managers": managers_list,
                "warnings": warnings,
                "note": "stale=v2: no open tasks + no open tasks + no notes/tasks/events activity within N days; prefilter by lead.updated_at.",
            }
        )

    except Exception as e:
        log_event("report_error", {"error": str(e)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
