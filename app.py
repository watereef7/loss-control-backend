
import os
import json
import time
import secrets
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS

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
DEFAULT_LIMIT = 100

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
    r = requests.post(url, json=payload, timeout=25)
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
    r = requests.post(url, json=payload, timeout=25)
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
    r = requests.request(method, url, headers=headers, params=params or {}, json=json_body, timeout=35)
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
    params["limit"] = min(int(limit), 250)  # amo usually allows up to 250 in some endpoints; safe-ish
    while page <= max_pages:
        params["page"] = page
        data = _amo_request(subdomain, "GET", path, params=params)
        embedded = (data.get("_embedded") or {})
        # guess key by path
        key = None
        for k in ("leads", "users", "pipelines", "loss_reasons", "tasks", "events", "notes"):
            if k in embedded:
                key = k
                break
        if not key:
            # fallback: first embedded list
            for k, v in embedded.items():
                if isinstance(v, list):
                    key = k
                    break
        items = embedded.get(key) if key else []
        if items:
            out.extend(items)
        # next?
        links = data.get("_links") or {}
        if "next" not in links:
            break
        page += 1
    return out



def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def _lead_ids_with_current_tasks(subdomain: str, lead_ids: list, stale_days: int) -> set:
    """Return lead IDs that have at least one OPEN task which is not overdue more than stale_days.
    In other words, task.complete_till >= now - stale_days*86400.
    """
    now_ts = int(time.time())
    min_ok = now_ts - int(stale_days) * 86400
    ok = set()
    if not lead_ids:
        return ok

    for chunk in _chunks(list(lead_ids), 200):
        params = {
            "filter[entity_type]": "leads",
            "filter[is_completed]": 0,
            "filter[entity_id][]": chunk,
        }
        tasks = _amo_list_paged(subdomain, "/api/v4/tasks", params=params, limit=250, max_pages=20)
        for t in tasks:
            eid = t.get("entity_id")
            if not eid:
                continue
            ct = int(t.get("complete_till") or 0)
            if ct >= min_ok:
                ok.add(int(eid))
    return ok


def _lead_ids_with_recent_events(subdomain: str, lead_ids: list, from_ts: int) -> set:
    """Return lead IDs that have at least one event with created_at >= from_ts."""
    found = set()
    if not lead_ids:
        return found

    for chunk in _chunks(list(lead_ids), 10):  # amo events API: up to 10 entity_id per request
        params = {
            "filter[created_at][from]": int(from_ts),
            "filter[entity]": "lead",
            "filter[entity_id][]": chunk,
        }
        events = _amo_list_paged(subdomain, "/api/v4/events", params=params, limit=250, max_pages=20)
        for ev in events:
            eid = ev.get("entity_id")
            if eid:
                found.add(int(eid))
    return found

def _tg_send(text: str):
    if not (TG_BOT_TOKEN and TG_CHAT_ID):
        return False
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text}, timeout=15)
        return r.ok
    except Exception:
        return False


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


@app.get("/debug/last")
def debug_last():
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-60:]
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

    text = (
        "🟦 Новый клиент установил Loss Control\n"
        f"subdomain: {data.get('subdomain')}\n"
        f"account_id: {data.get('account_id')}\n"
        f"user_id: {data.get('user_id')}\n\n"
        f"ФИО: {data.get('fio')}\n"
        f"Email: {data.get('email')}\n"
        f"Телефон: {data.get('phone')}\n"
    )
    _tg_send(text)

    return jsonify({"ok": True})


# ---------- OAuth ----------
@app.get("/oauth/start")
def oauth_start():
    if not AMO_CLIENT_ID:
        return jsonify({"ok": False, "error": "missing_env", "details": "AMO_CLIENT_ID"}), 500

    subdomain = _infer_subdomain_from_request()
    state = secrets.token_urlsafe(16)
    if subdomain:
        _states_put(state, subdomain)

    # amo: mode=post_message is typical for marketplace flows; still ends up with redirect_uri + code
    url = f"{AMO_AUTH_URL}?client_id={AMO_CLIENT_ID}&state={state}&mode=post_message"

    if request.args.get("go") == "1":
        return redirect(url)

    return jsonify({"ok": True, "url": url, "state": state, "subdomain": subdomain})


@app.get("/oauth/callback")
@app.post("/oauth/callback")
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
        # Kommo/amo has loss reasons endpoints; in amo RU docs this also exists in Leads section.
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
    - stale deals: open deals with no recent events (>N days) AND no current tasks (or tasks overdue >N days), grouped by manager
    """
    subdomain = (request.args.get("subdomain") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    stale_days = int(request.args.get("stale_days") or "7")
    manager_id = (request.args.get("manager_id") or "").strip()

    if not subdomain:
        return jsonify({"ok": False, "error": "missing_subdomain"}), 400

    ts_from = _to_ts(date_from) if date_from else 0
    ts_to = _to_ts(date_to, end_of_day=True) if date_to else 0
    stale_ts_to = int(time.time()) - stale_days * 86400

    try:
        # dictionaries for names
        users = _amo_list_paged(subdomain, "/api/v4/users", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        user_name = {u.get("id"): u.get("name") for u in users if u.get("id")}

        reasons = _amo_list_paged(subdomain, "/api/v4/leads/loss_reasons", params={}, limit=DEFAULT_LIMIT, max_pages=10)
        reason_name = {r.get("id"): r.get("name") for r in reasons if r.get("id")}

        # -------- closed leads (won/lost) --------
        params_closed = {}
        if ts_from:
            params_closed["filter[closed_at][from]"] = ts_from
        if ts_to:
            params_closed["filter[closed_at][to]"] = ts_to

        # pull closed leads in range, then split to won/lost
        closed = _amo_list_paged(subdomain, "/api/v4/leads", params=params_closed, limit=DEFAULT_LIMIT, max_pages=20)

        lost_leads = []
        won_leads = []
        for l in closed:
            sid = int(l.get("status_id") or 0)
            if manager_id and str(l.get("responsible_user_id")) != manager_id:
                continue
            if sid == 143:
                lost_leads.append(l)
            elif sid == 142:
                won_leads.append(l)

        # -------- stale leads (v2) --------
        # candidate set: deals not closed whose updated_at is older than N days (cheap prefilter)
        params_candidates = {
            "filter[updated_at][to]": stale_ts_to,
        }
        candidates = _amo_list_paged(subdomain, "/api/v4/leads", params=params_candidates, limit=DEFAULT_LIMIT, max_pages=20)

        open_candidates = []
        for l in candidates:
            sid = int(l.get("status_id") or 0)
            if sid in (142, 143):  # closed win/loss
                continue
            if manager_id and str(l.get("responsible_user_id")) != manager_id:
                continue
            open_candidates.append(l)

        lead_ids = [int(l.get("id") or 0) for l in open_candidates if l.get("id")]
        lead_ids_set = set(lead_ids)

        # Tasks rule from user:
        # "нет задач" = нет текущих задач ИЛИ задачи просрочены на N дней
        # We interpret "текущие" as open tasks with complete_till >= now - N days.
        leads_with_current_tasks = _lead_ids_with_current_tasks(subdomain, lead_ids, stale_days)

        # Events rule: no events in last N days
        leads_with_recent_events = _lead_ids_with_recent_events(subdomain, list(lead_ids_set), stale_ts_to)

        stale_ids = lead_ids_set - leads_with_current_tasks - leads_with_recent_events
        stale_leads = [l for l in open_candidates if int(l.get("id") or 0) in stale_ids]

        # group by manager

        def pack_lead(l, kind: str):
            lid = l.get("id")
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
                "days_no_activity": _days_since(int(l.get("updated_at") or 0)),
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
                    "won_count": 0,
                    "won_sum": 0,
                    "won_leads": [],
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

        
        # won aggregation
        for l in won_leads:
            uid = l.get("responsible_user_id")
            key = str(uid)
            pm = per_manager.setdefault(
                key,
                {
                    "manager_id": uid,
                    "manager_name": user_name.get(uid) or str(uid),
                    "won_count": 0,
                    "won_sum": 0,
                    "won_leads": [],
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
            pm["won_count"] += 1
            pm["won_sum"] += price
            pm["won_leads"].append(pack_lead(l, "won"))

# stale aggregation
        for l in stale_leads:
            uid = l.get("responsible_user_id")
            key = str(uid)
            pm = per_manager.setdefault(
                key,
                {
                    "manager_id": uid,
                    "manager_name": user_name.get(uid) or str(uid),
                    "won_count": 0,
                    "won_sum": 0,
                    "won_leads": [],
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
            reasons_list = [
                {"reason": k, "count": v["count"], "sum": v["sum"]}
                for k, v in pm["lost_by_reason"].items()
            ]
            # sort: by sum desc
            reasons_list.sort(key=lambda x: (-x["sum"], -x["count"], x["reason"]))
            pm["lost_by_reason"] = reasons_list
            # sort leads by price desc
            pm.get("won_leads", []).sort(key=lambda x: (-x["price"], x["id"]))
            pm["lost_leads"].sort(key=lambda x: (-x["price"], x["id"]))
            pm["stale_leads"].sort(key=lambda x: (-x["price"], -x["days_no_activity"], x["id"]))
            managers_list.append(pm)

        managers_list.sort(key=lambda x: (-(x["lost_sum"] + x["stale_sum"]), -(x["lost_count"] + x["stale_count"]), x["manager_name"]))

        totals = {
            "won_count": sum(m.get("won_count", 0) for m in managers_list),
            "won_sum": sum(m.get("won_sum", 0) for m in managers_list),
            "lost_count": sum(m["lost_count"] for m in managers_list),
            "lost_sum": sum(m["lost_sum"] for m in managers_list),
            "stale_count": sum(m["stale_count"] for m in managers_list),
            "stale_sum": sum(m["stale_sum"] for m in managers_list),
        }
        totals["total_risk_sum"] = totals["lost_sum"] + totals["stale_sum"]
        totals["risk_open_stale_sum"] = totals["stale_sum"]

        return jsonify(
            {
                "ok": True,
                "subdomain": subdomain,
                "date_from": date_from,
                "date_to": date_to,
                "stale_days": stale_days,
                "manager_id": manager_id or None,
                "totals": totals,
                "managers": managers_list,
                "note": "stale uses: no recent events (>N days) AND no current tasks (or tasks overdue >N days) (v2).",
            }
        )

    except Exception as e:
        log_event("report_error", {"error": str(e)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
