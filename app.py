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
AMO_REDIRECT_URI = (os.environ.get("AMO_REDIRECT_URI") or "").strip()

TG_BOT_TOKEN = (os.environ.get("TG_BOT_TOKEN") or "").strip()
TG_CHAT_ID = (os.environ.get("TG_CHAT_ID") or "").strip()

# amo auth page for RU region
AMO_AUTH_URL = "https://www.amocrm.ru/oauth"

# =========================
# Storage (Render-friendly)
# =========================
BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.environ.get("DATA_DIR", "/var/data/loss_control")
if not os.path.isabs(DATA_DIR):
    DATA_DIR = os.path.join(BASE_DIR, DATA_DIR)

EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")  # by subdomain
STATES_FILE = os.path.join(DATA_DIR, "states.json")  # oauth states mapping

STATE_TTL_SEC = 15 * 60

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


# =========================
# Helpers
# =========================

def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _ensure_data_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, data):
    _ensure_data_dir()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
        return True
    except Exception:
        return False


def log_event(event_type: str, payload: dict):
    record = {"ts": _now_iso(), "event": event_type, "payload": payload}
    _ensure_data_dir()
    try:
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
        # expire
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
    host = host.strip()
    # host can be like: meawake.amocrm.ru
    host = host.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] == "amocrm":
        return parts[0]
    if len(parts) >= 2 and parts[-2].endswith("amocrm"):
        return parts[0]
    # sometimes referer contains just subdomain
    if "." not in host:
        return host
    return parts[0]


def _infer_subdomain_from_request() -> str:
    # 1) explicit query
    sd = (request.args.get("subdomain") or "").strip()
    if sd:
        return sd
    # 2) referer query param from amo
    ref = (request.args.get("referer") or "").strip()
    if ref:
        # ref can be like meawake.amocrm.ru
        return _parse_subdomain_from_host(ref)
    # 3) HTTP Referer header
    hdr = request.headers.get("Referer")
    if hdr:
        try:
            return _parse_subdomain_from_host(urlparse(hdr).hostname or "")
        except Exception:
            pass
    return ""


def _amo_base_url(subdomain: str) -> str:
    """Return base URL like https://<subdomain>.amocrm.ru"""
    sd = (subdomain or "").strip()
    sd = sd.replace("https://", "").replace("http://", "")
    sd = sd.split("/")[0]
    # if user passed full host like meawake.amocrm.ru -> take left part
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

    r = requests.post(url, json=payload, timeout=20)
    if not r.ok:
        raise RuntimeError(f"token_exchange_failed: {r.status_code} {r.text[:300]}")

    data = r.json()
    # normalize with expires_at
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

    r = requests.post(url, json=payload, timeout=20)
    if not r.ok:
        raise RuntimeError(f"token_refresh_failed: {r.status_code} {r.text[:300]}")

    data = r.json()
    expires_in = int(data.get("expires_in", 0) or 0)
    data["expires_at"] = int(time.time()) + max(expires_in - 60, 0)
    data["base_url"] = base
    return data


def _amo_get_access_token(subdomain: str) -> str:
    tok = _tokens_get(subdomain)
    if not tok:
        raise RuntimeError("not_connected: run /oauth/start and approve access")

    # refresh if needed
    if int(tok.get("expires_at", 0)) <= int(time.time()):
        refreshed = _amo_refresh_token(subdomain, tok.get("refresh_token"))
        _tokens_set(subdomain, refreshed)
        tok = refreshed

    access_token = tok.get("access_token")
    if not access_token:
        raise RuntimeError("token_missing_access_token")
    return access_token


def _amo_api_get(subdomain: str, path: str, params=None):
    base = _amo_base_url(subdomain)
    token = _amo_get_access_token(subdomain)

    url = f"{base}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=30)
    if not r.ok:
        raise RuntimeError(f"amo_api_failed: {r.status_code} {r.text[:300]}")
    return r.json()


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
    # returns unix seconds
    try:
        dt = datetime.strptime(date_yyyy_mm_dd, "%Y-%m-%d")
        ts = int(time.mktime(dt.timetuple()))
        if end_of_day:
            ts += 24 * 3600 - 1
        return ts
    except Exception:
        return 0


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
                "/report/losses (GET)",
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
            lines = f.readlines()[-20:]
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
    """Called from widget settings 'Save'.

    We REQUIRE consent=true and fio/email/phone.
    Then send a lead to Telegram.
    """

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


@app.get("/oauth/start")
def oauth_start():
    """Returns amo auth URL. If ?go=1 -> redirects to amo auth page.

    Optionally accept ?subdomain=xxx to bind oauth state to that account.
    """

    if not AMO_CLIENT_ID:
        return (
            jsonify({"ok": False, "error": "missing_env", "details": "AMO_CLIENT_ID"}),
            500,
        )

    subdomain = _infer_subdomain_from_request()

    state = secrets.token_urlsafe(16)
    if subdomain:
        _states_put(state, subdomain)

    # IMPORTANT: for amo RU "mode=post_message" is enough (redirect_uri is taken from integration settings)
    url = f"{AMO_AUTH_URL}?client_id={AMO_CLIENT_ID}&state={state}&mode=post_message"

    if request.args.get("go") == "1":
        return redirect(url)

    return jsonify({"ok": True, "url": url, "state": state, "subdomain": subdomain})


@app.get("/oauth/callback")
@app.post("/oauth/callback")
def oauth_callback():
    """amo redirects here after user approves access."""

    code = (request.args.get("code") or "").strip() or (request.form.get("code") or "").strip()
    state = (request.args.get("state") or "").strip() or (request.form.get("state") or "").strip()

    # resolve subdomain
    subdomain = ""

    st = _states_get(state)
    if st and st.get("subdomain"):
        subdomain = st["subdomain"]

    if not subdomain:
        subdomain = _infer_subdomain_from_request()

    if not code:
        log_event("oauth_fail", {"reason": "no_code", "args": dict(request.args)})
        return (
            jsonify({"ok": False, "error": "no_code", "details": "No code provided"}),
            400,
        )

    if not subdomain:
        log_event("oauth_fail", {"reason": "no_subdomain", "args": dict(request.args)})
        return (
            jsonify({"ok": False, "error": "no_subdomain", "details": "Cannot detect subdomain"}),
            400,
        )

    try:
        tok = _amo_token_exchange(subdomain=subdomain, code=code)
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
        log_event(
            "oauth_error",
            {
                "subdomain": subdomain,
                "error": str(e),
                "args": dict(request.args),
            },
        )
        return (
            jsonify({"ok": False, "error": "internal_error", "details": str(e)}),
            500,
        )


@app.get("/report/losses")
def report_losses():
    """Very first version of analytics.

    Goal for now: prove that OAuth works and we can read leads.
    """

    subdomain = (request.args.get("subdomain") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    if not subdomain:
        return jsonify({"ok": False, "error": "missing_subdomain"}), 400

    # simple range -> unix seconds
    ts_from = _to_ts(date_from) if date_from else 0
    ts_to = _to_ts(date_to, end_of_day=True) if date_to else 0

    try:
        params = {}
        if ts_from:
            params["filter[closed_at][from]"] = ts_from
        if ts_to:
            params["filter[closed_at][to]"] = ts_to

        # NOTE: We do not yet filter only "lost" statuses here.
        # First step: just return closed leads count & sum.
        resp = _amo_api_get(subdomain, "/api/v4/leads", params=params)

        leads = (resp.get("_embedded") or {}).get("leads") or []
        total = len(leads)
        total_price = 0
        for l in leads:
            try:
                total_price += int(l.get("price") or 0)
            except Exception:
                pass

        return jsonify(
            {
                "ok": True,
                "subdomain": subdomain,
                "date_from": date_from,
                "date_to": date_to,
                "closed_leads": total,
                "sum_price": total_price,
                "note": "v1: counts ALL closed leads in range (not only lost yet)",
            }
        )

    except Exception as e:
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
