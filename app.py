import os
import json
import time
import hmac
import hashlib
import secrets
from datetime import datetime
from urllib.parse import urlencode

import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# ----------------------------
# Config (env)
# ----------------------------
AMO_CLIENT_ID = (os.environ.get("AMO_CLIENT_ID") or "").strip()
AMO_CLIENT_SECRET = (os.environ.get("AMO_CLIENT_SECRET") or "").strip()

# People often name it differently. Support both.
AMO_REDIRECT_URI = (os.environ.get("AMO_REDIRECT_URI") or os.environ.get("AMO_REDIRECT_URL") or "").strip()

# Telegram (support both naming styles)
TG_BOT_TOKEN = (os.environ.get("TG_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
TG_CHAT_ID = (os.environ.get("TG_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID") or "").strip()

# Optional: secret for signing cookies / state (can be empty; we still work)
APP_SECRET = (os.environ.get("APP_SECRET") or "").strip()

# ----------------------------
# Storage paths
# ----------------------------
def _pick_data_dir() -> str:
    """
    Render: writable only in /tmp unless you attached a persistent disk (often mounted at /var/data).
    We'll prefer /var/data/loss_control if writable, else fallback to /tmp/loss_control.
    """
    preferred = "/var/data/loss_control"
    fallback = "/tmp/loss_control"
    for path in (preferred, fallback):
        try:
            os.makedirs(path, exist_ok=True)
            test = os.path.join(path, ".write_test")
            with open(test, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test)
            return path
        except Exception:
            continue
    # last resort: current dir
    return os.path.join(os.path.dirname(__file__), "data")

DATA_DIR = _pick_data_dir()
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")   # {subdomain: {...tokens...}}
STATES_FILE = os.path.join(DATA_DIR, "states.json")   # {state: {...}}

# In-memory fallbacks (if disk isn't writable for some reason)
_MEM_TOKENS = {}
_MEM_STATES = {}

# ----------------------------
# App
# ----------------------------
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


# ----------------------------
# Helpers
# ----------------------------
def log_event(event_type: str, payload: dict):
    rec = {"ts": datetime.utcnow().isoformat() + "Z", "event": event_type, "payload": payload}
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # Don't break API because of FS issues
        pass


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, data):
    # atomic-ish save
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _states_get():
    # prefer disk, fallback mem
    data = _load_json(STATES_FILE, None)
    if isinstance(data, dict):
        return data
    return dict(_MEM_STATES)


def _states_set(data: dict):
    # try disk, fallback mem
    try:
        _save_json(STATES_FILE, data)
    except Exception:
        _MEM_STATES.clear()
        _MEM_STATES.update(data)


def _tokens_get():
    data = _load_json(TOKENS_FILE, None)
    if isinstance(data, dict):
        return data
    return dict(_MEM_TOKENS)


def _tokens_set(data: dict):
    try:
        _save_json(TOKENS_FILE, data)
    except Exception:
        _MEM_TOKENS.clear()
        _MEM_TOKENS.update(data)


def _amo_auth_host():
    # For your case (amocrm.ru) this is correct.
    return "https://www.amocrm.ru"


def _require_oauth_env():
    missing = []
    if not AMO_CLIENT_ID:
        missing.append("AMO_CLIENT_ID")
    if not AMO_CLIENT_SECRET:
        missing.append("AMO_CLIENT_SECRET")
    if not AMO_REDIRECT_URI:
        missing.append("AMO_REDIRECT_URI (or AMO_REDIRECT_URL)")
    return missing


def _parse_subdomain_from_referer(referer: str) -> str:
    # Example: https://meawake.amocrm.ru/...
    try:
        if not referer:
            return ""
        host = referer.split("//", 1)[-1].split("/", 1)[0]
        if host.endswith(".amocrm.ru"):
            return host.split(".")[0]
        return ""
    except Exception:
        return ""


def _tg_send(text: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return False, "tg_not_configured"
    try:
        url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text}, timeout=15)
        ok = bool(r.ok)
        return ok, r.text if not ok else "ok"
    except Exception as e:
        return False, str(e)


def _amo_token_exchange(code: str) -> dict:
    """
    Exchange authorization code to access/refresh tokens.
    """
    url = _amo_auth_host() + "/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AMO_REDIRECT_URI,
    }
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()


def _amo_refresh(refresh_token: str) -> dict:
    url = _amo_auth_host() + "/oauth2/access_token"
    payload = {
        "client_id": AMO_CLIENT_ID,
        "client_secret": AMO_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "redirect_uri": AMO_REDIRECT_URI,
    }
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()


def _amo_api_get(subdomain: str, path: str, access_token: str):
    # amo API base
    base = f"https://{subdomain}.amocrm.ru"
    r = requests.get(base + path, headers={"Authorization": f"Bearer {access_token}"}, timeout=25)
    r.raise_for_status()
    return r.json()


def _get_valid_token(subdomain: str) -> str:
    tokens = _tokens_get()
    t = tokens.get(subdomain)
    if not t:
        raise RuntimeError("not_connected: run /oauth/start and approve access")

    # If token still valid (with small buffer)
    now = int(time.time())
    expires_at = int(t.get("expires_at", 0))
    if expires_at - 60 > now and t.get("access_token"):
        return t["access_token"]

    # refresh
    refreshed = _amo_refresh(t.get("refresh_token", ""))
    new = {
        "access_token": refreshed.get("access_token", ""),
        "refresh_token": refreshed.get("refresh_token", ""),
        "expires_at": now + int(refreshed.get("expires_in", 0)),
        "token_type": refreshed.get("token_type", ""),
        "scope": refreshed.get("scope", ""),
        "updated_at": now,
    }
    tokens[subdomain] = new
    _tokens_set(tokens)
    log_event("oauth_refresh_ok", {"subdomain": subdomain})
    return new["access_token"]


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def index():
    return jsonify(
        {
            "ok": True,
            "service": "loss-control-backend",
            "data_dir": DATA_DIR,
            "endpoints": [
                "/health (GET)",
                "/debug/env (GET)",
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


@app.get("/debug/env")
def debug_env():
    # Show only presence (not secret values)
    def present(v): return bool(v)

    return jsonify(
        {
            "ok": True,
            "data_dir": DATA_DIR,
            "env_present": {
                "AMO_CLIENT_ID": present(AMO_CLIENT_ID),
                "AMO_CLIENT_SECRET": present(AMO_CLIENT_SECRET),
                "AMO_REDIRECT_URI": present(AMO_REDIRECT_URI),
                "TG_BOT_TOKEN": present(TG_BOT_TOKEN),
                "TG_CHAT_ID": present(TG_CHAT_ID),
            },
        }
    )


@app.get("/debug/last")
def debug_last():
    try:
        if not os.path.exists(EVENTS_FILE):
            return jsonify({"ok": True, "lines": []})
        with open(EVENTS_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            # read last ~16kb
            f.seek(max(size - 16384, 0), os.SEEK_SET)
            chunk = f.read().decode("utf-8", errors="ignore")
        lines = [ln for ln in chunk.splitlines() if ln.strip()][-20:]
        return jsonify({"ok": True, "lines": lines})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/debug/tokens")
def debug_tokens():
    # Do not expose tokens; show just which subdomains connected
    try:
        tokens = _tokens_get()
        return jsonify({"ok": True, "connected": sorted(list(tokens.keys()))})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


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

    required = ["account_id", "subdomain", "user_id", "fio", "email", "phone"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        log_event("install_rejected_missing_fields", {"missing": missing, "data": data})
        return jsonify({"ok": False, "error": "missing_fields", "missing": missing}), 400

    # Send lead to Telegram
    text = (
        "🆕 Установка виджета Loss Control\n"
        f"Аккаунт: {data.get('subdomain')}.amocrm.ru\n"
        f"Account ID: {data.get('account_id')}\n"
        f"User ID: {data.get('user_id')}\n"
        f"ФИО: {data.get('fio')}\n"
        f"Email: {data.get('email')}\n"
        f"Телефон: {data.get('phone')}\n"
        f"Backend URL: {data.get('backend_url','')}\n"
        f"Дата: {datetime.utcnow().isoformat()}Z"
    )
    tg_ok, tg_info = _tg_send(text)

    log_event("install", {"data": data, "telegram_ok": tg_ok, "telegram_info": tg_info})
    return jsonify({"ok": True, "telegram_ok": tg_ok})


@app.get("/oauth/start")
def oauth_start():
    """
    Returns amoCRM OAuth URL (mode=post_message).
    If you add ?go=1 — will redirect browser to amoCRM instead of JSON.
    """
    try:
        missing = _require_oauth_env()
        if missing:
            return jsonify({"ok": False, "error": "missing_oauth_env", "missing": missing}), 400

        subdomain = (request.args.get("subdomain") or "").strip()
        if not subdomain:
            subdomain = _parse_subdomain_from_referer(request.headers.get("Referer", ""))

        state = secrets.token_urlsafe(16)

        # save state (disk or memory)
        states = _states_get()
        states[state] = {"ts": int(time.time()), "subdomain": subdomain}
        _states_set(states)

        params = {"client_id": AMO_CLIENT_ID, "state": state, "mode": "post_message"}
        url = _amo_auth_host() + "/oauth?" + urlencode(params)

        log_event("oauth_start", {"subdomain": subdomain, "state": state})

        if request.args.get("go") == "1":
            return Response("", status=302, headers={"Location": url})
        return jsonify({"ok": True, "url": url})
    except Exception as e:
        log_event("oauth_start_error", {"error": str(e)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


@app.get("/oauth/redirect")
def oauth_redirect():
    """
    Redirect page for amoCRM 'mode=post_message'.
    amo opens this URL with ?code=...&state=...
    We'll POST that code to /oauth/callback and show a friendly message.
    """
    # IMPORTANT: keep this HTML simple (amo opens it in a popup)
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Loss Control OAuth</title>
  <style>body{{font-family:Arial, sans-serif; padding:24px;}}</style>
</head>
<body>
  <h3>Подключаем аккаунт…</h3>
  <div id="status">Пожалуйста, подождите.</div>
  <script>
    (function() {{
      const params = new URLSearchParams(window.location.search);
      const code = params.get('code');
      const state = params.get('state');

      // Try to inform opener (amo expects this)
      try {{
        if (window.opener && window.opener !== window) {{
          window.opener.postMessage({{type:'amo_oauth', code, state}}, '*');
        }}
      }} catch(e) {{}}

      async function post() {{
        const res = await fetch('/oauth/callback', {{
          method: 'POST',
          headers: {{'Content-Type':'application/json'}},
          body: JSON.stringify({{
            code: code,
            state: state,
            referer: document.referrer || '',
            origin: window.location.origin
          }})
        }});
        const data = await res.json().catch(() => ({{ok:false, error:'bad_json'}}));
        const el = document.getElementById('status');
        if (data && data.ok) {{
          el.innerHTML = '✅ Аккаунт подключен. Можно закрыть окно.';
        }} else {{
          el.innerHTML = '❌ Ошибка подключения: ' + (data.details || data.error || 'unknown');
        }}
      }}

      if (!code) {{
        document.getElementById('status').innerHTML = '❌ Нет параметра code в URL';
        return;
      }}
      post();
    }})();
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.post("/oauth/callback")
def oauth_callback():
    """
    Receives {code, state, referer} from /oauth/redirect and exchanges code -> tokens.
    """
    try:
        data = request.get_json(silent=True) or {}
        code = (data.get("code") or "").strip()
        state = (data.get("state") or "").strip()
        referer = (data.get("referer") or "").strip()

        if not code:
            return jsonify({"ok": False, "error": "missing_code"}), 400

        missing = _require_oauth_env()
        if missing:
            return jsonify({"ok": False, "error": "missing_oauth_env", "missing": missing}), 400

        subdomain = _parse_subdomain_from_referer(referer)
        # If state present, prefer stored subdomain from state
        if state:
            states = _states_get()
            s = states.get(state)
            if s and s.get("subdomain"):
                subdomain = s["subdomain"]

        if not subdomain:
            # last attempt: user can pass it explicitly
            subdomain = (data.get("subdomain") or "").strip()

        if not subdomain:
            return jsonify({"ok": False, "error": "cannot_detect_subdomain", "details": "No subdomain in referer/state"}), 400

        tok = _amo_token_exchange(code)
        now = int(time.time())
        tokens = _tokens_get()
        tokens[subdomain] = {
            "access_token": tok.get("access_token", ""),
            "refresh_token": tok.get("refresh_token", ""),
            "expires_at": now + int(tok.get("expires_in", 0)),
            "token_type": tok.get("token_type", ""),
            "scope": tok.get("scope", ""),
            "created_at": now,
        }
        _tokens_set(tokens)

        log_event("oauth_ok", {"subdomain": subdomain, "referer": referer})

        return jsonify({"ok": True, "subdomain": subdomain})
    except requests.HTTPError as e:
        # show amo error body if possible
        details = ""
        try:
            details = e.response.text
        except Exception:
            details = str(e)
        log_event("oauth_http_error", {"details": details})
        return jsonify({"ok": False, "error": "amo_http_error", "details": details}), 400
    except Exception as e:
        log_event("oauth_error", {"error": str(e)})
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


@app.get("/report/losses")
def report_losses():
    """
    Very MVP endpoint:
    returns basic counts for closed leads in date range.
    Later we will expand into full analytics (reasons, idle days, lost money).
    """
    try:
        subdomain = (request.args.get("subdomain") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        if not subdomain or not date_from or not date_to:
            return jsonify({"ok": False, "error": "missing_params", "need": ["subdomain", "date_from", "date_to"]}), 400

        # Token
        access = _get_valid_token(subdomain)

        # For now, just check we can call account endpoint
        acc = _amo_api_get(subdomain, "/api/v4/account", access)
        return jsonify({"ok": True, "subdomain": subdomain, "account_name": acc.get("name", "")})
    except Exception as e:
        return jsonify({"ok": False, "error": "internal_error", "details": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
