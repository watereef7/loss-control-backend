from urllib.parse import urlparse
import secrets

AMO_CLIENT_ID = os.environ.get("AMO_CLIENT_ID", "").strip()
AMO_CLIENT_SECRET = os.environ.get("AMO_CLIENT_SECRET", "").strip()
AMO_REDIRECT_URI = os.environ.get("AMO_REDIRECT_URI", "").strip()

TOKENS_FILE = os.path.join(DATA_DIR, "tokens.json")

def load_tokens():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(TOKENS_FILE):
            return {}
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def save_tokens(tokens: dict):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def parse_subdomain_from_referer(referer: str) -> str:
    # referer приходит как адрес аккаунта пользователя (например https://meawake.amocrm.ru)
    # см. документацию: code, referer, state ... приходят на Redirect URI
    if not referer:
        return ""
    host = urlparse(referer).netloc or referer
    # host может быть "meawake.amocrm.ru"
    return host.split(".")[0] if host else ""

@app.get("/oauth/start")
def oauth_start():
    if not AMO_CLIENT_ID or not AMO_REDIRECT_URI:
        return jsonify({"ok": False, "error": "missing_env_AMO_CLIENT_ID_or_AMO_REDIRECT_URI"}), 500

    # state нужен для защиты, можно хранить/проверять строже, но для MVP хватит так
    state = secrets.token_urlsafe(16)

    # Открываем окно предоставления доступов
    url = f"https://www.amocrm.ru/oauth?client_id={AMO_CLIENT_ID}&state={state}&mode=post_message"
    return jsonify({"ok": True, "url": url})

@app.get("/oauth/callback")
def oauth_callback():
    # На Redirect URI amoCRM приходит с GET-параметрами: code, referer, state, ...
    # https://www.amocrm.ru/developers/content/oauth/step-by-step
    code = request.args.get("code")
    referer = request.args.get("referer")  # адрес аккаунта пользователя
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

    # Обмен кода на токены через /oauth2/access_token (на домене аккаунта)
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

    # Страница-заглушка (можно закрывать окно)
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
