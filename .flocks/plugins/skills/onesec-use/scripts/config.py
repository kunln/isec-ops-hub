import os
from pathlib import Path


BASE_URL = os.getenv("ONESEC_BASE_URL", "https://console.onesec.net")

# 浏览器模式默认复用统一 state 文件，也允许用环境变量覆盖。
AUTH_STATE_FILE = Path(
    os.getenv("ONESEC_AUTH_STATE", Path.home() / ".flocks" / "browser" / "onesec" / "auth-state.json")
)
COOKIE_FILE = Path(
    os.getenv("ONESEC_COOKIE_FILE", Path.home() / ".flocks" / "browser" / "onesec" / "onesec_cookie.json")
)

TOKEN = os.getenv("ONESEC_CSRF_TOKEN", "")

DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json; charset=UTF-8",
    "User-Agent": "OneSec-CLI/1.0",
}

TIMEOUT = 30

SSL_VERIFY = not (
    os.getenv("ONESEC_INSECURE", "").lower() in ("1", "true", "yes")
    or os.getenv("ONESEC_SSL_VERIFY", "true").lower() in ("0", "false", "no")
)
