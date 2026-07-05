"""
ThreatBook CLI Configuration

认证方式：
1. Cookie 认证（推荐）：自动从 tdp_cookie.json 加载
   - 在浏览器中登录 ThreatBook
   - F12 → Application → Cookies → 导出为 JSON 格式
   - 保存为 tdp_cookie.json

2. Token 认证（备用）：使用 THREATBOOK_TOKEN 环境变量
"""

import os
from pathlib import Path

# Base Configuration
BASE_URL = os.getenv("THREATBOOK_BASE_URL")
API_PREFIX = "/api/web"

# Cookie 认证配置
# 支持两种格式：
# 1. 直接数组: [{name, value, domain}, ...]
# 2. auth-state.json: {cookies: [...], origins: [...]}
# 可通过 THREATBOOK_COOKIE_FILE 环境变量指定路径
COOKIE_FILE = Path(os.getenv("THREATBOOK_COOKIE_FILE"))

# Token 认证（备用）
TOKEN = os.getenv("THREATBOOK_TOKEN", "")

# Default Headers
DEFAULT_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json; charset=UTF-8",
    "User-Agent": "ThreatBook-CLI/1.0",
}

# Request Configuration
TIMEOUT = 30

# SSL 配置
# 设置 THREATBOOK_INSECURE=1 或 THREATBOOK_SSL_VERIFY=false 禁用 SSL 验证（用于内网自签名证书）
SSL_VERIFY = not (
    os.getenv("THREATBOOK_INSECURE", "").lower() in ("1", "true", "yes")
    or os.getenv("THREATBOOK_SSL_VERIFY", "true").lower() in ("0", "false", "no")
)
