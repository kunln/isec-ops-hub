"""
ThreatBook API Client - 精简版
仅支持2个API端点，Cookie认证
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from config import API_PREFIX, BASE_URL, COOKIE_FILE, DEFAULT_HEADERS, SSL_VERIFY, TIMEOUT


class ThreatBookAPIError(Exception):
    """API Error Exception"""

    pass


def _domain_match(host: str, cookie_domain: str) -> bool:
    """Check if cookie domain matches the request host."""
    if not cookie_domain:
        return False
    pure_domain = cookie_domain.lstrip(".")
    return host == pure_domain or host.endswith(f".{pure_domain}")


def _load_cookies(cookie_file: Path) -> List[Dict]:
    """Load cookies from JSON file, supports multiple formats."""
    if not cookie_file.exists():
        return []

    with open(cookie_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Format 1: Direct array of cookies
    if isinstance(data, list):
        return data

    # Format 2: {cookies: [...], origins: [...]} like auth-state.json
    if isinstance(data, dict) and "cookies" in data:
        return data.get("cookies", [])

    return []


def _build_cookie_header(url: str, cookie_file: Path) -> str:
    """Build Cookie header from JSON cookie file."""
    cookies = _load_cookies(cookie_file)

    if not cookies:
        return ""

    host = url.split("/")[2] if "/" in url else url
    pairs = [
        f"{c.get('name', '')}={c.get('value', '')}"
        for c in cookies
        if c.get("name") and c.get("value") and _domain_match(host, c.get("domain", ""))
    ]
    return "; ".join(pairs)


def _parse_time(value: str) -> int:
    """解析时间字符串为 Unix 时间戳（UTC+8）。
    支持格式：
      - Unix 时间戳（纯数字）：1741536000
      - 日期：2026-03-10
      - 日期+时间：2026-03-10 16:00 / 2026-03-10 16:00:00
    """
    value = value.strip()
    if value.isdigit():
        return int(value)
    tz_local = timezone(timedelta(hours=8))
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=tz_local)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(f"无法解析时间：{value!r}，支持格式：时间戳 / 2026-03-10 / 2026-03-10 16:00")


def _get_time_range(
    days: int = 1,
    hours: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> Dict[str, int]:
    """获取时间范围。优先级：time_from/time_to > hours > days"""
    if time_from is not None or time_to is not None:
        now_ts = int(datetime.now().timestamp())
        ts_from = _parse_time(time_from) if time_from else now_ts - 86400
        ts_to = _parse_time(time_to) if time_to else now_ts
        return {"time_from": ts_from, "time_to": ts_to}
    now = datetime.now()
    ts_to = int(now.timestamp())
    if hours is not None:
        ts_from = int((now - timedelta(hours=hours)).timestamp())
    else:
        ts_from = int((now - timedelta(days=days)).timestamp())
    return {"time_from": ts_from, "time_to": ts_to}


class ThreatBookClient:
    """ThreatBook API Client - 精简版

    支持2个API端点：
    - 威胁监控: api/web/hw/monitor/threat/list
    - 日志搜索: api/web/log/searchBySql
    """

    def __init__(self, token: Optional[str] = None, base_url: str = BASE_URL, cookie_file: Optional[Path] = None):
        self.base_url = base_url.rstrip("/")
        self.cookie_file = cookie_file or COOKIE_FILE
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

        cookie_header = _build_cookie_header(self.base_url, self.cookie_file)
        if cookie_header:
            self.session.headers["Cookie"] = cookie_header

    def _build_url(self, endpoint: str) -> str:
        """Build full URL"""
        path = endpoint.lstrip("/")
        if path.startswith("api/web"):
            return f"{self.base_url}/{path}"
        return f"{self.base_url}{API_PREFIX}/{path}"

    def request(
        self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make API request"""
        url = self._build_url(endpoint)

        # Refresh cookie for each request
        cookie_header = _build_cookie_header(self.base_url, self.cookie_file)
        if cookie_header:
            self.session.headers["Cookie"] = cookie_header

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                json=data,
                params=params,
                timeout=TIMEOUT,
                verify=SSL_VERIFY,
            )

            if response.status_code == 404:
                return {"error": "Not Found", "status_code": 404, "response_code": -1}

            response.raise_for_status()

            try:
                return response.json()
            except json.JSONDecodeError:
                return {"data": response.text, "response_code": 0}

        except requests.exceptions.RequestException as e:
            raise ThreatBookAPIError(f"Request failed: {e}") from e

    # ==================== Threat Monitor API ====================

    def get_threat_list(
        self,
        page: int = 1,
        page_size: int = 20,
        days: int = 1,
        hours: Optional[int] = None,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
        sql: str = "(threat.level IN ('attack'))",
        refresh_rate: int = -1,
    ) -> Dict:
        """Get threat list - 获取威胁列表 (api/web/hw/monitor/threat/list)"""
        time_range = _get_time_range(days=days, hours=hours, time_from=time_from, time_to=time_to)
        return self.request(
            "POST",
            "hw/monitor/threat/list",
            data={
                "condition": {
                    "time_from": time_range["time_from"],
                    "time_to": time_range["time_to"],
                    "refresh_rate": refresh_rate,
                    "sql": sql,
                    "columns": [
                        {"label": "最近发现时间", "value": "time"},
                        {"label": "类型", "value": ["threat.level", "threat.result"]},
                        {"label": "攻击者IP/IOC", "value": "attacker"},
                        {"label": "威胁名称", "value": "threat.name"},
                        {"label": "威胁方向", "value": "direction"},
                        {"label": "源IP", "value": "net.src_ip"},
                        {"label": "目的IP", "value": "net.dest_ip"},
                        {"label": "严重级别", "value": "threat.severity"},
                        {"label": "检出次数", "value": "alert_count"},
                        {"label": "威胁id", "value": "threat.id"},
                    ],
                },
                "page": {
                    "cur_page": page,
                    "page_size": page_size,
                    "sort": [{"sort_by": "time", "sort_order": "desc"}],
                },
            },
        )

    # ==================== Log Query API ====================

    # 默认 columns：与页面展示字段一致
    _DEFAULT_LOG_COLUMNS = [
        {"label": "类型", "value": ["threat.level", "threat.result"]},
        {"label": "日期", "value": "time"},
        {"label": "源", "value": ["net.src_ip", "net.src_port", "net.tcp_option_ip"]},
        {"label": "目的", "value": ["net.dest_ip", "net.dest_port"]},
        {"label": "协议", "value": ["net.type", "net.http.method", "net.http.status", "net.protocol_version"]},
        {"label": "URL或域名", "value": "data"},
        {"label": "威胁名称", "value": "threat.name"},
        {"label": "ioc", "value": "threat.ioc"},
        {"label": "is_connected", "value": "threat.is_connected"},
        {"label": "威胁id", "value": "threat.id"},
    ]

    def search_logs_by_sql(
        self,
        sql: str = "",
        days: int = 1,
        hours: Optional[int] = None,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
        net_data_type: Optional[List[str]] = None,
        full: bool = False,
        columns: Optional[List[Dict]] = None,
    ) -> Dict:
        """Search logs by SQL - 使用SQL搜索日志 (api/web/log/searchBySql)

        columns 优先级：columns 参数 > full 模式（不传 columns）> 默认列表
        """
        time_range = _get_time_range(days=days, hours=hours, time_from=time_from, time_to=time_to)
        data: Dict[str, Any] = {
            "time_from": time_range["time_from"],
            "time_to": time_range["time_to"],
            "sql": sql,
            "assets_group": [],
            "net_data_type": net_data_type or ["attack", "risk", "action"],
        }
        if columns is not None:
            # 用户自定义字段列表
            data["columns"] = columns
        elif not full:
            # 默认：与页面展示一致的字段
            data["columns"] = self._DEFAULT_LOG_COLUMNS
        # full=True 时不传 columns，让后端返回全部字段
        return self.request("POST", "log/searchBySql", data=data)
