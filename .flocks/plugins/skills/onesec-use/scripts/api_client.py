import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from config import AUTH_STATE_FILE, BASE_URL, COOKIE_FILE, DEFAULT_HEADERS, SSL_VERIFY, TIMEOUT, TOKEN


class OneSecAPIError(Exception):
    pass


def _domain_match(host: str, cookie_domain: str) -> bool:
    if not cookie_domain:
        return False
    pure_domain = cookie_domain.lstrip(".")
    return host == pure_domain or host.endswith(f".{pure_domain}")


def _load_auth_state(auth_file: Path) -> Dict[str, Any]:
    if not auth_file.exists():
        return {"cookies": [], "origins": []}
    with open(auth_file, "r", encoding="utf-8") as f:
        return json.load(f)


def _extract_cookies(auth_file: Path) -> List[Dict[str, Any]]:
    auth_data = _load_auth_state(auth_file)
    if isinstance(auth_data, dict):
        cookies = auth_data.get("cookies", [])
        return cookies if isinstance(cookies, list) else []
    if isinstance(auth_data, list):
        return [item for item in auth_data if isinstance(item, dict)]
    return []


def _build_cookie_header(url: str, auth_file: Path) -> str:
    cookies = _extract_cookies(auth_file)
    if not cookies:
        return ""

    host = urlparse(url).hostname or url
    pairs = [
        f"{cookie.get('name', '')}={cookie.get('value', '')}"
        for cookie in cookies
        if cookie.get("name")
        and cookie.get("value")
        and (not cookie.get("domain") or _domain_match(host, str(cookie.get("domain", ""))))
    ]
    return "; ".join(pairs)


def _get_csrf_token(auth_file: Optional[Path], fallback_token: str = "") -> Optional[str]:
    if auth_file is None:
        return fallback_token or None
    for cookie in _extract_cookies(auth_file):
        if cookie.get("name") == "csrfToken":
            return cookie.get("value")
    return fallback_token or None


def _get_time_range(days: int = 7, hours: Optional[int] = None) -> Dict[str, int]:
    now = datetime.now()
    time_to = int(now.timestamp())
    if hours is not None:
        time_from = int((now - timedelta(hours=hours)).timestamp())
    else:
        time_from = int((now - timedelta(days=days)).timestamp())
    return {"time_from": time_from, "time_to": time_to}


class OneSecClient:
    def __init__(self, base_url: str = BASE_URL, auth_file: Optional[Path] = None, csrf_token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_file = auth_file
        self.csrf_token = csrf_token or TOKEN
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self._refresh_auth_headers()

    def _build_url(self, endpoint: str) -> str:
        return f"{self.base_url}/{endpoint.lstrip('/')}"

    def _refresh_auth_headers(self) -> None:
        csrf_token = _get_csrf_token(self.auth_file, self.csrf_token)
        if csrf_token:
            self.session.headers["csrfToken"] = csrf_token
        else:
            self.session.headers.pop("csrfToken", None)

        if self.auth_file and self.auth_file.exists():
            cookie_header = _build_cookie_header(self.base_url, self.auth_file)
            if cookie_header:
                self.session.headers["Cookie"] = cookie_header
            else:
                self.session.headers.pop("Cookie", None)
        else:
            self.session.headers.pop("Cookie", None)

    def request(
        self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        url = self._build_url(endpoint)
        self._refresh_auth_headers()

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
                return {"error": "Not Found", "status_code": 404, "code": -1}

            response.raise_for_status()
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"data": response.text, "code": 0}
        except requests.exceptions.RequestException as e:
            raise OneSecAPIError(f"Request failed: {e}") from e

    def search_threat_actions(
        self,
        days: int = 7,
        page: int = 1,
        page_size: int = 20,
        keyword: str = "",
    ) -> Dict[str, Any]:
        time_range = _get_time_range(days=days)
        data = {
            "time_from": time_range["time_from"],
            "time_to": time_range["time_to"],
            "group_list": [],
            "multi_search_field": {
                "host_name": [],
                "host_ip": [],
                "user_name": [],
                "threat_name": [],
                "root_cause_target": [],
            },
            "keyword": keyword,
            "umid": "",
            "os_list": [],
            "threat_severity": [],
            "threat_level": [],
            "threat_phase_list": [],
            "gray": [],
            "sorts": [
                {"sort_by": "last_signal_time", "sort_order": "desc"},
                {"sort_by": "threat_severity", "sort_order": "desc"},
            ],
            "page": {"cur_page": page, "page_size": page_size},
        }
        return self.request("POST", "api/saasedr/threat/action/search", data=data)

    def get_threat_name_top(self, days: int = 7, limit: int = 10) -> Dict[str, Any]:
        time_range = _get_time_range(days=days)
        return self.request(
            "POST",
            "api/saasedr/threat/action/name/top",
            data={"time_from": time_range["time_from"], "time_to": time_range["time_to"], "limit": limit},
        )

    def search_logs_by_sql(
        self,
        sql: str,
        days: int = 1,
        hours: Optional[int] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        time_range = _get_time_range(days=days, hours=hours)
        return self.request(
            "POST",
            "api/saasedr/log/searchBySql",
            data={
                "time_from": time_range["time_from"],
                "time_to": time_range["time_to"],
                "sql": sql,
                "useLoggingTime": True,
                "page": {"cur_page": page, "page_size": page_size},
                "sort": [{"sort_by": "event_time", "sort_order": "desc"}],
                "shown_fields": [
                    {"name": "事件性质", "field": "threat.level"},
                    {"name": "动作类型", "field": "event_type"},
                    {"name": "动作描述", "field": "event_description"},
                    {"name": "终端名称", "field": "host_name"},
                    {"name": "当前职场/分组", "field": "latest_group_name"},
                    {"name": "终端内网IP地址", "field": "host_ip"},
                    {"name": "进程文件名", "field": "proc_file.name"},
                ],
                "sql_source_id": "",
                "logHistory": True,
                "includeControl": True,
            },
        )

    def get_log_type_count(self, days: int = 1) -> Dict[str, Any]:
        time_range = _get_time_range(days=days)
        return self.request(
            "POST",
            "api/saasedr/log/type-count",
            data={"time_from": time_range["time_from"], "time_to": time_range["time_to"]},
        )

    def get_log_trend(self, days: int = 1) -> Dict[str, Any]:
        time_range = _get_time_range(days=days)
        return self.request(
            "POST",
            "api/saasedr/log/trend",
            data={"time_from": time_range["time_from"], "time_to": time_range["time_to"], "sql": ""},
        )


def resolve_auth_file() -> Optional[Path]:
    if AUTH_STATE_FILE.exists():
        return AUTH_STATE_FILE
    if COOKIE_FILE.exists():
        return COOKIE_FILE
    return None
