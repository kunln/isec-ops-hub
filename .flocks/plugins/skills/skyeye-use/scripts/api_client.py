"""Minimal SkyEye API client for the skill-local CLI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

import requests

from config import AUTH_STATE_FILE, BASE_URL, DEFAULT_HEADERS, SSL_VERIFY, TIMEOUT, TOKEN


class SkyeyeAPIError(Exception):
    """SkyEye API error."""


def _domain_match(host: str, cookie_domain: str) -> bool:
    pure_domain = cookie_domain.lstrip(".")
    return bool(pure_domain) and (host == pure_domain or host.endswith(f".{pure_domain}"))


def _load_auth_state(auth_file: Path) -> Dict[str, Any]:
    if not auth_file.exists():
        return {"cookies": [], "origins": []}
    return json.loads(auth_file.read_text(encoding="utf-8"))


def _extract_cookies(auth_file: Path) -> list[Dict[str, Any]]:
    auth_data = _load_auth_state(auth_file)
    if isinstance(auth_data, dict):
        cookies = auth_data.get("cookies", [])
        return cookies if isinstance(cookies, list) else []
    if isinstance(auth_data, list):
        return [item for item in auth_data if isinstance(item, dict)]
    return []


def _build_cookie_header(url: str, auth_file: Path) -> str:
    cookies = _extract_cookies(auth_file)
    host = urlparse(url).hostname or url
    pairs = []
    for cookie in cookies:
        if not cookie.get("name") or not cookie.get("value"):
            continue
        domain = str(cookie.get("domain", ""))
        if domain and not _domain_match(host, domain):
            continue
        pairs.append(f"{cookie['name']}={cookie['value']}")
    return "; ".join(pairs)


def _get_csrf_token(auth_file: Optional[Path], fallback_token: str = "") -> Optional[str]:
    if auth_file is None:
        return fallback_token or None
    for cookie in _extract_cookies(auth_file):
        if cookie.get("name") == "csrfToken":
            return cookie.get("value")
    return fallback_token or None


def _to_millis(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        number = int(value)
        return number if abs(number) >= 10_000_000_000 else number * 1000
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return _to_millis(int(text))
    normalized = text.replace("Z", "+00:00").replace("/", "-")
    try:
        return int(datetime.fromisoformat(normalized).timestamp() * 1000)
    except ValueError:
        raise ValueError(f"无法解析时间值: {value}") from None


def _get_time_range_ms(
    days: int = 1,
    hours: Optional[int] = None,
    start_time: Any = None,
    end_time: Any = None,
) -> Dict[str, int]:
    explicit_start = _to_millis(start_time)
    explicit_end = _to_millis(end_time)
    if explicit_start is not None or explicit_end is not None:
        now_ms = int(datetime.now().timestamp() * 1000)
        final_end = explicit_end if explicit_end is not None else now_ms
        if explicit_start is None:
            delta = timedelta(hours=hours) if hours is not None else timedelta(days=days)
            explicit_start = int((datetime.fromtimestamp(final_end / 1000) - delta).timestamp() * 1000)
        return {"start_time": explicit_start, "end_time": final_end}

    now = datetime.now()
    start = now - (timedelta(hours=hours) if hours is not None else timedelta(days=days))
    return {"start_time": int(start.timestamp() * 1000), "end_time": int(now.timestamp() * 1000)}


def _clean_mapping(values: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    if not values:
        return cleaned
    for key, value in values.items():
        if value is None or value == "":
            continue
        if isinstance(value, (dict, list)):
            cleaned[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, bool):
            cleaned[key] = "1" if value else "0"
        else:
            cleaned[key] = value
    return cleaned


def _join_csv(values: Optional[Iterable[str]]) -> str:
    if not values:
        return ""
    return ",".join(str(item) for item in values if item not in (None, ""))


class SkyeyeClient:
    """Minimal SkyEye HTTP client."""

    def __init__(
        self,
        base_url: str = BASE_URL,
        auth_file: Optional[Path] = None,
        csrf_token: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_file = auth_file or AUTH_STATE_FILE
        self.csrf_token = csrf_token or TOKEN
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self._refresh_auth_headers()

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
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        form_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        self._refresh_auth_headers()

        actual_params = _clean_mapping(params)
        csrf_token = _get_csrf_token(self.auth_file, self.csrf_token)
        if csrf_token:
            actual_params.setdefault("csrf_token", csrf_token)

        request_headers = dict(self.session.headers)
        if headers:
            request_headers.update(headers)
        if form_data is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=actual_params,
                json=json_data,
                data=form_data,
                headers=request_headers,
                timeout=TIMEOUT,
                verify=SSL_VERIFY,
            )
            if response.status_code == 404:
                return {"error": "Not Found", "status_code": 404, "code": -1}
            response.raise_for_status()
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"code": 0, "data": response.text}
        except requests.exceptions.RequestException as exc:
            raise SkyeyeAPIError(f"Request failed: {exc}") from exc

    def _build_alarm_params(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        days: int = 1,
        hours: Optional[int] = None,
        start_time: Any = None,
        end_time: Any = None,
        order_by: str = "access_time:desc",
        data_source: str = "1",
        is_alarm_list: str = "1",
        total_flag: str = "1",
        extra_filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        time_range = _get_time_range_ms(days=days, hours=hours, start_time=start_time, end_time=end_time)
        params = {
            "start_time": time_range["start_time"],
            "end_time": time_range["end_time"],
            "data_source": data_source,
            "offset": page,
            "limit": page_size,
            "order_by": order_by,
            "is_alarm_list": is_alarm_list,
            "total_flag": total_flag,
        }
        params.update(_clean_mapping(extra_filters))
        return params

    def _build_log_search_params(
        self,
        *,
        keyword: str = "",
        page: int = 1,
        page_size: int = 20,
        days: int = 1,
        hours: Optional[int] = None,
        start_time: Any = None,
        end_time: Any = None,
        branch_id: str = "",
        index: str = "alarm_collection",
        category: str = "event",
        interval: str = "20s",
        mode: str = "advance_model",
        key_fields: Optional[Iterable[str]] = None,
        graph_conf: Any = None,
        asset_group_ids: str = "",
        task_id: str = "",
        sess_key_ids: str = "",
        extra_filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        time_range = _get_time_range_ms(days=days, hours=hours, start_time=start_time, end_time=end_time)
        params = {
            "start_time": time_range["start_time"],
            "end_time": time_range["end_time"],
            "stime": time_range["start_time"],
            "etime": time_range["end_time"],
            "page": page,
            "size": page_size,
            "offset": page,
            "limit": page_size,
            "index": index,
            "category": category,
            "interval": interval,
            "mode": mode,
            "key_fields": _join_csv(key_fields) or "@timestamp",
            "graph_conf": json.dumps(graph_conf, ensure_ascii=False) if graph_conf is not None else "{}",
        }
        if keyword:
            params["keyword"] = keyword
        if branch_id:
            params["branch_id"] = branch_id
            params["curBranch"] = branch_id
        if asset_group_ids:
            params["asset_group_ids"] = asset_group_ids
        if task_id:
            params["task_id"] = task_id
        if sess_key_ids:
            params["sess_key_ids"] = sess_key_ids
        params.update(_clean_mapping(extra_filters))
        return params

    def get_alarm_list(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        days: int = 1,
        hours: Optional[int] = None,
        start_time: Any = None,
        end_time: Any = None,
        order_by: str = "access_time:desc",
        data_source: str = "1",
        is_alarm_list: str = "1",
        total_flag: str = "1",
        **filters: Any,
    ) -> Dict[str, Any]:
        return self.request(
            "GET",
            "skyeye/v1/alarm/alarm/list",
            params=self._build_alarm_params(
                page=page,
                page_size=page_size,
                days=days,
                hours=hours,
                start_time=start_time,
                end_time=end_time,
                order_by=order_by,
                data_source=data_source,
                is_alarm_list=is_alarm_list,
                total_flag=total_flag,
                extra_filters=filters,
            ),
        )

    def get_alarm_count(
        self,
        *,
        days: int = 1,
        hours: Optional[int] = None,
        start_time: Any = None,
        end_time: Any = None,
        data_source: str = "1",
        is_alarm_list: str = "1",
        **filters: Any,
    ) -> Dict[str, Any]:
        params = self._build_alarm_params(
            days=days,
            hours=hours,
            start_time=start_time,
            end_time=end_time,
            data_source=data_source,
            is_alarm_list=is_alarm_list,
            extra_filters=filters,
        )
        for key in ("offset", "limit", "order_by", "total_flag"):
            params.pop(key, None)
        return self.request("GET", "skyeye/v1/alarm/alarm/count", params=params)

    def search_log_analysis(self, **kwargs: Any) -> Dict[str, Any]:
        raw = self.request(
            "GET",
            "skyeye/v1/analysis/log-search/list",
            params=self._build_log_search_params(**kwargs),
        )
        # Normalize nested structure: data.data.search.{hits,total} → data.{hits,total}
        try:
            inner = raw["data"]["data"]
            search = inner.get("search", {})
            raw["data"] = {
                "hits": search.get("hits", []),
                "total": search.get("total", 0),
                "fields": inner.get("fields", []),
                "field_mapping": inner.get("field_mapping", {}),
            }
        except (KeyError, TypeError):
            pass
        return raw

