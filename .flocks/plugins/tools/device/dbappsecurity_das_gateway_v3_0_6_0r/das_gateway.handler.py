from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote, urljoin

import aiohttp

from flocks import security
from flocks.config.config_writer import ConfigWriter
from flocks.tool.registry import ToolContext, ToolResult


SERVICE_ID = "dbappsecurity_das_gateway_api"
STORAGE_KEY = "dbappsecurity_das_gateway_api_v3_0_6_0r"
DEFAULT_TIMEOUT = 30


def _spec(path: str, required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"path": path, "required": list(required)}


NETWORK_ACTIONS = {
    "interface_list": _spec("/api/v3/Objects/Interface"),
    "interface_detail": _spec("/api/v3/Objects/Interface/name/{name}", ("name",)),
    "subinterface_list": _spec("/api/v3/Objects/SubInterface"),
    "subinterface_detail": _spec("/api/v3/Objects/SubInterface/name/{name}", ("name",)),
    "bridge_interface_list": _spec("/api/v3/Objects/BridgeInterface"),
    "bridge_interface_detail": _spec("/api/v3/Objects/BridgeInterface/name/{name}", ("name",)),
    "net_zone_list": _spec("/api/v3/Objects/NetZone"),
    "net_zone_detail": _spec("/api/v3/Objects/NetZone/name/{name}", ("name",)),
    "interface_state": _spec("/api/v3/Objects/InterfaceState"),
    "route_table": _spec("/api/v3/Objects/RouteTable"),
    "static_route_list": _spec("/api/v3/Objects/RouteStatic"),
    "nat_pool_list": _spec("/api/v3/Policies/NatPool"),
    "nat_pool_detail": _spec("/api/v3/Policies/NatPool/name/{name}", ("name",)),
    "snat_list": _spec("/api/v3/Policies/SNat"),
    "snat_detail": _spec("/api/v3/Policies/SNat/id/{id}", ("id",)),
    "dnat_list": _spec("/api/v3/Policies/DNat"),
    "dnat_detail": _spec("/api/v3/Policies/DNat/id/{id}", ("id",)),
    "static_nat_list": _spec("/api/v3/Policies/StaticNat"),
    "static_nat_detail": _spec("/api/v3/Policies/StaticNat/id/{id}", ("id",)),
    "dns_server": _spec("/api/v3/Objects/DnsServer"),
    "dns_proxy_wildcard_list": _spec("/api/v3/Objects/DnsProxyWildcard"),
    "dns_proxy_wildcard_detail": _spec("/api/v3/Objects/DnsProxyWildcard/dname/{domain}", ("domain",)),
    "dns_cache_enable": _spec("/api/v3/Objects/DnsProxyCache/enable"),
    "dns_cache": _spec("/api/v3/Objects/DnsProxyCache"),
    "dns_server_specified_list": _spec("/api/v3/Objects/DnsServerSpecified"),
    "dns_server_specified_detail": _spec("/api/v3/Objects/DnsServerSpecified/dname/{domain}", ("domain",)),
    "dns_proxy_rule_enable": _spec("/api/v3/Objects/DnsProxyRule/enable"),
    "dns_proxy_rule_balance": _spec("/api/v3/Objects/DnsProxyRule/balance"),
    "dns_proxy_rule_list": _spec("/api/v3/Objects/DnsProxyRule"),
    "dns_proxy_rule_detail": _spec("/api/v3/Objects/DnsProxyRule/name/{interface_name}", ("interface_name",)),
}

OBJECT_ACTIONS = {
    "address_list": _spec("/api/v3/Objects/Address"),
    "address_detail": _spec("/api/v3/Objects/Address/name/{name}", ("name",)),
    "address_group_list": _spec("/api/v3/Objects/AddressGroups"),
    "address_group_detail": _spec("/api/v3/Objects/AddressGroups/name/{name}", ("name",)),
    "predef_service_list": _spec("/api/v3/Objects/PredefService"),
    "custom_service_list": _spec("/api/v3/Objects/CustomService"),
    "custom_service_detail": _spec("/api/v3/Objects/CustomService/name/{name}", ("name",)),
    "service_group_list": _spec("/api/v3/Objects/ServiceGroups"),
    "service_group_detail": _spec("/api/v3/Objects/ServiceGroups/name/{name}", ("name",)),
    "day_schedule_list": _spec("/api/v3/Objects/DaySchedule"),
    "day_schedule_detail": _spec("/api/v3/Objects/DaySchedule/name/{name}", ("name",)),
    "week_schedule_list": _spec("/api/v3/Objects/WeekSchedule"),
    "week_schedule_detail": _spec("/api/v3/Objects/WeekSchedule/name/{name}", ("name",)),
    "month_schedule_list": _spec("/api/v3/Objects/MonthSchedule"),
    "month_schedule_detail": _spec("/api/v3/Objects/MonthSchedule/name/{name}", ("name",)),
    "once_schedule_list": _spec("/api/v3/Objects/OnceSchedule"),
    "once_schedule_detail": _spec("/api/v3/Objects/OnceSchedule/name/{name}", ("name",)),
    "keyword_list": _spec("/api/v3/Objects/Keywords"),
    "keyword_detail": _spec("/api/v3/Objects/Keywords/name/{name}", ("name",)),
    "app_category_list": _spec("/api/v3/Objects/AppCategory"),
    "app_object_list": _spec("/api/v3/Objects/AppObj"),
    "app_object_detail": _spec("/api/v3/Objects/AppObj/name/{name}", ("name",)),
    "app_group_list": _spec("/api/v3/Objects/ApplicationGroups"),
    "custom_url_list": _spec("/api/v3/Objects/CustomUrl"),
    "custom_url_detail": _spec("/api/v3/Objects/CustomUrl/name/{name}", ("name",)),
    "malware_url": _spec("/api/v3/Objects/MalwareUrl"),
    "url_whitelist": _spec("/api/v3/Objects/UrlWhitelist"),
    "custom_https_list": _spec("/api/v3/Objects/CustomHttps"),
    "custom_https_detail": _spec("/api/v3/Objects/https_custom_object/name/{name}", ("name",)),
    "url_classification": _spec("/api/v3/Objects/UrlClassification"),
    "url_category_search": _spec("/api/v3/Objects/url_category_search/url/{url}", ("url",)),
    "auth_user_list": _spec("/api/v3/Objects/AuthUser"),
    "auth_user_detail": _spec("/api/v3/Objects/AuthUser/name/{name}", ("name",)),
    "auth_user_group_list": _spec("/api/v3/Objects/AuthUserGroups"),
    "auth_user_group_detail": _spec("/api/v3/Objects/AuthUserGroups/name/{name}", ("name",)),
    "radius_server_list": _spec("/api/v3/Objects/RadiusServer"),
    "radius_server_detail": _spec("/api/v3/Objects/RadiusServer/name/{name}", ("name",)),
    "radius_group_list": _spec("/api/v3/Objects/RadiusServerGroups"),
    "radius_group_detail": _spec("/api/v3/Objects/RadiusServerGroups/name/{name}", ("name",)),
    "ldap_server_list": _spec("/api/v3/Objects/LdapServer"),
    "ldap_server_detail": _spec("/api/v3/Objects/LdapServer/name/{name}", ("name",)),
    "ldap_group_list": _spec("/api/v3/Objects/LdapServerGroups"),
    "ldap_group_detail": _spec("/api/v3/Objects/LdapServerGroups/name/{name}", ("name",)),
}

POLICY_ACTIONS = {
    "security_policy_list": _spec("/api/v3/Policies/SecurityPolicy"),
    "security_policy_default_action": _spec("/api/v3/Objects/SecurityPolicy/default_action"),
    "applications_policy": _spec("/api/v3/Policies/ApplicationsPolicy/policy_id/{policy_id}", ("policy_id",)),
    "url_policy": _spec("/api/v3/Policies/UrlPolicy/policy_id/{policy_id}", ("policy_id",)),
    "audit_policy_list": _spec("/api/v3/Policies/AuditPolicy"),
    "audit_policy_detail": _spec("/api/v3/Policies/AuditPolicy/id/{id}", ("id",)),
    "route_policy_list": _spec("/api/v3/Policies/RoutePolicy"),
    "route_policy_detail": _spec("/api/v3/Policies/RoutePolicy/id/{id}", ("id",)),
    "vrf_list": _spec("/api/v3/Policies/VRF"),
    "vrf_detail": _spec("/api/v3/Policies/VRF/vrf_name/{vrf_name}", ("vrf_name",)),
    "global_whitelist_list": _spec("/api/v3/Policies/GlobalWhitelist"),
    "global_whitelist_detail": _spec("/api/v3/Policies/GlobalWhitelist/name/{name}", ("name",)),
    "global_whitelist_filter": _spec("/api/v3/Policies/GlobalWhitelist/filter_name/{filter_name}", ("filter_name",)),
}

SECURITY_ACTIONS = {
    "arp_table": _spec("/api/v3/Objects/ArpTable"),
    "ip_mac_bind_list": _spec("/api/v3/Objects/IpMacBind"),
    "ip_mac_bind_detail": _spec("/api/v3/Objects/IpMacBind/ip/{ip}", ("ip",)),
    "arp_spoof_config": _spec("/api/v3/Objects/ArpSpoofConfig"),
    "arp_flood": _spec("/api/v3/Objects/ArpFlood"),
    "arp_learn_control": _spec("/api/v3/Objects/ArpLearnControl"),
    "malformed_message_attack": _spec("/api/v3/Objects/MalformedMessageAttack"),
    "security_defend_scan": _spec("/api/v3/Objects/SecurityDefendScan"),
    "security_defend_scan_interface": _spec("/api/v3/Objects/SecurityDefendScan/ifname/{interface_name}", ("interface_name",)),
    "security_defend_flood": _spec("/api/v3/Objects/SecurityDefendFlood"),
    "security_defend_interface_flood": _spec("/api/v3/Objects/SecurityDefendInterfaceFlood"),
    "security_defend_interface_flood_detail": _spec("/api/v3/Objects/SecurityDefendInterfaceFlood/ifname/{interface_name}", ("interface_name",)),
    "blacklist_list": _spec("/api/v3/Objects/Blacklist"),
    "blacklist_detail": _spec("/api/v3/Objects/Blacklist/blist/{blist}", ("blist",)),
    "ips_template_list": _spec("/api/v3/Policies/IpsTemplate"),
    "ips_template_rules": _spec("/api/v3/Policies/Ips/template_name/{template_name}", ("template_name",)),
    "ips_template_rule_type": _spec("/api/v3/Policies/Ips/template_name/{template_name}/pId/{pid}/type/{rule_name}", ("template_name", "pid", "rule_name")),
    "ips_protocol_check": _spec("/api/v3/Policies/IpsProtocolCheck/name/{name}", ("name",)),
    "ips_rules": _spec("/api/v3/Policies/Ips"),
    "ips_rules_type": _spec("/api/v3/Policies/Ips/pId/{pid}/type/{type}", ("pid", "type")),
    "ips_custom_rule": _spec("/api/v3/Policies/IpsCustomRule/name/{name}", ("name",)),
    "av_engine": _spec("/api/v3/Policies/AvEngine"),
    "av_check_list": _spec("/api/v3/Policies/CheckList"),
    "virus_list": _spec("/api/v3/Policies/VirusList"),
    "virus_filter": _spec("/api/v3/Policies/VirusList/filter_name/{filter_name}", ("filter_name",)),
    "waf_policy_list": _spec("/api/v3/Policies/WafPolicy"),
    "waf_policy_detail": _spec("/api/v3/Policies/WafPolicy/name/{name}", ("name",)),
    "access_control_enable": _spec("/api/v3/Policies/AccessControl/policy_name/{policy_name}/enable", ("policy_name",)),
    "access_control_list": _spec("/api/v3/Policies/AccessControl/policy_name/{policy_name}", ("policy_name",)),
    "access_control_detail": _spec("/api/v3/Policies/AccessControl/policy_name/{policy_name}/id/{id}", ("policy_name", "id")),
    "waf_rule_profile": _spec("/api/v3/Policies/WafRuleProfile/name/{name}", ("name",)),
    "waf_rule_type": _spec("/api/v3/Policies/WafRuleType/policy_name/{policy_name}/type/{type}", ("policy_name", "type")),
    "anti_steal_link": _spec("/api/v3/Policies/AntiStealLink/policy_name/{policy_name}", ("policy_name",)),
    "csrf_enable": _spec("/api/v3/Policies/CSRFDefend/policy_name/{policy_name}/enable", ("policy_name",)),
    "csrf_rule": _spec("/api/v3/Policies/CSRFDefend/policy_name/{policy_name}/url/{url}", ("policy_name", "url")),
    "cc_defend": _spec("/api/v3/Policies/CCDefend/policy_name/{policy_name}", ("policy_name",)),
    "anti_tamper": _spec("/api/v3/Policies/AntiTamper/policy_name/{policy_name}", ("policy_name",)),
    "app_hide": _spec("/api/v3/Policies/AppHide/policy_name/{policy_name}", ("policy_name",)),
    "waf_rulebase": _spec("/api/v3/Policies/WafRuleRbase"),
    "anti_tamper_url_cache": _spec("/api/v3/Policies/AntiTamperUrlCache/policy_name/{policy_name}", ("policy_name",)),
}

QOS_ACTIONS = {
    "line_list": _spec("/api/v3/Objects/QosLine"),
    "line_detail": _spec("/api/v3/Objects/QosLine/name/{name}", ("name",)),
    "channel_policy_list": _spec("/api/v3/Objects/QosChannelPolicy"),
    "channel_policy_by_line": _spec("/api/v3/Objects/QosChannelPolicy/linename/{line_name}", ("line_name",)),
    "channel_policy_detail": _spec("/api/v3/Objects/QosChannelPolicy/name/{channel_name}", ("channel_name",)),
    "admin_key": _spec("/api/v3/Objects/QosAdminKey"),
    "admin_key_writers": _spec("/api/v3/Objects/QosAdminKey/linename/{channel_name}", ("channel_name",)),
    "monitor_qos": _spec("/api/v3/Objects/MonitorQos"),
    "whitelist": _spec("/api/v3/Objects/QosWhitelist"),
}

MONITORING_ACTIONS = {
    "syslog_server": _spec("/api/v3/Objects/SyslogServer"),
    "log_saved": _spec("/api/v3/Objects/LogSaved"),
    "snmp_config": _spec("/api/v3/Objects/SnmpConfig"),
    "snmp_user_list": _spec("/api/v3/Objects/SnmpUser"),
    "snmp_user_detail": _spec("/api/v3/Objects/SnmpUser/name/{name}", ("name",)),
    "monitor_app": _spec("/api/v3/Objects/MonitorApp/range/{range}", ("range",)),
    "monitor_app_users": _spec("/api/v3/Objects/MonitorApp/range/{range}/app_name/{appname}", ("range", "appname")),
    "monitor_user": _spec("/api/v3/Objects/MonitorUser/range/{range}", ("range",)),
    "monitor_user_apps": _spec("/api/v3/Objects/MonitorUser/range/{range}/user_name/{username}", ("range", "username")),
    "monitor_app_trend_by_app": _spec("/api/v3/Objects/MonitorAppTrend/range/{range}/app_name/{appname}", ("range", "appname")),
    "monitor_app_trend_by_user": _spec("/api/v3/Objects/MonitorAppTrend/range/{range}/user_name/{username}", ("range", "username")),
    "monitor_app_trend_by_user_app": _spec("/api/v3/Objects/MonitorAppTrend/range/{range}/user_name/{username}/app_name/{appname}", ("range", "username", "appname")),
    "who_online": _spec("/api/v3/Objects/Who"),
    "admin_block_user": _spec("/api/v3/Objects/AdminBlockUser"),
}

VPN_ACTIONS = {
    "ike_list": _spec("/api/v3/Policies/Ike"),
    "ike_filter": _spec("/api/v3/Policies/Ike/filter_ikename/{name}", ("name",)),
    "ike_detail": _spec("/api/v3/Policies/Ike/name/{name}", ("name",)),
    "ipsec_by_ike": _spec("/api/v3/Policies/IPsecVPN/ike_name/{ike_name}", ("ike_name",)),
    "ipsec_filter": _spec("/api/v3/Policies/IPsecVPN/ike_name/{ike_name}/name/{name}", ("ike_name", "name")),
    "ipsec_detail": _spec("/api/v3/Policies/IPsecVPN/name/{name}", ("name",)),
    "ipsec_tunnel_list": _spec("/api/v3/Policies/IpsecTunnel"),
    "ipsec_tunnel_filter": _spec("/api/v3/Policies/IpsecTunnel/filter_ipseif/{tunnel_ifname}", ("tunnel_ifname",)),
    "ipsec_tunnel_detail": _spec("/api/v3/Policies/IpsecTunnel/tunn_ifname/{tunnel_ifname}", ("tunnel_ifname",)),
    "ike_sa_list": _spec("/api/v3/Policies/IkeSa"),
    "ike_sa_filter": _spec("/api/v3/Policies/IkeSa/filter_name/{name}/filter_local_addr/{local_addr}/filter_peer_addr/{peer_addr}", ("name", "local_addr", "peer_addr")),
    "ipsec_sa_list": _spec("/api/v3/Policies/IpsecSa"),
    "ipsec_sa_detail": _spec("/api/v3/Policies/IpsecSa/sa_id/{sa_id}", ("sa_id",)),
    "easy_ipsec": _spec("/api/v3/Policies/EasyIpsec"),
    "easy_ipsec_sa_list": _spec("/api/v3/Policies/EasyIpsecSa"),
    "easy_ipsec_sa_filter": _spec("/api/v3/Policies/EasyIpsecSa/filter_name/{name}/filter_local_addr/{local_addr}/filter_peer_addr/{peer_addr}/filter_peer_subnet/{peer_subnet}", ("name", "local_addr", "peer_addr", "peer_subnet")),
    "easy_ipsec_sa_detail": _spec("/api/v3/Policies/EasyIpsecSa/name/{name}", ("name",)),
}

SYSTEM_ACTIONS = {
    "host_info": _spec("/api/v3/Objects/HostInfo"),
    "system_resource_info": _spec("/api/v3/Objects/SystemResourceInfo"),
    "license": _spec("/api/v3/Objects/License"),
    "management_config": _spec("/api/v3/Objects/ManagementConfig"),
    "timezone": _spec("/api/v3/Objects/Timezone"),
    "time_config": _spec("/api/v3/Objects/TimeConfig"),
    "auto_update": _spec("/api/v3/Objects/AutoUpdate"),
    "update_log": _spec("/api/v3/Objects/UpdateLog"),
    "interface_deploy_list": _spec("/api/v3/Objects/InterfaceDeploy"),
    "interface_deploy_detail": _spec("/api/v3/Objects/InterfaceDeploy/name/{interface_name}", ("interface_name",)),
    "dhcp_service_list": _spec("/api/v3/Objects/DHCPService"),
    "dhcp_service_interface": _spec("/api/v3/Objects/DHCPService/ifname/{ifname}", ("ifname",)),
    "dhcp_server_list": _spec("/api/v3/Objects/DHCPServer"),
    "dhcp_server_detail": _spec("/api/v3/Objects/DHCPServer/server_name/{server_name}", ("server_name",)),
    "dhcp_server_filter": _spec("/api/v3/Objects/DHCPServer/filter_name/{filter_name}", ("filter_name",)),
    "dhcp_exclusion_list": _spec("/api/v3/Objects/DHCPExclusion"),
    "dhcp_exclusion_detail_v4": _spec("/api/v3/Objects/DHCPExclusion/id/{id}/ip_start/{ip_start}/ip_end/{ip_end}", ("id", "ip_start", "ip_end")),
    "dhcp_exclusion_detail_v6": _spec("/api/v3/Objects/DHCPv6Exclusion/start_ip/{start_ip}/end_ip/{end_ip}", ("start_ip", "end_ip")),
    "dhcp_exclusion_filter": _spec("/api/v3/Objects/DHCPExclusion/filter_srcaddr/{filter_srcaddr}/filter_dstaddr/{filter_dstaddr}", ("filter_srcaddr", "filter_dstaddr")),
    "dhcp_ipbind_list": _spec("/api/v3/Objects/DHCPIpbind"),
    "dhcp_ipbind_detail": _spec("/api/v3/Objects/DHCPIpbind/bind_name/{bind_name}", ("bind_name",)),
    "dhcp_ipbind_filter": _spec("/api/v3/Objects/DHCPIpbind/filter_name/{filter_name}", ("filter_name",)),
    "dhcp_ipstatus_list": _spec("/api/v3/Objects/DHCPIpstatus"),
    "dhcp_ipstatus_filter": _spec("/api/v3/Objects/DHCPIpstatus/filter_ip/{filter_ip}", ("filter_ip",)),
    "app_cache_list": _spec("/api/v3/Objects/AppCache"),
    "app_cache_domain_list": _spec("/api/v3/Objects/AppCacheDomain"),
    "app_cache_domain_detail": _spec("/api/v3/Objects/AppCacheDomain/domain/{domain}", ("domain",)),
    "user_share_config": _spec("/api/v3/Objects/UserShareConfig"),
}

ACTION_GROUPS = {
    "network": NETWORK_ACTIONS,
    "objects": OBJECT_ACTIONS,
    "policy": POLICY_ACTIONS,
    "security": SECURITY_ACTIONS,
    "qos": QOS_ACTIONS,
    "monitoring": MONITORING_ACTIONS,
    "vpn": VPN_ACTIONS,
    "system": SYSTEM_ACTIONS,
}

_PLACEHOLDER_RE = re.compile(r"\{+\s*([^{}]+?)\s*\}+")


def _get_raw_service() -> dict[str, Any]:
    for key in (STORAGE_KEY, SERVICE_ID):
        raw = ConfigWriter.get_api_service_raw(key)
        if isinstance(raw, dict) and raw:
            return raw
    return {}


def _get_custom_setting(raw_service: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in raw_service:
        return raw_service.get(key)
    custom_settings = raw_service.get("custom_settings", {})
    if isinstance(custom_settings, dict) and key in custom_settings:
        return custom_settings.get(key)
    return default


def _resolve_base_url(raw_service: dict[str, Any]) -> str:
    raw_value = raw_service.get("base_url") or _get_custom_setting(raw_service, "base_url")
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return _strip_api_prefix(resolved.strip())

    secret_manager = security.get_secret_manager()
    host = (
        secret_manager.get("dbappsecurity_das_gateway_host")
        or secret_manager.get("das_gateway_host")
        or security.resolve_value("{env:DBAPPSECURITY_DAS_GATEWAY_HOST}")
        or security.resolve_value("{env:DAS_GATEWAY_HOST}")
    )
    if isinstance(host, str) and host.strip():
        host = host.strip().rstrip("/")
        if host.startswith(("http://", "https://")):
            return _strip_api_prefix(host)
        return f"https://{host}"
    return ""


def _strip_api_prefix(base_url: str) -> str:
    cleaned = base_url.rstrip("/")
    return cleaned[: -len("/api/v3")] if cleaned.lower().endswith("/api/v3") else cleaned


def _secret_or_setting(raw_service: dict[str, Any], key: str, secret_names: tuple[str, ...], env_names: tuple[str, ...]) -> str:
    raw_value = (
        raw_service.get(key)
        or raw_service.get(key.replace("_", ""))
        or _get_custom_setting(raw_service, key)
        or _get_custom_setting(raw_service, key.replace("_", ""))
    )
    if raw_value:
        resolved = security.resolve_value(raw_value)
        if isinstance(resolved, str) and resolved.strip():
            return resolved.strip()

    secret_manager = security.get_secret_manager()
    for secret_name in secret_names:
        value = secret_manager.get(secret_name)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for env_name in env_names:
        value = security.resolve_value(f"{{env:{env_name}}}")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _resolve_auth(raw_service: dict[str, Any]) -> tuple[str, str]:
    username = _secret_or_setting(
        raw_service,
        "username",
        ("dbappsecurity_das_gateway_username", "das_gateway_username"),
        ("DBAPPSECURITY_DAS_GATEWAY_USERNAME", "DAS_GATEWAY_USERNAME"),
    )
    password = _secret_or_setting(
        raw_service,
        "password",
        ("dbappsecurity_das_gateway_password", "das_gateway_password"),
        ("DBAPPSECURITY_DAS_GATEWAY_PASSWORD", "DAS_GATEWAY_PASSWORD"),
    )
    return username, password


def _verify_ssl(raw_service: dict[str, Any]) -> bool:
    raw_value = raw_service.get("verify_ssl")
    if raw_value is None:
        raw_value = raw_service.get("ssl_verify")
    if raw_value is None:
        raw_value = _get_custom_setting(raw_service, "verify_ssl", True)
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, str):
        return raw_value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw_value)


def _resolve_timeout(raw_service: dict[str, Any]) -> int:
    raw_value = raw_service.get("timeout") or _get_custom_setting(raw_service, "timeout", DEFAULT_TIMEOUT)
    try:
        timeout = int(raw_value)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    return max(1, timeout)


def _clean_mapping(values: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        cleaned[key] = value
    return cleaned


def _pagination_from_headers(headers: Any) -> dict[str, Any]:
    mapping = {
        "current_page": "X-Pagination-Current-Page",
        "page_count": "X-Pagination-Page-Count",
        "per_page": "X-Pagination-Per-Page",
        "total_count": "X-Pagination-Total-Count",
    }
    result: dict[str, Any] = {}
    for target, header in mapping.items():
        value = headers.get(header) if headers else None
        if value is None:
            continue
        try:
            result[target] = int(value)
        except (TypeError, ValueError):
            result[target] = value
    return result


def _payload_error(payload: Any) -> str | None:
    if not isinstance(payload, dict) or "code" not in payload:
        return None
    code = payload.get("code")
    if code in (None, 0, 1, 200, "0", "1", "200"):
        return None
    message = payload.get("msg") or payload.get("message") or payload.get("error")
    return f"明御安全网关 API 返回失败（code={code}）：{message or '未提供失败原因'}"


def _pick_output(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def _http_error_message(status: int, text: str) -> str:
    if status == 401:
        return "明御安全网关拒绝了本次连接。请确认 Basic Auth 用户名和密码正确，且该账号有 RESTful API 权限。"
    if status == 403:
        return "明御安全网关返回 403。请确认账号权限、管理接口 HTTPS 服务和 RESTful API 服务已开启。"
    if status == 404:
        return "明御安全网关未找到该 API 路径，请确认设备版本为 V3.0-6.0r 或兼容版本。"
    return f"明御安全网关 API 请求失败：HTTP {status}，响应片段：{text[:300]}"


def _build_path(path: str, path_params: dict[str, Any] | None) -> tuple[str | None, str | None]:
    params = path_params or {}
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        value = params.get(key)
        if value is None:
            value = params.get(key.replace("-", "_"))
        if value is None:
            missing.append(key)
            return match.group(0)
        return quote(str(value), safe="%")

    rendered = _PLACEHOLDER_RE.sub(replace, path)
    if missing:
        return None, "缺少 path_params 参数：" + ", ".join(dict.fromkeys(missing))
    return rendered, None


def _build_query(
    *,
    query: dict[str, Any] | None,
    page: int | None,
    count: int | None,
    language: str | None,
) -> dict[str, Any]:
    params = dict(query or {})
    if page is not None:
        params.setdefault("page", page)
    if count is not None:
        params.setdefault("count", count)
    if language:
        params.setdefault("language", language)
    return _clean_mapping(params)


async def _request_get(
    path: str,
    *,
    api_name: str,
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    raw_service = _get_raw_service()
    base_url = _resolve_base_url(raw_service)
    username, password = _resolve_auth(raw_service)
    if not base_url:
        return ToolResult(success=False, error="明御安全网关 Base URL 未配置，请在 Device Integration 中填写设备地址。")
    if not username or not password:
        return ToolResult(success=False, error="明御安全网关 Basic Auth 用户名或密码未配置，请在 Device Integration 中更新凭据。")

    rendered_path, path_error = _build_path(path, path_params)
    if path_error:
        return ToolResult(success=False, error=path_error)

    url = urljoin(f"{base_url}/", rendered_path.lstrip("/"))
    request_params = _build_query(query=query, page=page, count=count, language=language)
    timeout = aiohttp.ClientTimeout(total=_resolve_timeout(raw_service))
    connector = aiohttp.TCPConnector(ssl=_verify_ssl(raw_service))
    metadata = {"source": "DBAPPSecurity DAS-Gateway", "api": api_name, "path": rendered_path}

    try:
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            kwargs: dict[str, Any] = {"auth": aiohttp.BasicAuth(username, password)}
            if request_params:
                kwargs["params"] = request_params
            async with session.request("GET", url, **kwargs) as response:
                text = await response.text()
                metadata["pagination"] = _pagination_from_headers(response.headers)
                if response.status >= 400:
                    return ToolResult(success=False, error=_http_error_message(response.status, text), metadata=metadata)
                try:
                    payload = json.loads(text) if text else {}
                except json.JSONDecodeError:
                    return ToolResult(success=True, output=text, metadata=metadata)
    except aiohttp.ClientError as exc:
        return ToolResult(success=False, error=f"无法连接明御安全网关：{exc}", metadata=metadata)
    except Exception as exc:
        return ToolResult(success=False, error=f"调用明御安全网关 API 时发生异常：{exc}", metadata=metadata)

    error = _payload_error(payload)
    if error:
        return ToolResult(success=False, error=error, output=payload, metadata=metadata)
    return ToolResult(success=True, output=_pick_output(payload), metadata=metadata)


async def health(ctx: ToolContext, include_license: bool = True) -> ToolResult:
    actions = ["host_info", "system_resource_info"]
    if include_license:
        actions.append("license")

    output: dict[str, Any] = {}
    metadata: dict[str, Any] = {"source": "DBAPPSecurity DAS-Gateway", "api": "health"}
    for action in actions:
        result = await _request_get(SYSTEM_ACTIONS[action]["path"], api_name=f"health.{action}", language="CN")
        if not result.success:
            return ToolResult(success=False, error=result.error, output=output or result.output, metadata={**metadata, **(result.metadata or {})})
        output[action] = result.output
    return ToolResult(success=True, output=output, metadata=metadata)


async def _read_action(
    group: str,
    action: str,
    *,
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    actions = ACTION_GROUPS[group]
    spec = actions.get(action)
    if spec is None:
        return ToolResult(success=False, error=f"不支持的 {group} 动作：{action}。可选：{', '.join(actions)}")
    required = spec.get("required") or []
    supplied = path_params or {}
    missing = [key for key in required if supplied.get(key) in (None, "")]
    if missing:
        return ToolResult(success=False, error="缺少 path_params 参数：" + ", ".join(missing))
    return await _request_get(
        spec["path"],
        api_name=f"{group}.{action}",
        path_params=path_params,
        query=query,
        page=page,
        count=count,
        language=language,
    )


async def network(
    ctx: ToolContext,
    action: str = "interface_list",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("network", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def objects(
    ctx: ToolContext,
    action: str = "address_list",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("objects", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def policy(
    ctx: ToolContext,
    action: str = "security_policy_list",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("policy", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def security_read(
    ctx: ToolContext,
    action: str = "arp_table",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("security", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def qos(
    ctx: ToolContext,
    action: str = "line_list",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("qos", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def monitoring(
    ctx: ToolContext,
    action: str = "monitor_app",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("monitoring", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def vpn(
    ctx: ToolContext,
    action: str = "ike_list",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("vpn", action, path_params=path_params, query=query, page=page, count=count, language=language)


async def system(
    ctx: ToolContext,
    action: str = "host_info",
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
    page: int | None = None,
    count: int | None = None,
    language: str | None = "CN",
) -> ToolResult:
    return await _read_action("system", action, path_params=path_params, query=query, page=page, count=count, language=language)
