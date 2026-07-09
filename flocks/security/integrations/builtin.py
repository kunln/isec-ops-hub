"""Built-in Integration Package metadata.

This module only declares static package and capability metadata. It does not
instantiate or call v1 connectors, perform network requests, persist raw API
responses, store raw logs, or manage credentials. A future PR can add external
manifest.yaml loading while preserving these built-in skeleton definitions.
"""

from __future__ import annotations

from flocks.security.integrations.models import (
    IntegrationCapability,
    IntegrationPackage,
    IntegrationPackageManifest,
)


def _build_package(manifest: IntegrationPackageManifest, descriptions: dict[str, str]) -> IntegrationPackage:
    return IntegrationPackage(
        manifest=manifest,
        capabilities={
            capability: IntegrationCapability(
                package_id=manifest.package_id,
                capability=capability,
                display_name=capability,
                description=descriptions.get(capability),
            )
            for capability in manifest.capabilities
        },
    )


def get_builtin_integration_packages() -> list[IntegrationPackage]:
    """Return built-in static Integration Package metadata for Phase 2."""

    tda = _build_package(
        IntegrationPackageManifest(
            package_id="asiainfo.tda",
            name="信桅高级威胁监测系统 TDA",
            vendor="AsiaInfo",
            product="TDA",
            version="builtin-skeleton-v1",
            category="security_monitoring",
            description="Built-in Integration Package skeleton for TDA metadata.",
            auth_type="hmac_sha256",
            capabilities=[
                "alert.search",
                "event.search",
                "asset.search",
                "weak_password.search",
                "plaintext_password.search",
            ],
            sensitive_fields=[
                "api_key",
                "secret",
                "sign",
                "auth_timestamp",
                "login_password",
                "login_password_encrypted",
                "http_req_body",
                "http_resp_body",
            ],
            raw_response_policy="transient_only",
            raw_log_storage="forbidden",
        ),
        {
            "alert.search": "Search TDA alert metadata.",
            "event.search": "Search TDA event metadata.",
            "asset.search": "Search TDA asset metadata.",
        },
    )
    mingyu_apt = _build_package(
        IntegrationPackageManifest(
            package_id="dbappsecurity.mingyu_apt",
            name="明御APT攻击预警平台",
            vendor="DBAPPSecurity",
            product="Mingyu APT",
            version="builtin-skeleton-v1",
            category="security_monitoring",
            description="Built-in Integration Package skeleton for Mingyu APT metadata.",
            auth_type="api_key_header",
            capabilities=[
                "alert.search",
                "event.search",
                "risk.search",
                "important_event.search",
            ],
            sensitive_fields=[
                "api_key",
                "apikey",
                "token",
                "password",
                "rawdata",
                "raw_payload",
                "request",
                "response",
            ],
            raw_response_policy="transient_only",
            raw_log_storage="forbidden",
        ),
        {
            "alert.search": "Search Mingyu APT alert metadata.",
            "event.search": "Search Mingyu APT event metadata.",
            "risk.search": "Search Mingyu APT risk metadata.",
            "important_event.search": "Search Mingyu APT important event metadata.",
        },
    )
    return [tda, mingyu_apt]
