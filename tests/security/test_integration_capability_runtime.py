from __future__ import annotations

from flocks.security.integrations import (
    IntegrationCapabilityRunRequest,
    IntegrationCapabilityRuntime,
    is_destructive_capability,
    sanitize_run_params,
)


def test_default_runtime_uses_builtin_registry() -> None:
    runtime = IntegrationCapabilityRuntime()

    package_ids = {package.manifest.package_id for package in runtime.registry.list_packages()}

    assert "asiainfo.tda" in package_ids
    assert "dbappsecurity.mingyu_apt" in package_ids


def test_tda_alert_search_dry_run_returns_planned() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="alert.search", params={"limit": 10})
    )

    assert result.status == "planned"
    assert result.result_summary["dry_run_only"] is True


def test_mingyu_risk_search_dry_run_returns_planned() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="dbappsecurity.mingyu_apt", capability="risk.search")
    )

    assert result.status == "planned"


def test_unknown_package_returns_validation_failed() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="unknown.package", capability="alert.search")
    )

    assert result.status == "validation_failed"
    assert result.error_summary is not None


def test_unknown_capability_returns_validation_failed() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="risk.search")
    )

    assert result.status == "validation_failed"
    assert result.error_summary is not None


def test_non_dry_run_returns_not_implemented() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="alert.search", dry_run=False)
    )

    assert result.status == "not_implemented"
    assert result.error_summary is not None


def test_sensitive_params_are_sanitized() -> None:
    sanitized = sanitize_run_params(
        {
            "api_key": "plain-api-key",
            "secret": "plain-secret",
            "token": "plain-token",
            "password": "plain-password",
            "sign": "plain-sign",
            "auth_timestamp": "plain-auth-ts",
            "safe": "visible",
        }
    )

    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["secret"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["sign"] == "[REDACTED]"
    assert sanitized["auth_timestamp"] == "[REDACTED]"
    assert sanitized["safe"] == "visible"


def test_nested_sensitive_params_are_sanitized() -> None:
    sanitized = sanitize_run_params(
        {
            "filters": [
                {"authorization": "Bearer plain-token"},
                {"nested": {"cookie": "session=plain", "value": "ok"}},
            ]
        }
    )

    assert sanitized["filters"][0]["authorization"] == "[REDACTED]"
    assert sanitized["filters"][1]["nested"]["cookie"] == "[REDACTED]"
    assert sanitized["filters"][1]["nested"]["value"] == "ok"


def test_destructive_ip_block_is_rejected() -> None:
    assert is_destructive_capability("ip.block") is True
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="ip.block")
    )

    assert result.status == "rejected"


def test_destructive_policy_update_is_rejected() -> None:
    assert is_destructive_capability("policy.update") is True
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="policy.update")
    )

    assert result.status == "rejected"


def test_run_does_not_call_v1_connectors(monkeypatch) -> None:
    def fail_import(name, *args, **kwargs):
        if name.startswith("flocks.security.connectors"):
            raise AssertionError("v1 connector import attempted")
        return original_import(name, *args, **kwargs)

    original_import = __import__
    monkeypatch.setattr("builtins.__import__", fail_import)

    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="alert.search")
    )

    assert result.status == "planned"


def test_run_does_not_create_security_objects(monkeypatch) -> None:
    def fail_import(name, *args, **kwargs):
        forbidden = ("evidence", "alert", "analysis", "incident")
        if name.startswith("flocks.security") and any(part in name.lower() for part in forbidden):
            raise AssertionError("security object module import attempted")
        return original_import(name, *args, **kwargs)

    original_import = __import__
    monkeypatch.setattr("builtins.__import__", fail_import)

    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(package_id="dbappsecurity.mingyu_apt", capability="risk.search")
    )

    assert result.status == "planned"
    assert result.result_summary["safety_summary"]["security_object_creation"] == "disabled"


def test_request_summary_does_not_contain_raw_secret_value() -> None:
    result = IntegrationCapabilityRuntime().run(
        IntegrationCapabilityRunRequest(
            package_id="asiainfo.tda",
            capability="alert.search",
            params={"secret": "do-not-leak", "nested": {"token": "also-do-not-leak"}},
        )
    )

    summary_text = str(result.request_summary)
    assert "do-not-leak" not in summary_text
    assert "also-do-not-leak" not in summary_text
    assert "[REDACTED]" in summary_text


def test_capability_summary_contains_package_vendor_product_capability() -> None:
    plan = IntegrationCapabilityRuntime().build_plan(
        IntegrationCapabilityRunRequest(package_id="asiainfo.tda", capability="alert.search")
    )

    assert plan.capability_summary["package_id"] == "asiainfo.tda"
    assert plan.capability_summary["vendor"] == "AsiaInfo"
    assert plan.capability_summary["product"] == "TDA"
    assert plan.capability_summary["capability"] == "alert.search"


def test_safety_summary_contains_raw_response_and_log_policies() -> None:
    plan = IntegrationCapabilityRuntime().build_plan(
        IntegrationCapabilityRunRequest(package_id="dbappsecurity.mingyu_apt", capability="risk.search")
    )

    assert plan.safety_summary["raw_response_policy"] == "transient_only"
    assert plan.safety_summary["raw_log_storage"] == "forbidden"
