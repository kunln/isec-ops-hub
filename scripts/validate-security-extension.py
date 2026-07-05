#!/usr/bin/env python3
"""Run an end-to-end acceptance check for the Security Extension MVP.

The script uses a temporary Flocks data directory and a temporary FastAPI app
that mounts only ``/api/security``. It does not mutate the user's real Flocks
database.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def log(message: str) -> None:
    print(f"[security-acceptance] {message}", flush=True)


def eprint(message: str) -> None:
    print(f"[security-acceptance] {message}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the Security Extension MVP API/tool/report workflow without touching real data.",
    )
    parser.add_argument(
        "--keep-data",
        action="store_true",
        help="Keep the temporary data directory and print its path for debugging.",
    )
    return parser


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


async def run_acceptance(data_dir: Path) -> dict[str, Any]:
    os.environ["FLOCKS_DATA_DIR"] = str(data_dir)

    from fastapi import FastAPI, Request
    from httpx import ASGITransport, AsyncClient

    from flocks.auth.context import AuthUser
    from flocks.config.config import Config
    from flocks.security.sample_data import SAMPLE_IDS
    from flocks.server.routes.security import router as security_router
    from flocks.storage.storage import Storage
    from flocks.tool.registry import ToolContext
    from flocks.tool.security.security_ops import (
        security_asset_risk_profile,
        security_connector_list,
        security_connector_preview,
        security_connector_test_connection,
        security_connector_validate,
        security_report_generate,
        security_vulnerability_prioritize,
    )

    Config._global_config = None
    Config._cached_config = None
    Storage._db_path = None
    Storage._initialized = False

    await Storage.init(data_dir / "flocks.db")

    app = FastAPI()

    @app.middleware("http")
    async def inject_admin(request: Request, call_next):
        request.state.auth_user = AuthUser(
            id="security-acceptance-admin",
            username="security-acceptance-admin",
            role="admin",
            status="active",
            must_reset_password=False,
        )
        return await call_next(request)

    app.include_router(security_router, prefix="/api/security")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://security-acceptance") as client:
        health = await client.get("/api/security/health")
        assert_true(health.status_code == 200, f"health failed: {health.text}")
        log("health ok")

        connectors = await client.get("/api/security/connectors")
        assert_true(connectors.status_code == 200, f"connector list failed: {connectors.text}")
        connector_ids = [item["id"] for item in connectors.json()]
        assert_true("mock-security-demo" in connector_ids, "mock connector missing")
        assert_true("fixture-replay-demo" in connector_ids, "fixture replay connector missing")
        connector_id = "mock-security-demo"
        replay_connector_id = "fixture-replay-demo"
        connector_test = await client.post(f"/api/security/connectors/{connector_id}/test")
        assert_true(connector_test.status_code == 200, f"connector test failed: {connector_test.text}")
        assert_true(bool(connector_test.json()["normalized_data"]["assets"]), "connector test missing normalized assets")
        validation = await client.post(f"/api/security/connectors/{replay_connector_id}/validate")
        assert_true(validation.status_code == 200, f"connector validation failed: {validation.text}")
        assert_true(
            validation.json()["adapter_contracts"]["asset.search"]["version"] == "connector.adapter.v1",
            "connector validation missing adapter contract",
        )
        preview = await client.post(
            f"/api/security/connectors/{replay_connector_id}/preview",
            params={"capability": "asset.search"},
        )
        assert_true(preview.status_code == 200, f"connector preview failed: {preview.text}")
        assert_true(bool(preview.json()["normalized_data"]["assets"]), "connector preview missing normalized assets")
        assert_true("items[1].ip" in preview.json()["missing_fields"], "connector preview missing expected warning")
        log("connector standardization and replay ok")

        loaded = await client.post("/api/security/sample-data/load")
        assert_true(loaded.status_code == 200, f"sample load failed: {loaded.text}")
        ids = loaded.json()["ids"]
        assert_true(ids["alert"] == SAMPLE_IDS["alert"], "sample manifest returned unexpected alert id")
        log("sample data loaded")

        assets = await client.get("/api/security/assets", params={"keyword": "portal"})
        assert_true(assets.status_code == 200, f"asset list failed: {assets.text}")
        assert_true(len(assets.json()) == 1, "expected one sample asset")
        log("asset query ok")

        profile = await client.get(f"/api/security/assets/{ids['asset']}/risk-profile")
        assert_true(profile.status_code == 200, f"asset risk profile failed: {profile.text}")
        assert_true(profile.json()["risk_score"]["score"] >= 55, "expected high-risk asset profile score")
        log("asset risk profile ok")

        vulnerabilities = await client.get("/api/security/vulnerabilities", params={"severity": "critical"})
        assert_true(vulnerabilities.status_code == 200, f"vulnerability list failed: {vulnerabilities.text}")
        assert_true(len(vulnerabilities.json()) >= 1, "expected at least one critical vulnerability")
        log("vulnerability query ok")

        priorities = await client.get("/api/security/vulnerabilities/prioritized", params={"asset_id": ids["asset"]})
        assert_true(priorities.status_code == 200, f"vulnerability priorities failed: {priorities.text}")
        assert_true(priorities.json()[0]["risk_score"]["score"] >= 80, "expected critical vulnerability priority")
        log("vulnerability prioritization ok")

        alerts = await client.get("/api/security/alerts", params={"ioc": "198.51.100.23"})
        assert_true(alerts.status_code == 200, f"alert list failed: {alerts.text}")
        assert_true(len(alerts.json()) == 1, "expected one IOC-matched alert")
        log("alert query ok")

        correlation = await client.post(f"/api/security/correlate/alert/{ids['alert']}")
        assert_true(correlation.status_code == 200, f"correlation failed: {correlation.text}")
        assert_true(correlation.json()["risk_score"]["score"] >= 55, "expected high-risk correlation score")
        log("correlation ok")

        triage = await client.post(f"/api/security/triage/alert/{ids['alert']}")
        assert_true(triage.status_code == 200, f"triage failed: {triage.text}")
        triage_payload = triage.json()
        incident_id = triage_payload.get("incident_id")
        assert_true(bool(incident_id), "triage did not create an incident")
        assert_true(triage_payload["should_create_incident"] is True, "triage should recommend incident creation")
        log(f"triage ok, incident={incident_id}")

        report = await client.post(f"/api/security/reports/incident/{incident_id}")
        assert_true(report.status_code == 200, f"report failed: {report.text}")
        assert_true("安全事件研判报告" in report.json()["content"], "incident report missing expected title")
        log("incident report ok")

        ctx = ToolContext(session_id="security-acceptance", message_id="security-acceptance", agent="security-acceptance")
        connector_tool_result = await security_connector_list(ctx)
        assert_true(connector_tool_result.success, f"security_connector_list failed: {connector_tool_result.error}")
        connector_test_tool_result = await security_connector_test_connection(ctx, connector_id=connector_id)
        assert_true(
            connector_test_tool_result.success,
            f"security_connector_test_connection failed: {connector_test_tool_result.error}",
        )
        connector_validate_tool_result = await security_connector_validate(ctx, connector_id=replay_connector_id)
        assert_true(
            connector_validate_tool_result.success,
            f"security_connector_validate failed: {connector_validate_tool_result.error}",
        )
        connector_preview_tool_result = await security_connector_preview(
            ctx,
            connector_id=replay_connector_id,
            capability="asset.search",
        )
        assert_true(
            connector_preview_tool_result.success,
            f"security_connector_preview failed: {connector_preview_tool_result.error}",
        )

        profile_tool_result = await security_asset_risk_profile(ctx, asset_id=ids["asset"])
        assert_true(profile_tool_result.success, f"security_asset_risk_profile failed: {profile_tool_result.error}")

        priority_tool_result = await security_vulnerability_prioritize(ctx, asset_id=ids["asset"])
        assert_true(priority_tool_result.success, f"security_vulnerability_prioritize failed: {priority_tool_result.error}")

        tool_result = await security_report_generate(
            ctx,
            incident_id=incident_id,
            format="markdown",
        )
        assert_true(tool_result.success, f"security_report_generate failed: {tool_result.error}")
        assert_true("安全事件研判报告" in str(tool_result.output), "tool report output missing expected title")
        log("security tool ok")

        cleared = await client.delete("/api/security/sample-data/clear")
        assert_true(cleared.status_code == 200, f"sample clear failed: {cleared.text}")
        assert_true(cleared.json()["deleted"]["assets"] == 1, "sample asset was not cleared")
        log("sample clear ok")

        assets_after_clear = await client.get("/api/security/assets", params={"keyword": "portal"})
        assert_true(assets_after_clear.status_code == 200, f"post-clear asset query failed: {assets_after_clear.text}")
        assert_true(len(assets_after_clear.json()) == 0, "sample clear left sample assets behind")
        log("post-clear verification ok")

    await Storage.shutdown()
    return {
        "data_dir": str(data_dir),
        "incident_id": incident_id,
        "status": "passed",
    }


async def amain() -> int:
    args = build_parser().parse_args()
    if args.keep_data:
        data_dir = Path(tempfile.mkdtemp(prefix="flocks-security-acceptance-"))
        result = await run_acceptance(data_dir)
        log(f"PASSED; temporary data kept at {result['data_dir']}")
        return 0

    with tempfile.TemporaryDirectory(prefix="flocks-security-acceptance-") as tmpdir:
        result = await run_acceptance(Path(tmpdir))
        log(f"PASSED; incident={result['incident_id']}")
    return 0


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        return asyncio.run(amain())
    except Exception as exc:
        eprint(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
