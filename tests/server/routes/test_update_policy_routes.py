from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_update_check_disabled_does_not_call_external_release_api(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from flocks.commercial.models import ConnectivityUpdate, UpdatePolicyUpdate
    from flocks.commercial.store import default_store
    from flocks.updater import updater

    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=True))
    await default_store.update_update_policy(
        UpdatePolicyUpdate(
            update_check_enabled=False,
            legacy_flocks_update_sources_enabled=True,
        )
    )

    calls: list[str] = []

    async def fake_fetch(*args, **kwargs):
        calls.append("external")
        return "9999.1.1", None, None, None, None

    monkeypatch.setattr(updater, "_fetch_github_release", fake_fetch)
    monkeypatch.setattr(updater, "_fetch_gitee_release", fake_fetch)
    monkeypatch.setattr(updater, "_fetch_gitlab_release", fake_fetch)

    response = await client.get("/api/update/check")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["update_allowed"] is False
    assert payload["has_update"] is False
    assert "disabled" in payload["error"].lower()
    assert calls == []


@pytest.mark.asyncio
async def test_legacy_update_sources_disabled_does_not_call_external_release_api(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from flocks.commercial.models import ConnectivityUpdate, UpdatePolicyUpdate
    from flocks.commercial.store import default_store
    from flocks.updater import updater

    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=True))
    await default_store.update_update_policy(
        UpdatePolicyUpdate(
            update_check_enabled=True,
            legacy_flocks_update_sources_enabled=False,
        )
    )

    calls: list[str] = []

    async def fake_fetch(*args, **kwargs):
        calls.append("external")
        return "9999.1.1", None, None, None, None

    monkeypatch.setattr(updater, "_fetch_github_release", fake_fetch)
    monkeypatch.setattr(updater, "_fetch_gitee_release", fake_fetch)
    monkeypatch.setattr(updater, "_fetch_gitlab_release", fake_fetch)

    response = await client.get("/api/update/check")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["update_allowed"] is False
    assert payload["has_update"] is False
    assert "legacy" in payload["error"].lower()
    assert calls == []


@pytest.mark.asyncio
async def test_update_apply_disabled_rejects_before_download(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from flocks.commercial.models import ConnectivityUpdate, UpdatePolicyUpdate
    from flocks.commercial.store import default_store
    from flocks.updater import updater

    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=True))
    await default_store.update_update_policy(
        UpdatePolicyUpdate(
            update_apply_enabled=False,
            legacy_flocks_update_sources_enabled=True,
        )
    )

    async def fail_download(*args, **kwargs):
        raise AssertionError("update download should not start when apply is disabled")

    monkeypatch.setattr(updater, "_download_archive", fail_download)

    response = await client.post("/api/update/apply", params={"target_version": "2099.1.1"})

    assert response.status_code == 403, response.text
    assert "applying updates is disabled" in response.text.lower()


@pytest.mark.asyncio
async def test_outbound_disabled_rejects_update_apply_before_download(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from flocks.commercial.models import ConnectivityUpdate, UpdatePolicyUpdate
    from flocks.commercial.store import default_store
    from flocks.updater import updater

    await default_store.update_connectivity(ConnectivityUpdate(outbound_enabled=False))
    await default_store.update_update_policy(
        UpdatePolicyUpdate(
            update_apply_enabled=True,
            legacy_flocks_update_sources_enabled=True,
        )
    )

    async def fail_download(*args, **kwargs):
        raise AssertionError("update download should not start when outbound is disabled")

    monkeypatch.setattr(updater, "_download_archive", fail_download)

    response = await client.post("/api/update/apply", params={"target_version": "2099.1.1"})

    assert response.status_code == 403, response.text
    assert "update download" in response.text
