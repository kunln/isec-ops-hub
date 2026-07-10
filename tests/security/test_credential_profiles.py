"""Tests for Integration Credential Profile metadata skeleton."""

from __future__ import annotations

from pathlib import Path

import pytest

from flocks.security.integrations import (
    CredentialProfile,
    CredentialProfileCreate,
    CredentialProfileStore,
    CredentialProfileUpdate,
    default_credential_profile_store,
    resolve_credential_profile_ref,
)
from flocks.security.integrations.credential_profiles import PersistentCredentialProfileStore
from flocks.storage.storage import Storage


@pytest.fixture
async def storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FLOCKS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLOCKS_CONFIG_DIR", str(tmp_path / "config"))
    from flocks.config.config import Config

    Config._global_config = None
    Config._cached_config = None
    Storage._db_path = None
    Storage._initialized = False
    await Storage.init(tmp_path / "flocks.db")
    yield
    await Storage.clear()
    Storage._db_path = None
    Storage._initialized = False
    Config._global_config = None
    Config._cached_config = None


def test_exports_include_credential_profile_symbols() -> None:
    assert CredentialProfile is not None
    assert CredentialProfileCreate is not None
    assert CredentialProfileStore is not None
    assert CredentialProfileUpdate is not None
    assert default_credential_profile_store is not None
    assert resolve_credential_profile_ref is not None


def test_in_memory_store_keeps_metadata_only() -> None:
    store = CredentialProfileStore()
    profile = store.create_profile(
        CredentialProfileCreate(
            profile_id="profile-a",
            package_id="asiainfo.tda",
            display_name="TDA credentials",
            secret_ref="secret://tda/profile-a",
            metadata={"region": "cn"},
        )
    )
    dumped = profile.model_dump(mode="json")
    assert dumped["profile_id"] == "profile-a"
    assert dumped["metadata"] == {"region": "cn"}
    assert "api_key" not in str(dumped).lower()
    assert "password" not in str(dumped).lower()


def test_secret_like_metadata_rejected() -> None:
    store = CredentialProfileStore()
    with pytest.raises(ValueError):
        store.create_profile(CredentialProfileCreate(display_name="bad", metadata={"api_key": "x"}))
    with pytest.raises(ValueError):
        store.create_profile(CredentialProfileCreate(display_name="bad", metadata={"note": "Bearer abc"}))


@pytest.mark.asyncio
async def test_persistent_store_and_resolve_reference(storage) -> None:
    store = PersistentCredentialProfileStore()
    created = await store.create_profile(CredentialProfileCreate(profile_id="profile-b", display_name="Profile B"))
    resolved = await resolve_credential_profile_ref(created.profile_id, store=store)
    assert resolved is not None
    assert resolved.profile_id == "profile-b"


@pytest.mark.asyncio
async def test_reinstantiated_store_reads_existing_profile(storage) -> None:
    store = PersistentCredentialProfileStore()
    created = await store.create_profile(CredentialProfileCreate(display_name="Profile C", metadata={"safe": "value"}))
    reinstantiated = PersistentCredentialProfileStore()
    fetched = await reinstantiated.get_profile(created.profile_id)
    assert fetched is not None
    assert fetched.metadata == {"safe": "value"}


@pytest.mark.asyncio
async def test_update_and_delete_profile(storage) -> None:
    store = PersistentCredentialProfileStore()
    created = await store.create_profile(CredentialProfileCreate(display_name="Profile D"))
    updated = await store.update_profile(created.profile_id, CredentialProfileUpdate(display_name="Profile D2"))
    deleted = await store.delete_profile(created.profile_id)
    fetched = await store.get_profile(created.profile_id)
    assert updated is not None
    assert updated.display_name == "Profile D2"
    assert deleted is True
    assert fetched is None
