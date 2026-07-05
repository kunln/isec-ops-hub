"""
Concurrency and safety tests

Covers:
  - Concurrent session creation (race conditions)
  - Concurrent message sending to the same session
  - Concurrent session deletion and read (no panics)
  - SQLite concurrent write safety via Storage
  - Multiple independent requests: result set correctness
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest
from fastapi import status
from httpx import AsyncClient


# ===========================================================================
# Concurrent session operations
# ===========================================================================

class TestConcurrentSessionOperations:

    @pytest.mark.asyncio
    async def test_concurrent_session_creation_all_succeed(
        self, client: AsyncClient
    ):
        """
        50 concurrent POST /api/session requests should all return 200 and
        each produce a unique session ID.
        """
        n = 50

        async def create_one(idx: int) -> str:
            resp = await client.post(
                "/api/session", json={"title": f"concurrent-{idx}"}
            )
            assert resp.status_code == status.HTTP_200_OK, (
                f"Request {idx} failed: {resp.text}"
            )
            return resp.json()["id"]

        ids = await asyncio.gather(*[create_one(i) for i in range(n)])

        # All IDs should be unique
        assert len(set(ids)) == n, "Duplicate session IDs detected"

    @pytest.mark.asyncio
    async def test_concurrent_session_listing_is_consistent(
        self, client: AsyncClient
    ):
        """
        Concurrent list requests should all return the same sessions (no
        torn reads).
        """
        # Pre-create some sessions
        for i in range(10):
            await client.post("/api/session", json={"title": f"pre-{i}"})

        # Issue 20 concurrent list requests
        resps = await asyncio.gather(
            *[client.get("/api/session") for _ in range(20)]
        )
        counts = [len(r.json()) for r in resps]

        # All responses should return the same count (no partial writes visible)
        assert len(set(counts)) == 1, (
            f"Inconsistent list counts: {counts}"
        )

    @pytest.mark.asyncio
    async def test_concurrent_message_sending_to_same_session(
        self, client: AsyncClient, session_id: str
    ):
        """
        Multiple concurrent noReply messages to the same session should all
        succeed without data corruption.
        """
        n = 20

        async def send_one(idx: int):
            resp = await client.post(
                f"/api/session/{session_id}/message",
                json={
                    "parts": [{"type": "text", "text": f"msg-{idx}"}],
                    "noReply": True,
                },
            )
            assert resp.status_code == status.HTTP_200_OK

        await asyncio.gather(*[send_one(i) for i in range(n)])

        # All messages should have been stored
        list_resp = await client.get(f"/api/session/{session_id}/message")
        assert list_resp.status_code == status.HTTP_200_OK
        assert len(list_resp.json()) == n

    @pytest.mark.asyncio
    async def test_concurrent_create_and_delete(self, client: AsyncClient):
        """
        Concurrent creates and deletes should not result in 500 errors.
        """
        # Pre-create sessions to delete
        create_resps = await asyncio.gather(
            *[client.post("/api/session", json={"title": f"del-{i}"}) for i in range(10)]
        )
        ids_to_delete = [r.json()["id"] for r in create_resps]

        async def do_create():
            resp = await client.post("/api/session", json={"title": "new"})
            return resp.status_code

        async def do_delete(sid: str):
            resp = await client.delete(f"/api/session/{sid}")
            return resp.status_code

        tasks = (
            [do_create() for _ in range(10)]
            + [do_delete(sid) for sid in ids_to_delete]
        )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"Exceptions during concurrent ops: {errors}"

        status_codes = [r for r in results if isinstance(r, int)]
        server_errors = [s for s in status_codes if s >= 500]
        assert not server_errors, (
            f"Server errors during concurrent ops: {server_errors}"
        )


# ===========================================================================
# Storage (SQLite) concurrent write safety
# ===========================================================================

class TestStorageConcurrency:

    @pytest.mark.asyncio
    async def test_concurrent_writes_all_persist(self):
        """
        Concurrent writes to the same Storage should all succeed and be
        retrievable afterwards.  Uses the isolated_env DB (already initialised).
        """
        from flocks.storage.storage import Storage

        n = 30

        async def write_one(i: int):
            await Storage.write(
                ["concurrent", "test", f"key-{i}"],
                {"value": i},
            )

        await asyncio.gather(*[write_one(i) for i in range(n)])

        # Verify all writes are retrievable
        missing = []
        for i in range(n):
            try:
                result = await Storage.read(["concurrent", "test", f"key-{i}"])
                assert result["value"] == i
            except Storage.NotFoundError:
                missing.append(i)

        assert not missing, f"Missing storage keys: {missing}"

    @pytest.mark.asyncio
    async def test_concurrent_read_write_no_torn_data(self):
        """
        Concurrent reads during writes should never return corrupt data.
        """
        from flocks.storage.storage import Storage

        # Seed initial value
        await Storage.write(["rw", "item"], {"counter": 0})

        errors: List[Exception] = []

        async def reader():
            for _ in range(10):
                try:
                    data = await Storage.read(["rw", "item"])
                    assert isinstance(data.get("counter"), int)
                except Storage.NotFoundError:
                    pass
                except Exception as e:
                    errors.append(e)
                await asyncio.sleep(0)

        async def writer(n: int):
            for i in range(n):
                try:
                    await Storage.write(["rw", "item"], {"counter": i})
                except Exception as e:
                    errors.append(e)
                await asyncio.sleep(0)

        await asyncio.gather(
            *[reader() for _ in range(5)],
            *[writer(10) for _ in range(5)],
        )

        assert not errors, f"Errors during concurrent read/write: {errors}"

    @pytest.mark.asyncio
    async def test_concurrent_delete_and_get_no_crash(self):
        """
        Deleting a key while another coroutine reads it should not crash.
        """
        from flocks.storage.storage import Storage

        await Storage.write(["volatile", "key"], {"data": "hello"})

        errors: List[Exception] = []

        async def try_get():
            for _ in range(5):
                try:
                    await Storage.read(["volatile", "key"])
                except Storage.NotFoundError:
                    pass
                except Exception as e:
                    errors.append(e)
                await asyncio.sleep(0)

        async def try_delete():
            for _ in range(5):
                try:
                    await Storage.remove(["volatile", "key"])
                except Storage.NotFoundError:
                    pass
                except Exception as e:
                    errors.append(e)
                await asyncio.sleep(0)

        await asyncio.gather(try_get(), try_delete())

        assert not errors, f"Unexpected errors: {errors}"


# ===========================================================================
# Request isolation
# ===========================================================================

class TestRequestIsolation:

    @pytest.mark.asyncio
    async def test_session_state_not_shared_across_requests(
        self, client: AsyncClient
    ):
        """
        Each session should maintain its own independent message list.
        """
        # Create two sessions and add different messages
        resp_a = await client.post("/api/session", json={"title": "A"})
        resp_b = await client.post("/api/session", json={"title": "B"})
        sid_a = resp_a.json()["id"]
        sid_b = resp_b.json()["id"]

        await client.post(
            f"/api/session/{sid_a}/message",
            json={"parts": [{"type": "text", "text": "from-A"}], "noReply": True},
        )
        await client.post(
            f"/api/session/{sid_b}/message",
            json={"parts": [{"type": "text", "text": "from-B"}], "noReply": True},
        )

        msgs_a = (await client.get(f"/api/session/{sid_a}/message")).json()
        msgs_b = (await client.get(f"/api/session/{sid_b}/message")).json()

        texts_a = {p["text"] for m in msgs_a for p in m.get("parts", [])}
        texts_b = {p["text"] for m in msgs_b for p in m.get("parts", [])}

        assert "from-A" in texts_a
        assert "from-B" not in texts_a
        assert "from-B" in texts_b
        assert "from-A" not in texts_b
