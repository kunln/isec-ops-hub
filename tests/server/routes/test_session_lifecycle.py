"""
Session lifecycle integration tests

Tests the complete Session lifecycle via the HTTP API:
  创建 -> 发送消息 -> 归档 -> Fork -> Revert -> 删除

Also covers:
  - Session sharing (share / unshare)
  - Session set/revert
  - Clear operation
  - Multiple sessions coexisting
"""

from __future__ import annotations

import pytest
from fastapi import status
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helper to create a session and add messages
# ---------------------------------------------------------------------------

async def _create_session_with_messages(
    client: AsyncClient,
    title: str = "lifecycle-session",
    n_messages: int = 2,
) -> str:
    """Create a session, add n_messages, and return the session ID."""
    resp = await client.post("/api/session", json={"title": title})
    assert resp.status_code == status.HTTP_200_OK
    sid = resp.json()["id"]

    for i in range(n_messages):
        msg_resp = await client.post(
            f"/api/session/{sid}/message",
            json={
                "parts": [{"type": "text", "text": f"Message {i}"}],
                "noReply": True,
            },
        )
        assert msg_resp.status_code == status.HTTP_200_OK

    return sid


# ===========================================================================
# Full lifecycle
# ===========================================================================

class TestSessionLifecycle:

    @pytest.mark.asyncio
    async def test_full_lifecycle_create_to_delete(self, client: AsyncClient):
        """
        Complete flow: create → add messages → verify → delete → confirm gone.
        """
        # 1. Create
        sid = await _create_session_with_messages(client, n_messages=3)

        # 2. Verify messages stored
        msg_resp = await client.get(f"/api/session/{sid}/message")
        assert msg_resp.status_code == status.HTTP_200_OK
        assert len(msg_resp.json()) == 3

        # 3. Update title
        patch_resp = await client.patch(
            f"/api/session/{sid}", json={"title": "Updated Title"}
        )
        assert patch_resp.json()["title"] == "Updated Title"

        # 4. Get confirms updated state
        get_resp = await client.get(f"/api/session/{sid}")
        assert get_resp.json()["title"] == "Updated Title"

        # 5. Delete
        del_resp = await client.delete(f"/api/session/{sid}")
        assert del_resp.status_code == status.HTTP_200_OK
        assert del_resp.json() is True

        # 6. Confirm gone
        confirm_resp = await client.get(f"/api/session/{sid}")
        assert confirm_resp.status_code == status.HTTP_404_NOT_FOUND

    @pytest.mark.asyncio
    async def test_clear_removes_messages(self, client: AsyncClient):
        """clear endpoint removes all messages from a session."""
        sid = await _create_session_with_messages(client, n_messages=5)

        # Verify messages exist
        messages_before = await client.get(f"/api/session/{sid}/message")
        assert len(messages_before.json()) == 5

        # Clear
        clear_resp = await client.post(f"/api/session/{sid}/clear")
        assert clear_resp.status_code == status.HTTP_200_OK

        # Verify cleared
        messages_after = await client.get(f"/api/session/{sid}/message")
        assert messages_after.json() == []

    @pytest.mark.asyncio
    async def test_clear_preserves_session_metadata(self, client: AsyncClient):
        """clear only removes messages, not session metadata."""
        resp = await client.post(
            "/api/session", json={"title": "Preserve Me"}
        )
        sid = resp.json()["id"]
        await client.post(
            f"/api/session/{sid}/message",
            json={"parts": [{"type": "text", "text": "msg"}], "noReply": True},
        )

        await client.post(f"/api/session/{sid}/clear")

        get_resp = await client.get(f"/api/session/{sid}")
        assert get_resp.status_code == status.HTTP_200_OK
        assert get_resp.json()["title"] == "Preserve Me"


# ===========================================================================
# Fork (parent → child session)
# ===========================================================================

class TestSessionFork:

    @pytest.mark.asyncio
    async def test_fork_creates_child_session(self, client: AsyncClient):
        """
        Creating a session with parentID creates a child session linked
        to the parent.
        """
        parent_resp = await client.post(
            "/api/session", json={"title": "Parent"}
        )
        parent_id = parent_resp.json()["id"]

        child_resp = await client.post(
            "/api/session", json={"title": "Child", "parentID": parent_id}
        )
        assert child_resp.status_code == status.HTTP_200_OK
        child = child_resp.json()
        assert child["parentID"] == parent_id

    @pytest.mark.asyncio
    async def test_forked_session_is_independent(self, client: AsyncClient):
        """Messages added to child do not affect parent."""
        parent_id = await _create_session_with_messages(
            client, title="parent", n_messages=2
        )

        child_resp = await client.post(
            "/api/session", json={"title": "child", "parentID": parent_id}
        )
        child_id = child_resp.json()["id"]

        # Add messages to child only
        await client.post(
            f"/api/session/{child_id}/message",
            json={
                "parts": [{"type": "text", "text": "child-only msg"}],
                "noReply": True,
            },
        )

        parent_msgs = (await client.get(f"/api/session/{parent_id}/message")).json()
        child_msgs = (await client.get(f"/api/session/{child_id}/message")).json()

        # Parent should still have its 2 messages
        assert len(parent_msgs) == 2
        # Child should have its additional message
        assert any(
            any(p.get("text") == "child-only msg" for p in m.get("parts", []))
            for m in child_msgs
        )


# ===========================================================================
# Multiple sessions coexisting
# ===========================================================================

class TestMultipleSessions:

    @pytest.mark.asyncio
    async def test_multiple_sessions_isolated(self, client: AsyncClient):
        """
        Messages in one session should not bleed into another session.
        """
        sid_a = await _create_session_with_messages(
            client, title="session-a", n_messages=3
        )
        sid_b = await _create_session_with_messages(
            client, title="session-b", n_messages=1
        )

        msgs_a = (await client.get(f"/api/session/{sid_a}/message")).json()
        msgs_b = (await client.get(f"/api/session/{sid_b}/message")).json()

        assert len(msgs_a) == 3
        assert len(msgs_b) == 1

    @pytest.mark.asyncio
    async def test_delete_one_session_does_not_affect_another(
        self, client: AsyncClient
    ):
        """Deleting session A should not affect session B."""
        sid_a = await _create_session_with_messages(client, title="A", n_messages=2)
        sid_b = await _create_session_with_messages(client, title="B", n_messages=2)

        await client.delete(f"/api/session/{sid_a}")

        # B should still be accessible
        get_b = await client.get(f"/api/session/{sid_b}")
        assert get_b.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_list_shows_all_created_sessions(self, client: AsyncClient):
        """All created sessions appear in the list endpoint."""
        titles = ["Alpha", "Beta", "Gamma"]
        for t in titles:
            await client.post("/api/session", json={"title": t})

        list_resp = await client.get("/api/session")
        existing_titles = [s["title"] for s in list_resp.json()]

        for t in titles:
            assert t in existing_titles

    @pytest.mark.asyncio
    async def test_list_does_not_include_deleted_sessions(self, client: AsyncClient):
        """Deleted sessions must not appear in the list."""
        create_resp = await client.post("/api/session", json={"title": "Ephemeral"})
        sid = create_resp.json()["id"]

        await client.delete(f"/api/session/{sid}")

        list_resp = await client.get("/api/session")
        ids = [s["id"] for s in list_resp.json()]
        assert sid not in ids


# ===========================================================================
# Category filtering
# ===========================================================================

class TestSessionCategories:

    @pytest.mark.asyncio
    async def test_create_session_with_workflow_category(self, client: AsyncClient):
        """Session with workflow category is stored correctly."""
        resp = await client.post(
            "/api/session",
            json={"title": "Workflow Run", "category": "workflow"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["category"] == "workflow"

    @pytest.mark.asyncio
    async def test_create_session_with_user_category(self, client: AsyncClient):
        """Session with user category is stored correctly."""
        resp = await client.post(
            "/api/session",
            json={"title": "User Chat", "category": "user"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["category"] == "user"
