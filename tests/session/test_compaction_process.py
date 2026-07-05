"""
Tests for SessionCompaction in flocks/session/lifecycle/compaction.py

Covers:
- SessionCompaction.is_overflow(): token overflow detection
- SessionCompaction.prune(): prune_disabled flag
- CompactionPolicy integration with is_overflow
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from flocks.session.lifecycle.compaction import (
    CompactionPolicy,
    ContextTier,
    SessionCompaction,
)


# ---------------------------------------------------------------------------
# is_overflow(): basic overflow detection
# ---------------------------------------------------------------------------

class TestIsOverflow:
    @pytest.mark.asyncio
    async def test_auto_disabled_always_false(self):
        tokens = {"input": 900000, "output": 0, "cache": {"read": 0}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
            auto_disabled=True,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_zero_context_always_false(self):
        tokens = {"input": 999999, "output": 0}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=0,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_below_usable_not_overflow(self):
        # context=100k, output=32k → usable=68k; tokens=50k → no overflow
        tokens = {"input": 50000, "output": 0, "cache": {"read": 0}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_above_usable_is_overflow(self):
        # context=100k, output=32k → usable=68k; tokens=70k → overflow
        tokens = {"input": 70000, "output": 0, "cache": {"read": 0}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_cache_read_counted_in_total(self):
        # input=30k, cache.read=40k → total=70k; context=100k, usable=68k → overflow
        tokens = {"input": 30000, "output": 0, "cache": {"read": 40000}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_model_input_limit_used_when_provided(self):
        # model_input=80k explicitly; tokens=85k → overflow
        tokens = {"input": 85000, "output": 0}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=200000,
            model_input=80000,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_with_policy_below_threshold(self):
        # claude-3-5-sonnet context: 200k tokens, output: 8192
        policy = CompactionPolicy.from_model(200000, 8192)
        tokens = {"input": 1000, "output": 0, "cache": {"read": 0}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=200000,
            policy=policy,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_with_policy_above_threshold(self):
        policy = CompactionPolicy.from_model(200000, 8192)
        # Set tokens to exceed the policy's overflow_threshold
        tokens = {
            "input": policy.overflow_threshold + 5000,
            "output": 0,
            "cache": {"read": 0},
        }
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=200000,
            policy=policy,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_empty_tokens_not_overflow(self):
        tokens = {}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_output_tokens_included_in_count(self):
        # input=10k, output=65k → total=75k > usable(68k) → overflow
        tokens = {"input": 10000, "output": 65000, "cache": {}}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=100000,
        )
        assert result is True


# ---------------------------------------------------------------------------
# is_overflow() with various model context sizes
# ---------------------------------------------------------------------------

class TestIsOverflowModelSizes:
    @pytest.mark.asyncio
    async def test_small_context_200k(self):
        # 200k context model with 8k output limit → usable = 191808
        # Use tokens > usable to trigger overflow
        usable = 200000 - 8192  # 191808
        tokens = {"input": usable + 1000, "output": 0}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=200000,
            model_output=8192,
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_gemini_1m_context(self):
        # 1M context, 50% used — should NOT be overflow
        tokens = {"input": 500000, "output": 0}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=1000000,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_gemini_1m_context_over_limit(self):
        # Use tokens > usable to trigger overflow in 1M context model
        usable = 1000000 - 32000  # 968000
        tokens = {"input": usable + 1000, "output": 0}
        result = await SessionCompaction.is_overflow(
            tokens=tokens,
            model_context=1000000,
            model_output=32000,
        )
        assert result is True


# ---------------------------------------------------------------------------
# prune(): basic behavior
# ---------------------------------------------------------------------------

class TestPrune:
    @pytest.mark.asyncio
    async def test_prune_disabled_does_nothing(self):
        # With prune_disabled=True, should return immediately without touching session
        called = []

        async def mock_list(*args, **kwargs):
            called.append(args)
            return []

        with patch("flocks.session.message.Message.list", new=mock_list):
            await SessionCompaction.prune("ses_test", prune_disabled=True)

        assert not called, "Message.list should not be called when prune_disabled=True"

    @pytest.mark.asyncio
    async def test_prune_with_policy_no_messages(self):
        # Prune with a valid policy on an empty session should not raise
        policy = CompactionPolicy.from_model(200000, 8192)
        with patch("flocks.session.message.Message.list", new=AsyncMock(return_value=[])):
            await SessionCompaction.prune("ses_test_policy", policy=policy)


# ---------------------------------------------------------------------------
# CompactionPolicy integration sanity
# ---------------------------------------------------------------------------

class TestCompactionPolicyIntegration:
    def test_policy_overflow_threshold_positive(self):
        # 200k context, 8k output
        policy = CompactionPolicy.from_model(200000, 8192)
        assert policy.overflow_threshold > 0

    def test_policy_overflow_threshold_less_than_context(self):
        policy = CompactionPolicy.from_model(200000, 8192)
        assert policy.overflow_threshold < 200000

    def test_policy_prune_protect_positive(self):
        policy = CompactionPolicy.from_model(200000, 8192)
        assert policy.prune_protect > 0

    @pytest.mark.parametrize("context,output,expected_tier", [
        (8000, 1024, ContextTier.SMALL),      # usable < 12k
        (50000, 4096, ContextTier.MEDIUM),    # usable ~46k ≤ 100k
        (200000, 8192, ContextTier.LARGE),    # usable ~192k ≤ 500k
        (1000000, 32000, ContextTier.XLARGE), # usable ~968k > 500k
    ])
    def test_model_tier_classification(self, context, output, expected_tier):
        policy = CompactionPolicy.from_model(context, output)
        assert policy.tier == expected_tier
