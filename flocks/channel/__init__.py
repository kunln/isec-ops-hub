"""
Flocks Channel system — IM platform integration (Feishu, WeCom, Discord, …).

Public API:
    ChannelPlugin      — abstract base class for channel plugins
    ChannelRegistry    — global plugin registry
    GatewayManager     — lifecycle manager for channel connections
    OutboundDelivery   — unified outbound delivery dispatcher
"""

from flocks.channel.base import (
    ChannelCapabilities,
    ChannelMeta,
    ChannelPlugin,
    ChannelStatus,
    ChatType,
    DeliveryResult,
    InboundMessage,
    OutboundContext,
)

__all__ = [
    "ChannelCapabilities",
    "ChannelMeta",
    "ChannelPlugin",
    "ChannelStatus",
    "ChatType",
    "DeliveryResult",
    "InboundMessage",
    "OutboundContext",
]
