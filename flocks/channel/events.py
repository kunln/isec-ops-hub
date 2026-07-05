"""
Channel Bus event definitions.

All channel-related events published through the Flocks Bus system.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from flocks.bus.bus_event import BusEvent


class ChannelMessageReceivedProps(BaseModel):
    channel_id: str
    account_id: str
    message_id: str
    sender_id: str
    chat_id: str
    chat_type: str
    session_id: str
    text: str = ""


class ChannelMessageSentProps(BaseModel):
    channel_id: str
    account_id: Optional[str] = None
    message_id: str
    to: str
    session_id: Optional[str] = None
    success: bool = True
    error: Optional[str] = None


class ChannelConnectedProps(BaseModel):
    channel_id: str
    account_id: str = "default"


class ChannelDisconnectedProps(BaseModel):
    channel_id: str
    account_id: str = "default"
    reason: Optional[str] = None


ChannelMessageReceived = BusEvent.define(
    "channel.message.received", ChannelMessageReceivedProps
)
ChannelMessageSent = BusEvent.define(
    "channel.message.sent", ChannelMessageSentProps
)
ChannelConnected = BusEvent.define(
    "channel.connected", ChannelConnectedProps
)
ChannelDisconnected = BusEvent.define(
    "channel.disconnected", ChannelDisconnectedProps
)
