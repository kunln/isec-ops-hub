"""
Common bus event definitions.
"""

from pydantic import BaseModel, Field, ConfigDict

from flocks.bus.bus_event import BusEvent


class SessionInfoProps(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    title: str | None = None
    parent_id: str | None = Field(default=None, alias="parentID")
    project_id: str | None = Field(default=None, alias="projectID")


class SessionCreatedProps(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    info: SessionInfoProps


class SessionDeletedProps(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    session_id: str = Field(alias="sessionID")


class SessionIdleProps(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    session_id: str = Field(alias="sessionID")


class SessionErrorProps(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    session_id: str = Field(alias="sessionID")
    error: str


SessionCreated = BusEvent.define("session.created", SessionCreatedProps)
SessionDeleted = BusEvent.define("session.deleted", SessionDeletedProps)
SessionIdle = BusEvent.define("session.idle", SessionIdleProps)
SessionError = BusEvent.define("session.error", SessionErrorProps)
