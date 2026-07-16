"""Connector Adapter Interface skeleton for Integration Runtime v2.

This module defines the safe execution boundary between Sync Engine planning and
future connector-backed fetches. It intentionally does not perform HTTP, resolve
credentials, run sync, execute mappings, dispatch evidence, or create Security
objects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_REDACTED = "[REDACTED]"
_RAW_LIKE_KEYS = {
    "raw",
    "raw_data",
    "raw_event",
    "raw_payload",
    "raw_response",
    "request",
    "response",
    "body",
    "request_body",
    "response_body",
    "html",
    "blob",
    "binary",
    "packet",
    "pcap",
    "payload_bytes",
    "payload",
    "logs",
    "events",
}
_SECRET_LIKE_KEYS = {
    "api_key",
    "apikey",
    "passwd",
    "secret",
    "token",
    "password",
    "credential",
    "authorization",
    "bearer",
    "sign",
    "auth_timestamp",
}
_ITEM_REF_KEYS = {"item_id", "id", "item_type", "type", "source", "summary"}
_SECRET_VALUE_MARKERS = (
    "bearer ",
    "begin private key",
    "api_key=",
    "apikey=",
    "password=",
    "secret=",
    "token=",
    "passwd=",
    "authorization=",
    "sign=",
    "auth_timestamp=",
)
_FORBIDDEN_REQUEST_FIELDS = _SECRET_LIKE_KEYS | {"apiKey", "access_token", "refresh_token"}


def _normalize_key(key: Any) -> str:
    return str(key).strip().lower().replace("-", "_")


def _is_secret_like_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    return normalized in _SECRET_LIKE_KEYS or any(part in _SECRET_LIKE_KEYS for part in normalized.split("_"))


def _is_raw_like_key(key: Any) -> bool:
    return _normalize_key(key) in _RAW_LIKE_KEYS


def _is_secret_like_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in _SECRET_VALUE_MARKERS)


def sanitize_adapter_mapping(value: Any) -> Any:
    """Return a safe adapter export with raw containers removed and secrets redacted."""

    if isinstance(value, BaseModel):
        value = value.model_dump()
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if _is_raw_like_key(key):
                continue
            key_text = str(key)
            if _is_secret_like_key(key):
                sanitized[key_text] = _REDACTED
                continue
            sanitized[key_text] = sanitize_adapter_mapping(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_adapter_mapping(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_adapter_mapping(item) for item in value]
    if _is_secret_like_value(value):
        return _REDACTED
    return value


class _AdapterBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class IntegrationAdapterRequest(_AdapterBaseModel):
    package_id: str
    instance_id: str | None = None
    capability: str
    mode: str = "manual"
    params: dict[str, Any] = Field(default_factory=dict)
    cursor: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = None
    dry_run: bool = True
    requested_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("params", "cursor", "metadata", mode="before")
    @classmethod
    def _sanitize_mappings(cls, value: Any) -> dict[str, Any]:
        return sanitize_adapter_mapping(value if isinstance(value, dict) else {})

    @model_validator(mode="before")
    @classmethod
    def _reject_credential_values(cls, data: Any) -> Any:
        if isinstance(data, dict):
            forbidden = [key for key in data if _normalize_key(key) in _FORBIDDEN_REQUEST_FIELDS and _normalize_key(key) != "credential_ref"]
            if forbidden:
                raise ValueError("IntegrationAdapterRequest accepts credential_ref only, not credential values")
        return data


class AdapterItemRef(_AdapterBaseModel):
    item_id: str | None = None
    item_type: str | None = None
    source: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)

    @field_validator("summary", mode="before")
    @classmethod
    def _sanitize_summary(cls, value: Any) -> dict[str, Any]:
        return sanitize_adapter_mapping(value if isinstance(value, dict) else {})


class IntegrationAdapterResult(_AdapterBaseModel):
    status: str
    dry_run: bool = True
    package_id: str
    instance_id: str | None = None
    capability: str
    item_count: int = 0
    items: list[dict[str, Any]] = Field(default_factory=list)
    item_refs: list[AdapterItemRef] = Field(default_factory=list)
    cursor: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("items", mode="before")
    @classmethod
    def _sanitize_items(cls, value: Any) -> list[dict[str, Any]]:
        items = value if isinstance(value, list) else []
        return [item for item in sanitize_adapter_mapping(items) if isinstance(item, dict)]

    @field_validator("cursor", "summary", "metadata", mode="before")
    @classmethod
    def _sanitize_result_mappings(cls, value: Any) -> dict[str, Any]:
        return sanitize_adapter_mapping(value if isinstance(value, dict) else {})

    @field_validator("warnings", "errors", mode="before")
    @classmethod
    def _sanitize_messages(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(sanitize_adapter_mapping(item)) for item in value]

    @field_validator("item_refs", mode="before")
    @classmethod
    def _sanitize_item_refs(cls, value: Any) -> list[Any]:
        return sanitize_adapter_mapping(value if isinstance(value, list) else [])


def validate_adapter_request(request: IntegrationAdapterRequest) -> None:
    """Validate the request contract without resolving credentials or executing anything."""

    exported = request.model_dump()
    for field in _FORBIDDEN_REQUEST_FIELDS:
        if field in exported and field != "credential_ref":
            raise ValueError("IntegrationAdapterRequest accepts credential_ref only, not credential values")


def build_adapter_item_refs(items: list[dict[str, Any]]) -> list[AdapterItemRef]:
    """Build lightweight item references from normalized-ish adapter items."""

    refs: list[AdapterItemRef] = []
    for item in sanitize_adapter_mapping(items):
        if not isinstance(item, dict):
            continue
        summary = {
            str(key): val
            for key, val in item.items()
            if _normalize_key(key) not in _ITEM_REF_KEYS and not _is_secret_like_key(key) and not _is_raw_like_key(key)
        }
        refs.append(
            AdapterItemRef(
                item_id=item.get("item_id") or item.get("id"),
                item_type=item.get("item_type") or item.get("type"),
                source=item.get("source"),
                summary=summary,
            )
        )
    return refs


class IntegrationAdapter(ABC):
    adapter_id: str
    package_id: str
    supported_capabilities: set[str] | None

    @abstractmethod
    async def run_capability(self, request: IntegrationAdapterRequest) -> IntegrationAdapterResult:
        """Run a capability through the adapter boundary."""

        raise NotImplementedError


class FakeIntegrationAdapter(IntegrationAdapter):
    """Safe fake adapter for tests and future preview wiring."""

    def __init__(
        self,
        package_id: str,
        supported_capabilities: set[str] | None = None,
        *,
        adapter_id: str = "fake.integration.adapter",
        fake_items: list[dict[str, Any]] | None = None,
        cursor: dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.adapter_id = adapter_id
        self.package_id = package_id
        self.supported_capabilities = supported_capabilities
        self.fake_items = fake_items or []
        self.cursor = cursor or {}
        self.summary = summary or {}
        self.warnings = warnings or []
        self.errors = errors or []
        self.metadata = metadata or {}

    async def run_capability(self, request: IntegrationAdapterRequest) -> IntegrationAdapterResult:
        validate_adapter_request(request)
        if self.supported_capabilities is not None and request.capability not in self.supported_capabilities:
            return IntegrationAdapterResult(
                status="unsupported_capability",
                dry_run=True,
                package_id=request.package_id,
                instance_id=request.instance_id,
                capability=request.capability,
                errors=[f"Unsupported capability: {request.capability}"],
            )
        items = sanitize_adapter_mapping(self.fake_items)
        return IntegrationAdapterResult(
            status="success",
            dry_run=True,
            package_id=request.package_id,
            instance_id=request.instance_id,
            capability=request.capability,
            item_count=len(items),
            items=items,
            item_refs=build_adapter_item_refs(items),
            cursor=self.cursor,
            summary=self.summary,
            warnings=self.warnings,
            errors=self.errors,
            metadata=self.metadata,
        )
