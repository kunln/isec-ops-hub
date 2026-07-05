"""
Configuration management routes

Routes for getting and updating configuration.

Flocks TUI expects Config format:
{
    "$schema": string,
    "theme": string,
    "keybinds": KeybindsConfig,
    "model": string,
    "provider": { [providerID]: ProviderConfig },
    "agent": { [agentName]: AgentConfig },
    "mcp": { [name]: McpConfig },
    ...
}
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from flocks.commercial import audit
from flocks.commercial.access_control import require_capability, require_capability_for_request
from flocks.commercial.models import AuditStatus
from flocks.config.config import Config, GlobalConfig, ConfigInfo as ConfigInfoModel
from flocks.provider.provider import Provider
from flocks.utils.log import Log

router = APIRouter()
log = Log.create(service="routes.config")


def _build_model_from_config(
    provider_id: str,
    model_id: str,
    model_cfg: Any,
    existing: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if hasattr(model_cfg, "model_dump"):
        data = model_cfg.model_dump(exclude_none=True, by_alias=True)
    elif isinstance(model_cfg, dict):
        data = {k: v for k, v in model_cfg.items() if v is not None}
    else:
        data = {}

    if data.get("disabled") is True:
        return None

    existing = existing or {}
    existing_limit = existing.get("limit", {}) if isinstance(existing.get("limit", {}), dict) else {}
    limit = data.get("limit") if isinstance(data.get("limit"), dict) else {}

    context = limit.get("context") or existing_limit.get("context") or 128000
    output = limit.get("output") or existing_limit.get("output") or 4096

    tool_call = data.get("tool_call")
    if tool_call is None:
        tool_call = data.get("toolCall")
    if tool_call is None:
        tool_call = existing.get("tool_call", True)

    temperature = data.get("temperature")
    if temperature is None:
        temperature = existing.get("temperature", True)

    attachment = data.get("attachment")
    if attachment is None:
        attachment = existing.get("attachment", False)

    reasoning = data.get("reasoning")
    if reasoning is None:
        reasoning = existing.get("reasoning", False)

    name = data.get("name") or existing.get("name") or model_id

    model_info = {
        "id": model_id,
        "name": name,
        "providerID": provider_id,
        "attachment": attachment,
        "reasoning": reasoning,
        "temperature": temperature,
        "tool_call": tool_call,
        "limit": {
            "context": context,
            "output": output,
        },
        "options": data.get("options") or existing.get("options") or {},
    }

    if "family" in data or "family" in existing:
        model_info["family"] = data.get("family") or existing.get("family")
    if "api" in data or "api" in existing:
        model_info["api"] = data.get("api") or existing.get("api")

    return model_info


def _merge_config_models(
    models_dict: Dict[str, Dict[str, Any]],
    provider_id: str,
    config: Any,
) -> Dict[str, Dict[str, Any]]:
    provider_cfg = (getattr(config, "provider", None) or {}).get(provider_id)
    if not provider_cfg or not getattr(provider_cfg, "models", None):
        return models_dict

    for model_id, model_cfg in provider_cfg.models.items():
        existing = models_dict.get(model_id)
        merged = _build_model_from_config(provider_id, model_id, model_cfg, existing)
        if merged:
            models_dict[model_id] = merged

    return models_dict


class ProviderDefaultsResponse(BaseModel):
    """Provider defaults response"""
    providers: list[Dict[str, Any]]
    default: Dict[str, str]


@router.get("", dependencies=[Depends(require_capability("system.config.read"))], summary="Get configuration")
async def get_config() -> Dict[str, Any]:
    """
    Get configuration
    
    Retrieve the current Flocks configuration settings and preferences.
    Flocks TUI expects the merged Config object directly.
    """
    try:
        # Get complete configuration (includes global + project + env)
        complete_config = await Config.get()
        
        # Return merged config in Flocks format
        return complete_config.model_dump(by_alias=True, exclude_none=True)
    except Exception as e:
        log.error("config.get.error", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/", summary="Update configuration")
async def update_config(config_data: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """
    Update configuration
    
    Update Flocks configuration settings and preferences.
    Returns the updated Config in Flocks format.

    Sensitive channel fields (botToken, appSecret, secret, clientSecret, …)
    are automatically extracted to .secret.json and replaced with
    {secret:channel_<id>_<field>} references before the config is written to
    flocks.json, so that plaintext secrets never land in that file.
    """
    actor = await require_capability_for_request(
        request,
        "system.config.write",
        action="config.update",
        target="config",
    )
    try:
        # Extract channel sensitive fields into .secret.json before persisting
        if "channels" in config_data and isinstance(config_data.get("channels"), dict):
            from flocks.security.channel_secrets import extract_channel_secrets
            config_data = {**config_data, "channels": extract_channel_secrets(config_data["channels"])}

        # Parse and validate configuration
        config = ConfigInfoModel.model_validate(config_data)
        
        # Update project config
        await Config.update(config)
        
        # Clear cache to reload
        Config.clear_cache()
        
        log.info("config.updated")
        await audit.record_audit_event(
            action="config.update",
            target="config",
            status=AuditStatus.SUCCESS,
            actor=actor,
            request=request,
            summary="Updated local configuration",
            metadata={"top_level_keys": sorted(config_data.keys())},
        )
        
        return await get_config()
    except Exception as e:
        log.error("config.update.error", {"error": str(e)})
        await audit.record_audit_event(
            action="config.update",
            target="config",
            status=AuditStatus.FAILED,
            actor=actor,
            request=request,
            summary=str(e),
            metadata={"top_level_keys": sorted(config_data.keys())},
        )
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/providers",
    dependencies=[Depends(require_capability("system.config.read"))],
    response_model=ProviderDefaultsResponse,
    summary="List config providers",
)
async def get_providers():
    """
    List config providers
    
    Get a list of all configured AI providers and their default models.
    
    Note: Flocks TUI expects models as Dict[modelID, Model], not List[Model].
    """
    try:
        with log.time("providers"):
            config = await Config.get()
            await Provider.apply_config(config)

            # Get all provider IDs
            provider_ids = Provider.list_providers()
            
            # Get models for each provider
            providers_list = []
            default_models = {}
            
            for provider_id in provider_ids:
                try:
                    models = Provider.list_models(provider_id)
                    
                    # Flocks TUI expects models as Dict[modelID, Model]
                    models_dict = {}
                    first_model_id = None
                    
                    for model in models:
                        if first_model_id is None:
                            first_model_id = model.id
                        
                        # Build model dict in Flocks format
                        models_dict[model.id] = {
                            "id": model.id,
                            "name": model.name,
                            "providerID": model.provider_id,
                            "attachment": model.capabilities.supports_vision,
                            "reasoning": False,
                            "temperature": True,
                            "tool_call": model.capabilities.supports_tools,
                            "limit": {
                                "context": model.capabilities.context_window or 128000,
                                "output": model.capabilities.max_tokens or 4096,
                            },
                            "options": {},
                        }
                    
                    _merge_config_models(models_dict, provider_id, config)

                    provider_info = {
                        "id": provider_id,
                        "name": provider_id.capitalize(),
                        "models": models_dict,
                    }
                    
                    providers_list.append(provider_info)
                    
                    # Get default model (first model in the list)
                    if not first_model_id and models_dict:
                        first_model_id = next(iter(models_dict))
                    if first_model_id:
                        default_models[provider_id] = first_model_id
                except Exception as e:
                    log.warn("provider.models.error", {"provider": provider_id, "error": str(e)})
            
            return ProviderDefaultsResponse(
                providers=providers_list,
                default=default_models,
            )
    except Exception as e:
        log.error("providers.list.error", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))
