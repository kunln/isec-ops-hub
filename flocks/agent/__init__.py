"""
Agent management module.

Canonical import locations:
  flocks.agent.agent         — AgentInfo, AgentModel, AgentPromptMetadata, …
  flocks.agent.registry      — Agent class (load / get / list)
  flocks.agent.agent_factory — scan_and_load, inject_dynamic_prompts
  flocks.agent.prompt_utils  — prompt builder functions
  flocks.session.prompt_strings     — PROMPT_COMPACTION/TITLE/SUMMARY/GENERATE

This __init__ exposes the public API via lazy imports to avoid circular
dependencies with session/runner.py.
"""

__all__ = [
    "Agent",
    "AgentInfo",
    "AgentModel",
    # Session management prompts
    "PROMPT_COMPACTION",
    "PROMPT_TITLE",
    "PROMPT_SUMMARY",
    # YAML config loader
    "yaml_to_agent_info",
]

_LAZY_MAP = {
    "Agent": "flocks.agent.registry",
    "AgentInfo": "flocks.agent.agent",
    "AgentModel": "flocks.agent.agent",
    "PROMPT_COMPACTION": "flocks.session.prompt_strings",
    "PROMPT_TITLE": "flocks.session.prompt_strings",
    "PROMPT_SUMMARY": "flocks.session.prompt_strings",
    "yaml_to_agent_info": "flocks.agent.agent_factory",
}


def __getattr__(name: str):
    if name in _LAZY_MAP:
        import importlib
        module = importlib.import_module(_LAZY_MAP[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
