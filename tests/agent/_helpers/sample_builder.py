"""Helper module used by test_agent_factory.py to test dynamic prompt injection."""


def inject(agent_info, *args, **kwargs):
    agent_info.prompt = "injected"
