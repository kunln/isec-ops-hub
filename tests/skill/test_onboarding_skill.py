from pathlib import Path

import pytest

from flocks.skill.skill import Skill


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SKILL_FILE = PROJECT_ROOT / ".flocks" / "plugins" / "skills" / "onboarding" / "SKILL.md"


def test_parse_onboarding_project_skill_file() -> None:
    parsed = Skill._parse_skill_md(str(SKILL_FILE))

    assert parsed is not None
    assert parsed.name == "onboarding"
    assert "complete Flocks setup process" in parsed.description


def test_onboarding_security_tools_are_documented_as_api_services() -> None:
    content = SKILL_FILE.read_text(encoding="utf-8")

    assert "await set_service_credentials(" in content
    assert "await update_api_service(service_id, APIServiceUpdateRequest(enabled=True))" in content
    assert "result = await test_provider_credentials(service_id)" in content
    assert "await configure_api_service('virustotal', 'virustotal_api_key', '<VT_KEY>')" in content
    assert "await configure_api_service('fofa', 'fofa_key', '<EMAIL>:<KEY>')" in content
    assert "await configure_api_service('urlscan', 'urlscan_api_key', '<URLSCAN_KEY>')" in content
    assert "await configure_api_service('shodan', 'shodan_api_key', '<SHODAN_KEY>')" in content
    assert "ProviderCredentialRequest(\n            api_key='<KEY>'" not in content

    assert "ConfigWriter.add_mcp_server('virustotal'" not in content
    assert "ConfigWriter.add_mcp_server('fofa'" not in content
    assert "ConfigWriter.add_mcp_server('urlscan'" not in content
    assert "ConfigWriter.add_mcp_server('shodan'" not in content


def test_onboarding_skill_uses_shared_preflight_helper_and_mcp_status_rules() -> None:
    content = SKILL_FILE.read_text(encoding="utf-8")

    assert "from flocks.skill.onboarding_status import print_onboarding_preflight_status" in content
    assert "print_onboarding_preflight_status()" in content
    assert "Config.get_secret_file()" in content
    assert "tb_mcp_status" in content
    assert "skip 2a only if `tb_mcp_connected=True`" in content
    assert "已配置，未连接" in content


@pytest.mark.asyncio
async def test_discover_onboarding_project_skill() -> None:
    skills = await Skill.refresh()
    skill_names = {skill.name for skill in skills}

    assert "onboarding" in skill_names
