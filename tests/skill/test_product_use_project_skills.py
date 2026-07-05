from pathlib import Path

import pytest

from flocks.skill.skill import Skill


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_parse_product_use_project_skill_files() -> None:
    skill_files = [
        PROJECT_ROOT / ".flocks" / "plugins" / "skills" / "tdp-use" / "SKILL.md",
        PROJECT_ROOT / ".flocks" / "plugins" / "skills" / "onesec-use" / "SKILL.md",
        PROJECT_ROOT / ".flocks" / "plugins" / "skills" / "qingteng-use" / "SKILL.md",
        PROJECT_ROOT / ".flocks" / "plugins" / "skills" / "skyeye-use" / "SKILL.md",
    ]

    parsed = [Skill._parse_skill_md(str(skill_file)) for skill_file in skill_files]

    assert parsed[0] is not None
    assert parsed[0].name == "tdp-use"
    assert "TDP" in parsed[0].description

    assert parsed[1] is not None
    assert parsed[1].name == "onesec-use"
    assert "OneSEC" in parsed[1].description

    assert parsed[2] is not None
    assert parsed[2].name == "qingteng-use"
    assert "青藤" in parsed[2].description

    assert parsed[3] is not None
    assert parsed[3].name == "skyeye-use"
    assert "SkyEye" in parsed[3].description


@pytest.mark.asyncio
async def test_discover_product_use_project_skills() -> None:
    skills = await Skill.refresh()
    skill_names = {skill.name for skill in skills}

    assert "tdp-use" in skill_names
    assert "onesec-use" in skill_names
    assert "qingteng-use" in skill_names
    assert "skyeye-use" in skill_names
