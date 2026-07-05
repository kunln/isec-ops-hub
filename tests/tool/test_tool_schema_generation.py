"""Tests for tool parameter JSON schema generation."""

from __future__ import annotations


from flocks.tool.registry import ToolRegistry


def test_question_schema_questions_items_is_object() -> None:
    ToolRegistry.init()
    schema = ToolRegistry.get_schema("question")
    assert schema is not None

    json_schema = schema.to_json_schema()
    questions = json_schema["properties"]["questions"]
    assert questions["type"] == "array"
    assert questions["items"]["type"] == "object"
    assert "question" in questions["items"]["properties"]


def test_run_workflow_schema_workflow_anyof_object_or_string() -> None:
    ToolRegistry.init()
    schema = ToolRegistry.get_schema("run_workflow")
    assert schema is not None

    json_schema = schema.to_json_schema()
    workflow = json_schema["properties"]["workflow"]
    assert "anyOf" in workflow

    any_of = workflow["anyOf"]
    types = {entry.get("type") for entry in any_of}
    assert "object" in types
    assert "string" in types

