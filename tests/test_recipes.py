import pytest

from wafpierce.pentest_models import ImpactLevel, ModelValidationError
from wafpierce.recipes import execution_plan, render_nuclei_workflow, select_recipes


def test_recipe_selection_uses_observed_technology():
    matches = select_recipes(["nginx", "WordPress", "/wp-json/", "HTTPS"])
    ids = [match.recipe.recipe_id for match in matches]
    assert "wordpress-review" in ids
    assert "generic-authenticated-web" in ids


def test_safe_plan_keeps_intrusive_stages_visible_but_disabled():
    matches = select_recipes(["GraphQL Apollo Server"], include_generic=False)
    plan = execution_plan(matches, ImpactLevel.SAFE)
    assert any(item["stage_id"] == "graphql-depth" and not item["enabled"] for item in plan)
    assert any(item["stage_id"] == "graphql-role-diff" and item["enabled"] for item in plan)


def test_nuclei_workflow_contains_only_selected_tags():
    matches = select_recipes(["WordPress"], include_generic=False)
    workflow = render_nuclei_workflow([match.recipe for match in matches])
    assert "workflows:" in workflow
    assert "wordpress" in workflow
    assert "graphql" not in workflow


def test_nuclei_workflow_rejects_tag_injection():
    matches = select_recipes(["WordPress"], include_generic=False)
    with pytest.raises(ModelValidationError):
        render_nuclei_workflow(
            [match.recipe for match in matches], custom_tags=["x\n  - template: bad"]
        )
