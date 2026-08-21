from wafpierce.cloud_ingest import (
    normalize_iam_relationships,
    parse_prowler_rows,
    read_only_inventory_plan,
)
from wafpierce.internal_identity import (
    LockoutPolicy,
    parse_bloodhound_documents,
    plan_lockout_aware_spray,
)
from wafpierce.pentest_workspace import PentestWorkspace


def test_bloodhound_group_and_acl_relationships_become_attack_paths(tmp_path):
    user_id = "S-1-5-21-1000"
    group_id = "S-1-5-21-512"
    computer_id = "S-1-5-21-2000"
    result = parse_bloodhound_documents([
        {
            "meta": {"type": "users"},
            "data": [{"ObjectIdentifier": user_id, "Properties": {"name": "ALICE@EXAMPLE.TEST"}}],
        },
        {
            "meta": {"type": "groups"},
            "data": [{
                "ObjectIdentifier": group_id,
                "Properties": {"name": "DOMAIN ADMINS@EXAMPLE.TEST", "highvalue": True},
                "Members": [{"ObjectIdentifier": user_id, "ObjectType": "User"}],
            }],
        },
        {
            "meta": {"type": "computers"},
            "data": [{
                "ObjectIdentifier": computer_id,
                "Properties": {"name": "DC01.EXAMPLE.TEST", "operatingsystem": "Windows"},
                "Aces": [{"PrincipalSID": group_id, "RightName": "GenericAll"}],
            }],
        },
    ])
    assert {edge.relation for edge in result.edges} == {"member_of", "acl_genericall"}

    workspace = PentestWorkspace(str(tmp_path / "identity.db"))
    workspace_id = workspace.create_workspace("Internal", ["https://dc01.example.test"])
    result.persist(workspace, workspace_id)
    by_value = {item["value"]: item["asset_id"] for item in workspace.list_assets(workspace_id)}
    paths = workspace.find_paths(
        workspace_id, by_value[user_id], by_value[computer_id]
    )
    assert [edge["relation"] for edge in paths[0]] == ["member_of", "acl_genericall"]


def test_spray_planner_never_executes_and_respects_lockout_window():
    plan = plan_lockout_aware_spray(
        ["alice", "bob"],
        candidate_count=10,
        policy=LockoutPolicy(3, 30, 30),
        requested_attempts_per_identity=10,
    )
    assert plan.maximum_attempts_per_identity == 2
    assert plan.request_count == 4
    assert plan.batches[1].offset_seconds > 30 * 60
    assert plan.execution_supported is False


def test_prowler_and_iam_inputs_build_cloud_graph():
    prowler = parse_prowler_rows([{
        "Provider": "aws",
        "AccountId": "123456789012",
        "Region": "eu-west-1",
        "CheckID": "s3_bucket_public_access",
        "Status": "FAIL",
        "Severity": "high",
        "ResourceArn": "arn:aws:s3:::example-bucket",
    }])
    assert len(prowler.findings) == 1
    assert {edge.relation for edge in prowler.edges} == {"contains"}

    iam = normalize_iam_relationships(
        "aws",
        principals=[{"id": "arn:aws:iam::123:user/alice", "name": "alice"}],
        resources=[{"id": "arn:aws:iam::123:role/Admin", "name": "Admin"}],
        permissions=[{
            "principal_id": "arn:aws:iam::123:user/alice",
            "resource_id": "arn:aws:iam::123:role/Admin",
            "actions": ["sts:AssumeRole"],
        }],
    )
    assert iam.edges[0].relation == "can_assume"


def test_cloud_inventory_plan_references_secret_handle_only():
    plan = read_only_inventory_plan("azure", "cloud:azure:consultant")
    assert plan["read_only"] is True
    assert plan["execution_supported"] is False
    assert "password" not in plan
