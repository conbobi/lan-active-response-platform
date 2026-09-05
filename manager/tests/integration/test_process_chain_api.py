import pytest

pytestmark = pytest.mark.asyncio


async def test_process_group_and_chain_rule_apis(async_client):
    # 1. Verify seeded process groups
    res_groups = await async_client.get("/api/v1/process-groups/")
    assert res_groups.status_code == 200
    groups = res_groups.json()
    assert len(groups) >= 3
    group_names = [g["name"] for g in groups]
    assert "Office Applications" in group_names
    assert "Command Shells" in group_names
    assert "Web Downloaders" in group_names

    # 2. Verify seeded process chain rules
    res_rules = await async_client.get("/api/v1/process-chain-rules/")
    assert res_rules.status_code == 200
    rules = res_rules.json()
    assert len(rules) >= 2
    rule_names = [r["name"] for r in rules]
    assert "Office spawning shell" in rule_names
    assert "Shell downloading payload" in rule_names

    # 3. Create a new custom ProcessGroup
    new_group_payload = {
        "name": "Integration Test Group",
        "patterns": ["testproc.exe", "testpayload"],
        "description": "Group for integration testing"
    }
    res_create_grp = await async_client.post("/api/v1/process-groups/", json=new_group_payload)
    assert res_create_grp.status_code == 201
    created_grp = res_create_grp.json()
    grp_id = created_grp["id"]
    assert created_grp["name"] == "Integration Test Group"
    assert "testproc.exe" in created_grp["patterns"]

    # 4. Get ProcessGroup detail
    res_get_grp = await async_client.get(f"/api/v1/process-groups/{grp_id}")
    assert res_get_grp.status_code == 200
    assert res_get_grp.json()["id"] == grp_id

    # 5. Update ProcessGroup
    update_grp_payload = {
        "description": "Updated description"
    }
    res_up_grp = await async_client.put(f"/api/v1/process-groups/{grp_id}", json=update_grp_payload)
    assert res_up_grp.status_code == 200
    assert res_up_grp.json()["description"] == "Updated description"

    # Find another group to be parent
    office_grp = next(g for g in groups if g["name"] == "Office Applications")

    # 6. Create a ProcessChainRule referencing the new group
    new_rule_payload = {
        "name": "Test Office to Custom Proc",
        "parent_group_id": office_grp["id"],
        "child_group_id": grp_id,
        "action": "isolate",
        "is_active": True
    }
    res_create_rule = await async_client.post("/api/v1/process-chain-rules/", json=new_rule_payload)
    assert res_create_rule.status_code == 201
    created_rule = res_create_rule.json()
    rule_id = created_rule["id"]
    assert created_rule["name"] == "Test Office to Custom Proc"
    assert created_rule["action"] == "isolate"
    assert created_rule["child_group"]["name"] == "Integration Test Group"

    # 7. Try to delete the ProcessGroup while still referenced by the rule -> 409 CONFLICT
    res_del_conflict = await async_client.delete(f"/api/v1/process-groups/{grp_id}")
    assert res_del_conflict.status_code == 409

    # 8. Update the rule
    res_up_rule = await async_client.put(f"/api/v1/process-chain-rules/{rule_id}", json={"is_active": False, "action": "alert"})
    assert res_up_rule.status_code == 200
    assert res_up_rule.json()["is_active"] is False
    assert res_up_rule.json()["action"] == "alert"

    # 9. Delete the rule -> 204
    res_del_rule = await async_client.delete(f"/api/v1/process-chain-rules/{rule_id}")
    assert res_del_rule.status_code == 204

    # 10. Now delete the group -> 204 (no longer referenced)
    res_del_grp = await async_client.delete(f"/api/v1/process-groups/{grp_id}")
    assert res_del_grp.status_code == 204
