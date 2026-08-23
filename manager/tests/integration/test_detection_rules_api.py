import pytest

pytestmark = pytest.mark.asyncio


async def test_detection_rules_crud_api(async_client):
    # 1. List detection rules (triggers auto-seeding if empty)
    res_list = await async_client.get("/api/v1/rules/detection")
    assert res_list.status_code == 200
    rules = res_list.json()
    assert len(rules) >= 13

    # 2. Create a new custom detection rule
    custom_rule = {
        "rule_id": "custom_threat_rule",
        "name": "Custom Threat Detection",
        "description": "Detects custom malware signature",
        "enabled": True,
        "weight": 1.5,
        "config": {"custom_threshold": 10}
    }
    res_create = await async_client.post("/api/v1/rules/detection", json=custom_rule)
    assert res_create.status_code == 201
    created = res_create.json()
    assert created["rule_id"] == "custom_threat_rule"
    assert created["weight"] == 1.5

    # 3. Get rule detail
    res_get = await async_client.get("/api/v1/rules/detection/custom_threat_rule")
    assert res_get.status_code == 200
    assert res_get.json()["name"] == "Custom Threat Detection"

    # 4. Update rule
    update_data = {
        "enabled": False,
        "weight": 2.0
    }
    res_update = await async_client.put("/api/v1/rules/detection/custom_threat_rule", json=update_data)
    assert res_update.status_code == 200
    updated = res_update.json()
    assert updated["enabled"] is False
    assert updated["weight"] == 2.0

    # 5. Delete rule
    res_del = await async_client.delete("/api/v1/rules/detection/custom_threat_rule")
    assert res_del.status_code == 204

    # Confirm deletion
    res_get_del = await async_client.get("/api/v1/rules/detection/custom_threat_rule")
    assert res_get_del.status_code == 404
