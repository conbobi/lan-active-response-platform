-- Seed default response policies for graduated containment
INSERT INTO response_policies (
    id, name, description, min_score, max_score,
    action_type, scope, target_group_id, action_params,
    auto_rollback_seconds, priority, is_active, created_at, updated_at
) VALUES 
(
    'pol_block_ip_agent',
    'High Risk Block IP',
    'Block suspicious remote IP on host for score (50 - 69)',
    50.0,
    69.99,
    'block_ip',
    'agent',
    NULL,
    '{}'::json,
    300,
    20,
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    'pol_isolate_agent',
    'Severe Risk Isolate Agent',
    'Network isolate single compromised host for score (70 - 84)',
    70.0,
    84.99,
    'isolate',
    'agent',
    NULL,
    '{}'::json,
    300,
    30,
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
),
(
    'pol_isolate_group',
    'Critical Risk Isolate Group',
    'Isolate entire department / network zone when critical score (85+)',
    85.0,
    100.0,
    'isolate',
    'group',
    NULL,
    '{}'::json,
    300,
    40,
    true,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    min_score = EXCLUDED.min_score,
    max_score = EXCLUDED.max_score,
    action_type = EXCLUDED.action_type,
    scope = EXCLUDED.scope,
    auto_rollback_seconds = EXCLUDED.auto_rollback_seconds,
    priority = EXCLUDED.priority,
    is_active = EXCLUDED.is_active,
    updated_at = CURRENT_TIMESTAMP;
