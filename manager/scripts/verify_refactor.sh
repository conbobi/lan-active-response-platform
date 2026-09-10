#!/bin/bash
set -e

echo "=== 1. Syntax check ==="
uv run python -m compileall app/ -q

echo "=== 2. Import check ==="
uv run python -c "from app.main import app; print('✓ App imports OK')"

echo "=== 3. Route count ==="
uv run python -c "
from app.main import app
routes = [r for r in app.routes if hasattr(r, 'methods')]
print(f'✓ {len(routes)} routes mounted')
"

echo "=== 4. RiskRuleRegistry ==="
uv run python -c "
from app.services.risk_rules import create_default_registry
reg = create_default_registry()
n = len(reg.get_all_rules())
assert n >= 18, f'Expected >=18 rules, got {n}'
print(f'✓ {n} risk rules registered')
"

echo "=== 5. Tests ==="
uv run pytest -x --tb=short -q

echo "=== 6. Re-run tools ==="
uv run ruff check app/ --select F401,F841,F811 || true

echo "✅ ALL CHECKS PASSED"
