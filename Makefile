.PHONY: up down restart seed-policies test lint

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

restart-frontend:
	docker compose restart frontend

restart-manager:
	docker compose restart manager

seed-policies:
	docker exec -i larp-db-1 psql -U larp -d larpdb < manager/scripts/seed_policies.sql

verify-policies:
	curl -s http://localhost:8005/api/v1/policies/ | python3 -m json.tool
