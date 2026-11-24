import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.main import app
from app.models.base import Base
from app.models.incident import Incident
from app.models.incident_note import IncidentNote
from app.models.event import Event
from app.schemas.enums import IncidentSeverity, IncidentStatus
from app.core.deps import get_db


@pytest.fixture
async def setup_test_db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test_bulk.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db
    yield factory
    app.dependency_overrides.clear()
    await engine.dispose()


@pytest.mark.asyncio
async def test_bulk_resolve_and_delete_incidents(setup_test_db):
    factory = setup_test_db
    # 1. Tạo test incidents trong DB
    async with factory() as session:
        inc1 = Incident(
            id="test_inc_bulk_1",
            title="Test Incident 1",
            description="Test Description 1",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.OPEN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        inc2 = Incident(
            id="test_inc_bulk_2",
            title="Test Incident 2",
            description="Test Description 2",
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.OPEN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add_all([inc1, inc2])
        await session.commit()

        note = IncidentNote(
            id="note_test_1",
            incident_id="test_inc_bulk_1",
            user="tester",
            content="A note for testing delete cascade",
            created_at=datetime.now(timezone.utc),
        )
        session.add(note)
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 2. Test Bulk Resolve
        resp = await client.post(
            "/api/v1/incidents/bulk-resolve",
            json={"incident_ids": ["test_inc_bulk_1", "test_inc_bulk_2"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["resolved_count"] == 2

        # Kiểm tra DB status là resolved
        async with factory() as session:
            db_inc1 = await session.get(Incident, "test_inc_bulk_1")
            assert db_inc1.status == IncidentStatus.RESOLVED
            assert db_inc1.resolved_at is not None

        # 3. Test Single Delete
        resp_del = await client.delete("/api/v1/incidents/test_inc_bulk_1")
        assert resp_del.status_code == 200

        async with factory() as session:
            db_inc1_deleted = await session.get(Incident, "test_inc_bulk_1")
            assert db_inc1_deleted is None
            # Note liên quan cũng phải bị xóa
            db_note = await session.get(IncidentNote, "note_test_1")
            assert db_note is None

        # 4. Test Bulk Delete cho inc2
        resp_bulk_del = await client.post(
            "/api/v1/incidents/bulk-delete",
            json={"incident_ids": ["test_inc_bulk_2"]},
        )
        assert resp_bulk_del.status_code == 200
        assert resp_bulk_del.json()["deleted_count"] == 1

        async with factory() as session:
            db_inc2_deleted = await session.get(Incident, "test_inc_bulk_2")
            assert db_inc2_deleted is None


@pytest.mark.asyncio
async def test_clear_and_delete_events(setup_test_db):
    factory = setup_test_db
    # 1. Tạo test events
    async with factory() as session:
        ev1 = Event(
            id="test_ev_1",
            agent_id="agent_01",
            event_type="network_scan",
            severity="High",
            source="1.2.3.4",
            details={"msg": "port scan"},
            created_at=datetime.now(timezone.utc),
        )
        ev2 = Event(
            id="test_ev_2",
            agent_id="agent_01",
            event_type="fim_alert",
            severity="Medium",
            source="10.0.0.1",
            details={"file": "/etc/passwd"},
            created_at=datetime.now(timezone.utc),
        )
        session.add_all([ev1, ev2])
        await session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test delete single event
        resp_single = await client.delete("/api/v1/events/test_ev_1")
        assert resp_single.status_code == 200

        # Test clear all events
        resp_clear = await client.delete("/api/v1/events/")
        assert resp_clear.status_code == 200
        assert resp_clear.json()["deleted_count"] >= 1
