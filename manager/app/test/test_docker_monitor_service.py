import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from app.services.docker_monitor_service import DockerMonitorService


@pytest.mark.asyncio
async def test_calculate_cpu_percent_with_precpu():
    service = DockerMonitorService()
    
    mock_stats = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 200000000},
            "system_cpu_usage": 2000000000,
            "online_cpus": 2
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 100000000},
            "system_cpu_usage": 1000000000
        }
    }
    
    cpu_percent = service._calculate_cpu_percent("container_test_1", mock_stats, None)
    # delta_cpu = 100000000, delta_sys = 1000000000 -> (0.1) * 2 * 100 = 20.0%
    assert cpu_percent == 20.0


@pytest.mark.asyncio
async def test_calculate_cpu_percent_with_cache():
    service = DockerMonitorService()
    
    # 1st reading (precpu is 0)
    mock_stats_1 = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 100000000},
            "system_cpu_usage": 1000000000,
            "online_cpus": 1
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 0},
            "system_cpu_usage": 0
        }
    }
    service._calculate_cpu_percent("container_cache_test", mock_stats_1, None)
    
    # 2nd reading (using cache)
    mock_stats_2 = {
        "cpu_stats": {
            "cpu_usage": {"total_usage": 150000000},
            "system_cpu_usage": 2000000000,
            "online_cpus": 1
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": 0},
            "system_cpu_usage": 0
        }
    }
    cpu_percent = service._calculate_cpu_percent("container_cache_test", mock_stats_2, None)
    # delta_cpu = 50000000, delta_sys = 1000000000 -> (0.05) * 1 * 100 = 5.0%
    assert cpu_percent == 5.0


@pytest.mark.asyncio
async def test_get_containers_status_graceful_error():
    service = DockerMonitorService()
    with patch.object(service, "_get_client", side_effect=RuntimeError("Docker daemon socket not found")):
        with pytest.raises(RuntimeError):
            await service.get_containers_status()
