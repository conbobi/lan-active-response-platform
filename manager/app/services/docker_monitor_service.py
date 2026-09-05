import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.schemas.docker_status import ContainerStatusOut

logger = logging.getLogger("docker_monitor")

try:
    import docker
    from docker.errors import DockerException, APIError, NotFound
except ImportError:
    docker = None
    DockerException = Exception
    APIError = Exception
    NotFound = Exception


class DockerMonitorService:
    """Service to monitor and collect real-time status and resource metrics of Docker containers."""

    _instance = None
    _prev_cpu_stats: Dict[str, Dict[str, Any]] = {}

    def __new__(cls, *args, **kwargs):
        """Implement singleton pattern to preserve CPU stats cache across requests."""
        if cls._instance is None:
            cls._instance = super(DockerMonitorService, cls).__new__(cls)
            cls._instance._client = None
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, base_url: Optional[str] = None):
        if self._initialized:
            return
        self.base_url = base_url or "unix://var/run/docker.sock"
        self._initialized = True

    def _get_client(self):
        """Get or initialize the Docker client with robust error handling."""
        if docker is None:
            raise RuntimeError("Python 'docker' package is not installed.")

        if self._client is not None:
            try:
                self._client.ping()
                return self._client
            except Exception as e:
                logger.warning(f"Existing Docker client ping failed: {e}. Re-initializing client...")
                self._client = None

        try:
            self._client = docker.DockerClient(base_url=self.base_url, timeout=5)
            self._client.ping()
            return self._client
        except (DockerException, FileNotFoundError, PermissionError) as e:
            try:
                # Fallback to default environment configuration
                self._client = docker.from_env(timeout=5)
                self._client.ping()
                return self._client
            except Exception as env_e:
                self._client = None
                logger.error(f"Cannot connect to Docker daemon: socket error='{e}', env error='{env_e}'")
                raise RuntimeError(
                    f"Cannot connect to Docker daemon via '{self.base_url}' or environment: {env_e or e}"
                )

    def _format_uptime(self, started_at_str: str, status: str, exit_code: int = 0) -> str:
        """Format human-readable uptime from Docker StartedAt ISO 8601 string."""
        if status.lower() != "running":
            if status.lower() == "exited":
                return f"Exited ({exit_code})"
            return status.capitalize()

        if not started_at_str:
            return "Running"

        try:
            cleaned = started_at_str.rstrip("Z")
            if "." in cleaned:
                parts = cleaned.split(".")
                cleaned = parts[0] + "." + parts[1][:6]
            dt = datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = now - dt
            total_seconds = int(delta.total_seconds())

            if total_seconds < 0:
                return "Just started"

            days, rem = divmod(total_seconds, 86400)
            hours, rem = divmod(rem, 3600)
            minutes, seconds = divmod(rem, 60)

            if days > 0:
                return f"Up {days}d {hours}h"
            if hours > 0:
                return f"Up {hours}h {minutes}m"
            if minutes > 0:
                return f"Up {minutes}m {seconds}s"
            return f"Up {seconds}s"
        except Exception:
            return "Running"

    def _calculate_cpu_percent(
        self,
        container_id: str,
        stats: Dict[str, Any],
        raw_container: Any = None
    ) -> float:
        """
        Calculate accurate CPU percentage:
        1. Compare cpu_stats with precpu_stats provided by Docker.
        2. Fall back to cached previous reading from prior polling interval.
        Formula: cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
        """
        try:
            cpu_stats = stats.get("cpu_stats", {})
            cpu_usage = cpu_stats.get("cpu_usage", {})
            curr_total = cpu_usage.get("total_usage", 0)
            curr_system = cpu_stats.get("system_cpu_usage", 0)

            online_cpus = cpu_stats.get("online_cpus")
            if not online_cpus:
                percpu = cpu_usage.get("percpu_usage")
                online_cpus = len(percpu) if percpu else 1

            now_ts = time.time()
            prev = self._prev_cpu_stats.get(container_id)
            cpu_percent = 0.0

            # Method 1: Check Docker precpu_stats
            precpu_stats = stats.get("precpu_stats", {})
            precpu_usage = precpu_stats.get("cpu_usage", {})
            precpu_total = precpu_usage.get("total_usage", 0)
            precpu_system = precpu_stats.get("system_cpu_usage", 0)

            cpu_delta = curr_total - precpu_total
            system_delta = curr_system - precpu_system

            if precpu_total > 0 and system_delta > 0 and cpu_delta >= 0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0

            # Method 2: Compare with cached reading from previous poll cycle
            elif prev and (now_ts - prev["timestamp"] <= 30.0):
                prev_total = prev["total_usage"]
                prev_system = prev["system_cpu_usage"]

                cached_cpu_delta = curr_total - prev_total
                cached_sys_delta = curr_system - prev_system

                if cached_sys_delta > 0 and cached_cpu_delta >= 0:
                    cpu_percent = (cached_cpu_delta / cached_sys_delta) * online_cpus * 100.0

            # Cache current sample for subsequent calculations
            self._prev_cpu_stats[container_id] = {
                "total_usage": curr_total,
                "system_cpu_usage": curr_system,
                "timestamp": now_ts,
            }

            return round(max(0.0, cpu_percent), 2)
        except Exception as e:
            logger.debug(f"CPU calculation error for {container_id}: {e}")
            return 0.0

    def _sync_fetch_single_container(self, container: Any) -> ContainerStatusOut:
        """Synchronously collect stats and details for a single container (executed in thread)."""
        cid = container.short_id or container.id[:12]
        cname = container.name.lstrip("/")
        status = container.status.lower()

        attrs = container.attrs or {}
        state = attrs.get("State", {})
        started_at = state.get("StartedAt", "")
        exit_code = state.get("ExitCode", 0)

        uptime = self._format_uptime(started_at, status, exit_code)

        cpu_percent = 0.0
        memory_usage_mb = 0.0
        memory_limit_mb = 0.0
        network_rx_bytes = 0.0
        network_tx_bytes = 0.0

        if status == "running":
            try:
                stats = container.stats(stream=False)
                # Calculate CPU
                cpu_percent = self._calculate_cpu_percent(cid, stats, container)

                # Calculate Memory
                mem_stats = stats.get("memory_stats", {})
                usage_bytes = mem_stats.get("usage", 0)
                limit_bytes = mem_stats.get("limit", 0)

                stats_details = mem_stats.get("stats", {})
                inactive_file = stats_details.get("inactive_file", stats_details.get("total_inactive_file", 0))
                effective_usage = max(0, usage_bytes - inactive_file) if inactive_file else usage_bytes

                memory_usage_mb = round(effective_usage / (1024 * 1024), 2)
                memory_limit_mb = round(limit_bytes / (1024 * 1024), 2)

                # Calculate Network I/O
                networks = stats.get("networks", {})
                if networks:
                    for _, net_data in networks.items():
                        network_rx_bytes += net_data.get("rx_bytes", 0)
                        network_tx_bytes += net_data.get("tx_bytes", 0)

            except Exception as e:
                logger.warning(f"Could not read stats for container {cname} ({cid}): {e}")

        return ContainerStatusOut(
            container_id=cid,
            name=cname,
            status=status,
            uptime=uptime,
            cpu_percent=cpu_percent,
            memory_usage=memory_usage_mb,
            memory_limit=memory_limit_mb,
            network_rx=float(network_rx_bytes),
            network_tx=float(network_tx_bytes),
        )

    async def _async_fetch_single_container_with_timeout(
        self,
        container: Any,
        timeout: float = 5.0
    ) -> ContainerStatusOut:
        """Fetch container metrics asynchronously in a worker thread with per-container timeout."""
        cid = container.short_id or container.id[:12]
        cname = container.name.lstrip("/")
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._sync_fetch_single_container, container),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Timeout ({timeout}s) fetching metrics for container {cname} ({cid})")
            return ContainerStatusOut(
                container_id=cid,
                name=cname,
                status=container.status.lower(),
                uptime="Running (Stats Timeout)",
                cpu_percent=0.0,
                memory_usage=0.0,
                memory_limit=0.0,
                network_rx=0.0,
                network_tx=0.0,
            )
        except Exception as e:
            logger.error(f"Error fetching stats for container {cname} ({cid}): {e}")
            return ContainerStatusOut(
                container_id=cid,
                name=cname,
                status=getattr(container, "status", "unknown"),
                uptime="Error",
                cpu_percent=0.0,
                memory_usage=0.0,
                memory_limit=0.0,
                network_rx=0.0,
                network_tx=0.0,
            )

    async def get_containers_status(
        self,
        stats_timeout: float = 5.0,
        total_timeout: float = 15.0
    ) -> List[ContainerStatusOut]:
        """
        Fetch and return status and resource metrics for all Docker containers.
        Guarded with per-container and total timeouts to prevent event loop blocking.
        """
        async def _fetch_all():
            client = await asyncio.to_thread(self._get_client)
            raw_containers = await asyncio.to_thread(client.containers.list, all=True)

            if not raw_containers:
                return []

            tasks = [
                self._async_fetch_single_container_with_timeout(c, timeout=stats_timeout)
                for c in raw_containers
            ]

            results = await asyncio.gather(*tasks, return_exceptions=False)
            return sorted(results, key=lambda x: x.name.lower())

        try:
            return await asyncio.wait_for(_fetch_all(), timeout=total_timeout)
        except asyncio.TimeoutError:
            logger.error(f"Total timeout ({total_timeout}s) exceeded while collecting Docker container status")
            return []
        except (DockerException, FileNotFoundError, PermissionError, RuntimeError) as e:
            logger.error(f"Docker monitor error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in get_containers_status: {e}", exc_info=True)
            return []
