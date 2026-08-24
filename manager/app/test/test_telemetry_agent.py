import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

# Add agent path to sys.path so we can test agent module functions
agent_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent"))
if agent_path not in sys.path:
    sys.path.insert(0, agent_path)


from agent import get_process_list, get_network_connections, get_file_changes_count


def test_get_process_list():
    procs = get_process_list()
    assert isinstance(procs, list)
    assert len(procs) <= 50
    for p in procs:
        assert "pid" in p
        assert "name" in p
        assert "path" in p
        assert "cmdline" in p
        assert "is_suspicious" in p


def test_get_network_connections():
    conns = get_network_connections()
    assert isinstance(conns, list)
    assert len(conns) <= 30
    for c in conns:
        assert "src_ip" in c
        assert "src_port" in c
        assert "dst_ip" in c
        assert "dst_port" in c
        assert "is_suspicious" in c


def test_get_file_changes_count():
    count = get_file_changes_count()
    assert isinstance(count, int)
    assert count >= 0
