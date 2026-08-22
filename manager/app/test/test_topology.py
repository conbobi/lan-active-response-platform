import pytest
import requests
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

pytestmark = pytest.mark.skip(reason="Integration test requiring live environment")

BASE_URL = "http://localhost:8002/api/v1"
HEALTH_URL = "http://localhost:8002/health"

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------
def cleanup_database():
    """Xóa sạch dữ liệu cũ để test chạy lại từ đầu."""
    print("Cleaning database...")
    sql = "TRUNCATE agents, topology_links, flows, incidents, events, commands, process_info, rules, topology_change_logs CASCADE;"
    query_db(sql)

def send_request(method, path, data=None, expect_status=200, timeout=10):
    url = f"{BASE_URL}/{path}"
    headers = {"Content-Type": "application/json"}
    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            resp = requests.post(url, json=data, headers=headers, timeout=timeout)
        elif method.upper() == "PUT":
            resp = requests.put(url, json=data, headers=headers, timeout=timeout)
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=timeout)
        else:
            raise ValueError(f"Unsupported method {method}")
        print(f"{method} {path} -> {resp.status_code}")
        if resp.status_code != expect_status:
            print(f"  !!! Expected {expect_status}, got {resp.status_code}")
            print(f"  Response: {resp.text}")
        return resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
    except Exception as e:
        print(f"Request failed: {e}")
        return None

def create_agent_heartbeat(agent_id, cpu=10.0, ram=20.0, disk=30.0):
    return {
        "agent_id": agent_id,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

def create_link(link_id, source, target, capacity=1000, latency=5, packet_loss=0.0, is_active=True):
    return {
        "id": link_id,
        "source_agent_id": source,
        "target_agent_id": target,
        "capacity": capacity,
        "reserved_bandwidth": 0,
        "latency": latency,
        "load": 0,
        "packet_loss": packet_loss,
        "is_active": is_active
    }

def create_topology_update(link_id, source, target, new_latency, new_load, new_packet_loss, is_active, reason="test"):
    return {
        "link_id": link_id,
        "source_agent_id": source,
        "target_agent_id": target,
        "new_latency": new_latency,
        "new_load": new_load,
        "new_packet_loss": new_packet_loss,
        "is_active": is_active,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason
    }

def create_path_request(src, dst, required_bandwidth, priority=1, exclude_link_ids=None, max_hops=10):
    return {
        "source_agent_id": src,
        "destination_agent_id": dst,
        "required_bandwidth": required_bandwidth,
        "priority": priority,
        "exclude_link_ids": exclude_link_ids or [],
        "max_hops": max_hops
    }

def create_path_release(session_id, link_ids, allocated_bandwidth):
    return {
        "session_id": session_id,
        "link_ids": link_ids,
        "allocated_bandwidth": allocated_bandwidth,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

def query_db(sql):
    """Chạy lệnh SQL trực tiếp trong container db."""
    cmd = f"docker-compose exec -T db psql -U larp -d larpdb -c \"{sql}\""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return result.stdout.strip()
    except Exception as e:
        print(f"Lỗi truy vấn DB: {e}")
        return None

# ------------------------------------------------------------
# Các test case
# ------------------------------------------------------------
def test_health():
    print("1. Health check")
    resp = requests.get(HEALTH_URL)
    print(f"   Health: {resp.status_code} - {resp.json()}")
    assert resp.status_code == 200, "Health check thất bại"

def test_heartbeats():
    print("\n2. Gửi heartbeat để kích hoạt agents")
    agents = ["client1", "client2", "client3", "client4"]
    for agent in agents:
        data = create_agent_heartbeat(agent)
        resp = send_request("POST", "agents/heartbeat", data)
        assert resp is not None, f"Heartbeat {agent} thất bại"
        print(f"   {agent}: {resp}")

def test_create_links():
    print("\n3. Tạo topology links")
    links = [
        ("link-001", "client1", "client2", 1000),
        ("link-002", "client2", "client3", 1000),
        ("link-003", "client3", "client4", 1000),
        ("link-004", "client1", "client3", 500),
    ]
    for link_id, src, dst, cap in links:
        data = create_link(link_id, src, dst, capacity=cap)
        resp = send_request("POST", "topology/links", data, expect_status=201)
        assert resp is not None, f"Tạo link {link_id} thất bại"
        print(f"   {link_id} đã tạo")

def test_topology_update():
    print("\n4. Cập nhật topology cho link-001")
    update = create_topology_update("link-001", "client1", "client2",
                                    new_latency=5, new_load=0, new_packet_loss=0.5,
                                    is_active=True, reason="initial")
    resp = send_request("POST", "topology/update", update)
    assert resp is not None, "Topology update thất bại"
    print(f"   link-001 updated: {resp}")

def test_path_request_basic():
    print("\n5. Yêu cầu đường từ client1 đến client4 (100 Mbps)")
    req = create_path_request("client1", "client4", 100)
    path = send_request("POST", "path/request", req)
    assert path and path.get("found"), "Không tìm thấy đường dù đáng lẽ phải có"
    print(f"   Đường tìm thấy: {path}")
    session_id = path.get("session_id")
    if session_id:
        print("\n6. Giải phóng băng thông")
        release = create_path_release(session_id, path["link_ids"], 100)
        resp = send_request("POST", "path/release", release)
        assert resp is not None, "Giải phóng thất bại"
        print(f"   Phản hồi: {resp}")

def test_excessive_bandwidth():
    print("\n7. Yêu cầu băng thông quá lớn (900 Mbps)")
    req = create_path_request("client1", "client4", 900)
    path = send_request("POST", "path/request", req, expect_status=404)
    assert path is not None and not path.get("found"), "Đáng lẽ phải từ chối 900 Mbps"
    print(f"   Từ chối thành công: {path}")

def test_link_failure_and_reroute():
    print("\n8. Mô phỏng link-001 down")
    update = create_topology_update("link-001", "client1", "client2",
                                    new_latency=999, new_load=0, new_packet_loss=100.0,
                                    is_active=False, reason="simulated_down")
    resp = send_request("POST", "topology/update", update)
    assert resp is not None, "Topology update thất bại"
    print(f"   link-001 down: {resp}")

    print("\n9. Yêu cầu đường sau khi link-001 down (100 Mbps)")
    req = create_path_request("client1", "client4", 100)
    path = send_request("POST", "path/request", req)
    if path and path.get("found"):
        print(f"   Đường mới: {path}")
        # Giải phóng nếu có
        release = create_path_release(path["session_id"], path["link_ids"], 100)
        send_request("POST", "path/release", release)
    else:
        print("   Không tìm thấy đường (có thể do không còn route thay thế)")

def test_frontend_endpoints():
    print("\n10. Kiểm tra các API cho frontend (GET)")
    endpoints = [
        ("agents", "agents"),
        ("topology/links", "topology/links"),
        ("incidents", "incidents"),
        ("events", "events"),
        ("flows", "flows"),
        ("rules", "rules"),
        ("commands", "commands"),
    ]
    for name, path in endpoints:
        resp = send_request("GET", path, expect_status=200)
        if resp is not None:
            if isinstance(resp, list):
                print(f"   {name}: trả về {len(resp)} phần tử")
            elif isinstance(resp, dict):
                print(f"   {name}: trả về dict với keys {list(resp.keys())}")
            else:
                print(f"   {name}: trả về {type(resp)}")
        else:
            print(f"   {name}: THẤT BẠI")

def test_agent_offline_sweep():
    print("\n11. Kiểm tra sweep_dead_agents khi client1 offline")
    # Gửi heartbeat cho các agent còn lại để giữ active
    for agent in ["client2", "client3", "client4"]:
        data = create_agent_heartbeat(agent)
        send_request("POST", "agents/heartbeat", data)

    print("   Chờ 35 giây để scheduler quét agent chết...")
    for _ in range(7):  # 7 lần * 5 giây = 35s
        time.sleep(5)
        for agent in ["client2", "client3", "client4"]:
            data = create_agent_heartbeat(agent)
            send_request("POST", "agents/heartbeat", data)

    # Kiểm tra DB
    sql = "SELECT id, hostname, status, last_seen FROM agents WHERE id='client1';"
    result = query_db(sql)
    print(f"   Kết quả DB:\n{result}")
    if result and 'DEAD' in result.upper():
        print("   client1 đã DEAD như mong đợi.")
    else:
        print("   CẢNH BÁO: client1 có thể chưa DEAD, kiểm tra scheduler và threshold.")

    # Kiểm tra link liên quan
    sql_links = "SELECT id, is_active FROM topology_links WHERE source_agent_id='client1' OR target_agent_id='client1';"
    links_result = query_db(sql_links)
    print(f"   Link liên quan client1:\n{links_result}")

    # Path request từ client2 đến client4 nên tránh client1
    print("   Yêu cầu đường từ client2 đến client4 (nên tránh client1)")
    req = create_path_request("client2", "client4", 100)
    path = send_request("POST", "path/request", req)
    if path and path.get("found"):
        print(f"   Đường tìm thấy: {path}")
        assert "client1" not in path["path"], f"Đường không nên chứa client1, got {path['path']}"
        print("   Thành công: Đường tránh agent chết client1.")
        release = create_path_release(path["session_id"], path["link_ids"], 100)
        send_request("POST", "path/release", release)
    else:
        print("   Không tìm thấy đường (có thể do không còn route)")

def test_concurrent_path_requests():
    print("\n12. Kiểm tra concurrent path requests (tránh deadlock)")
    def send_path_request(_):
        req = create_path_request("client1", "client4", 50, priority=1)
        return send_request("POST", "path/request", req)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_path_request, i) for i in range(10)]
        results = []
        for future in as_completed(futures):
            try:
                res = future.result(timeout=15)
                results.append(res)
            except Exception as e:
                print(f"   Lỗi request: {e}")
                results.append(None)
    success_count = sum(1 for r in results if r and r.get("found"))
    print(f"   Hoàn thành {len(results)} yêu cầu, {success_count} thành công.")
    if success_count == 0:
        print("   CẢNH BÁO: Không có yêu cầu nào thành công, có thể deadlock hoặc hết băng thông.")
    else:
        print("   OK: Một số đường đã được cấp phát; giải phóng tất cả...")
        for r in results:
            if r and r.get("found"):
                release = create_path_release(r["session_id"], r["link_ids"], r["allocated_bandwidth"])
                send_request("POST", "path/release", release)

def run_all_tests():
    cleanup_database()
    test_health()
    test_heartbeats()
    test_create_links()
    test_topology_update()
    test_path_request_basic()
    test_concurrent_path_requests()   # <-- chạy ở đây
    test_excessive_bandwidth()
    test_link_failure_and_reroute()
    test_frontend_endpoints()
    test_agent_offline_sweep()       # chạy cuối cùng

    print("\n=== Tất cả các test cơ bản đã hoàn thành ===")

if __name__ == "__main__":
    run_all_tests()