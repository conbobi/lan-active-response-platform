import struct
import socket
import threading
import logging
from collections import deque
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    255: "ANY"
}


def parse_dns_question(payload: bytes) -> Optional[Dict[str, Any]]:
    """
    Lightweight pure-python DNS packet parser without Scapy dependencies.
    Extracts QNAME and QTYPE from raw DNS UDP payload.
    """
    try:
        if len(payload) < 12:
            return None

        # Unpack Header
        _, _, qdcount, _, _, _ = struct.unpack("!HHHHHH", payload[:12])
        if qdcount < 1:
            return None

        # Parse Question Name
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length > 63:  # Compression pointer or invalid
                break
            offset += 1
            label = payload[offset:offset + length].decode("ascii", errors="ignore")
            labels.append(label)
            offset += length

        qname = ".".join(labels)
        if offset + 4 <= len(payload):
            qtype_id, _ = struct.unpack("!HH", payload[offset:offset + 4])
            qtype = TYPE_MAP.get(qtype_id, f"TYPE_{qtype_id}")
        else:
            qtype = "A"

        return {
            "query": qname,
            "query_type": qtype,
            "length": len(qname),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception:
        return None


class DnsSniffer:
    """
    Lightweight in-memory DNS sniffer maintaining recent DNS query telemetry.
    Can capture packets via raw socket or accept programmatic query recordings.
    """

    def __init__(self, max_buffer: int = 50):
        self.buffer = deque(maxlen=max_buffer)
        self.lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def record_query(self, query: str, query_type: str = "A"):
        """Programmatically record a DNS query event."""
        with self.lock:
            self.buffer.append({
                "query": query.strip().lower(),
                "query_type": query_type.upper(),
                "length": len(query.strip()),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    def start_background_sniffer(self, interface: str = "eth0"):
        """Attempts to sniff UDP 53 packets using standard Linux raw sockets."""
        if self._running:
            return

        def _sniff_loop():
            try:
                # AF_PACKET raw socket filtering IPv4
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
                s.settimeout(2.0)
                while self._running:
                    try:
                        raw_data, _ = s.recvfrom(2048)
                        # IP Header is at offset 14 (Ethernet header)
                        if len(raw_data) < 34:
                            continue
                        proto = raw_data[23]
                        if proto == 17:  # UDP
                            ip_header_len = (raw_data[14] & 0x0F) * 4
                            udp_offset = 14 + ip_header_len
                            if len(raw_data) >= udp_offset + 8:
                                src_port, dst_port, _, _ = struct.unpack("!HHHH", raw_data[udp_offset:udp_offset + 8])
                                if dst_port == 53 or src_port == 53:
                                    dns_payload = raw_data[udp_offset + 8:]
                                    item = parse_dns_question(dns_payload)
                                    if item and item.get("query"):
                                        with self.lock:
                                            self.buffer.append(item)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
            except Exception as e:
                logger.debug(f"Raw socket sniffer unavailable (requires root/CAP_NET_RAW): {e}")

        self._running = True
        self._thread = threading.Thread(target=_sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def get_recent_queries(self) -> List[Dict[str, Any]]:
        """Retrieve and flush the buffered queries for telemetry report."""
        with self.lock:
            queries = list(self.buffer)
            # Retain small history buffer to maintain temporal correlation
            return queries


global_dns_sniffer = DnsSniffer()
