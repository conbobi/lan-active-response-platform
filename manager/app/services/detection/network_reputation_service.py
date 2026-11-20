import socket
import logging
import ipaddress
from typing import Dict, Any, Optional, Tuple, List

logger = logging.getLogger(__name__)

# Pre-indexed CIDR blocks for fast, offline, and reliable BGP/ASN lookup
KNOWN_PREFIXES: List[Tuple[ipaddress.IPv4Network, str, str, str]] = [
    # Microsoft Corporation (AS8075)
    (ipaddress.ip_network("150.171.0.0/16"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),
    (ipaddress.ip_network("40.79.0.0/16"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),
    (ipaddress.ip_network("20.0.0.0/8"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),
    (ipaddress.ip_network("13.64.0.0/11"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),
    (ipaddress.ip_network("52.96.0.0/12"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),
    (ipaddress.ip_network("52.112.0.0/14"), "AS8075", "Microsoft Corporation", "cloud_infrastructure"),

    # Cloudflare, Inc. (AS13335)
    (ipaddress.ip_network("104.16.0.0/12"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),
    (ipaddress.ip_network("172.64.0.0/13"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),
    (ipaddress.ip_network("162.158.0.0/15"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),
    (ipaddress.ip_network("108.162.192.0/18"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),
    (ipaddress.ip_network("198.41.128.0/17"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),
    (ipaddress.ip_network("173.245.48.0/20"), "AS13335", "Cloudflare, Inc.", "cdn_proxy"),

    # OVH SAS / Remote Relay Hosting (AS16276)
    (ipaddress.ip_network("15.235.0.0/16"), "AS16276", "OVH SAS", "hosting_provider"),
    (ipaddress.ip_network("178.32.0.0/15"), "AS16276", "OVH SAS", "hosting_provider"),
    (ipaddress.ip_network("141.94.0.0/15"), "AS16276", "OVH SAS", "hosting_provider"),
    (ipaddress.ip_network("51.254.0.0/15"), "AS16276", "OVH SAS", "hosting_provider"),

    # Google LLC (AS15169)
    (ipaddress.ip_network("142.250.0.0/15"), "AS15169", "Google LLC", "cloud_infrastructure"),
    (ipaddress.ip_network("172.217.0.0/16"), "AS15169", "Google LLC", "cloud_infrastructure"),

    # Amazon Web Services (AS16509)
    (ipaddress.ip_network("3.0.0.0/9"), "AS16509", "Amazon.com, Inc.", "cloud_infrastructure"),
    (ipaddress.ip_network("52.0.0.0/11"), "AS16509", "Amazon.com, Inc.", "cloud_infrastructure"),
    (ipaddress.ip_network("54.0.0.0/10"), "AS16509", "Amazon.com, Inc.", "cloud_infrastructure"),
]


class NetworkReputationService:
    """
    Provides IP, ASN, and reverse DNS enrichment as CONTEXTUAL TELEMETRY.
    Strictly follows SOC Principle 1:
    - Reputation is an informational attribute, NEVER an automatic trust bypass or blanket allowlist!
    - Threat intelligence detections always override infrastructure reputation.
    """

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def get_reputation(cls, ip: str) -> Dict[str, Any]:
        """
        Enrich an IP address with ASN, Organization, Category, and PTR reverse DNS.
        Returns a rich contextual dictionary.
        """
        if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1", "localhost"):
            return {
                "ip": ip,
                "asn": "LOCAL",
                "org": "Loopback/Local",
                "category": "loopback",
                "reverse_dns": "localhost",
                "is_known_provider": False
            }

        if ip in cls._cache:
            return cls._cache[ip]

        asn = "UNKNOWN"
        org = "Unknown Operator"
        category = "public_internet"

        # 1. Check CIDR table
        try:
            ip_obj = ipaddress.ip_address(ip)
            for subnet, sub_asn, sub_org, sub_cat in KNOWN_PREFIXES:
                if ip_obj in subnet:
                    asn = sub_asn
                    org = sub_org
                    category = sub_cat
                    break
        except Exception:
            pass

        # 2. Check PTR reverse DNS
        ptr_name = ""
        try:
            ptr_name = socket.gethostbyaddr(ip)[0].lower()
            if "anydesk" in ptr_name:
                category = "remote_access_relay"
                if org == "Unknown Operator":
                    org = "AnyDesk Relay Infrastructure"
            elif "cloudflare" in ptr_name:
                category = "cdn_proxy"
                if org == "Unknown Operator":
                    asn = "AS13335"
                    org = "Cloudflare, Inc."
            elif any(k in ptr_name for k in ("microsoft", "azure", "msedge")):
                category = "cloud_infrastructure"
                if org == "Unknown Operator":
                    asn = "AS8075"
                    org = "Microsoft Corporation"
        except Exception:
            pass

        result = {
            "ip": ip,
            "asn": asn,
            "org": org,
            "category": category,
            "reverse_dns": ptr_name,
            "is_known_provider": asn != "UNKNOWN" or category in ("remote_access_relay", "cdn_proxy", "cloud_infrastructure")
        }
        cls._cache[ip] = result
        return result

    @classmethod
    def evaluate_behavioral_context(
        cls,
        process_name: Optional[str],
        dst_ip: str,
        dst_port: int = 443,
        threat_intel_malicious: bool = False
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a connection is an expected, legitimate vendor interaction.
        Rules:
        - If Threat Intel reports malicious -> NEVER expected!
        - If process is an unexpected shell/interpreter executing suspicious commands -> NEVER expected!
        - Returns (is_expected_benign_traffic, explanation).
        """
        if threat_intel_malicious:
            return False, "Destination IP is flagged malicious by Threat Intelligence."

        p_name = (process_name or "").lower().strip()
        rep = cls.get_reputation(dst_ip)
        ptr = rep.get("reverse_dns", "").lower()
        asn = rep.get("asn", "")
        org = rep.get("org", "")

        # Suspicious processes (shells, netcat) are NEVER benign regardless of destination
        shell_binaries = {"sh", "bash", "zsh", "cmd.exe", "powershell.exe", "powershell", "nc", "ncat", "socat"}
        if p_name in shell_binaries:
            return False, f"Shell process '{p_name}' connecting to external endpoint {dst_ip}."

        # Case 1: AnyDesk remote control client talking to AnyDesk relay
        if "anydesk" in p_name and ("anydesk" in ptr or asn == "AS16276"):
            return True, f"Legitimate AnyDesk remote session via relay {ptr or dst_ip} ({org})."

        # Case 2: VS Code / Copilot runtime talking to Microsoft cloud
        if p_name in ("code", "copilot-runtime", "node") and (asn == "AS8075" or "microsoft" in org.lower() or "azure" in ptr):
            return True, f"Standard developer environment telemetry/API connection to {org}."

        # Case 3: Cloudflare tunnel client (cloudflared) connecting to Cloudflare Edge
        if "cloudflared" in p_name and (asn == "AS13335" or "cloudflare" in org.lower()):
            return True, f"Cloudflare Tunnel outbound edge connection ({org})."

        return False, ""

