from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
from app.schemas.base import ORMBaseModel


class ProcessItem(BaseModel):
    name: str
    pid: Optional[int] = None
    path: Optional[str] = None
    hash: Optional[str] = None
    is_suspicious: bool = False
    is_injected: bool = False
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    cmdline: Optional[str] = None


class NetworkConnectionItem(BaseModel):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    status: Optional[str] = None


class ProcessTreeItem(BaseModel):
    parent_pid: Optional[int] = None
    parent_name: str
    child_pid: Optional[int] = None
    child_name: str
    cmdline: Optional[str] = None


class RegistryChange(BaseModel):
    hive: Optional[str] = None
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    action: str = "modify"  # create, modify, delete


class CredentialAccessEvent(BaseModel):
    source_pid: Optional[int] = None
    source_process: Optional[str] = None
    target_object: str  # e.g., lsass.exe, SAM, SECURITY
    access_mask: Optional[str] = None
    details: Optional[str] = None


class LateralMovementEvent(BaseModel):
    event_type: str  # port_scan, smb_session, wmi_execution, winrm, rdp
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    details: Optional[str] = None


class DnsQueryItem(BaseModel):
    query: str
    query_type: Optional[str] = "A"
    resolved_ips: List[str] = Field(default_factory=list)


class RiskAssessmentDTO(BaseModel):
    agent_id: str
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    disk_usage: float = 0.0
    process_list: List[Dict[str, Any]] = Field(default_factory=list)
    network_connections: List[Dict[str, Any]] = Field(default_factory=list)
    file_changes_count: int = 0
    suspicious_commands: List[str] = Field(default_factory=list)
    shadow_copy_deletion: bool = False
    registry_changes: List[Dict[str, Any]] = Field(default_factory=list)
    credential_access_events: List[Dict[str, Any]] = Field(default_factory=list)
    lateral_movement_events: List[Dict[str, Any]] = Field(default_factory=list)
    mass_file_modification: bool = False
    dns_queries: List[Union[str, Dict[str, Any]]] = Field(default_factory=list)
    process_tree: List[Dict[str, Any]] = Field(default_factory=list)


class RiskScoreOut(ORMBaseModel):
    id: str
    agent_id: str
    score: float
    factors: Dict[str, Any]
    timestamp: datetime
