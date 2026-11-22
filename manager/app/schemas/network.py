from datetime import datetime
from ipaddress import ip_network
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Operation = Literal["enable", "disable", "reload", "add_rule", "delete_rule", "set_policy", "set_logging", "commit", "rollback"]
Section = Literal["overview", "firewall", "ports", "connections", "interfaces", "routes", "policy", "neighbors", "nat", "events"]
HexId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class NetworkSnapshotIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    schema_version: Literal[1]
    timestamp: datetime
    collected_at: datetime
    snapshot_id: HexId
    command_id: HexId | None = None
    platform: Literal["linux", "windows", "darwin"]
    status: Literal["ok", "partial", "unsupported"]
    sections: dict[Section, dict]


class FirewallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    operation: Operation
    reason: str = Field(min_length=1, max_length=255)
    confirmed: Literal[True]

    @field_validator("confirmed", mode="before")
    @classmethod
    def validate_confirmation(cls, value):
        if value is not True:
            raise ValueError("Explicit confirmation is required")
        return value

    rule_id: Annotated[str, Field(pattern=r"^[0-9a-f]{24}$")] | None = None
    protocol: Literal["tcp", "udp"] | None = None
    port: Annotated[int, Field(strict=True, ge=1, le=65535)] | None = None
    source: str | None = Field(default=None, max_length=64)
    interface: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}$")
    action: Literal["allow", "deny", "reject"] | None = None
    direction: Literal["incoming", "outgoing", "routed"] | None = None
    logging: Literal["off", "low", "medium", "high", "full"] | None = None
    transaction_id: HexId | None = None

    @field_validator("source")
    @classmethod
    def validate_source(cls, value):
        if value is None:
            return None
        if "%" in value:
            raise ValueError("Scoped IPv6 addresses are unsupported")
        return str(ip_network(value, strict=True))

    @model_validator(mode="after")
    def validate_operation_fields(self) -> Self:
        required, optional = {
            "add_rule": ({"protocol", "port", "action"}, {"source", "interface"}),
            "delete_rule": ({"rule_id"}, set()),
            "set_policy": ({"action", "direction"}, set()),
            "set_logging": ({"logging"}, set()),
            "commit": ({"transaction_id"}, set()),
            "rollback": ({"transaction_id"}, set()),
        }.get(self.operation, (set(), set()))
        present = self.model_dump(exclude_none=True).keys() - {"operation", "reason", "confirmed"}
        if not required <= present <= required | optional:
            raise ValueError("Parameters do not match the operation")
        return self


class NetworkView(BaseModel):
    agent_id: str
    online: bool
    stale: bool
    status: str
    role: str
    snapshot_id: str | None = None
    collected_at: datetime | None = None
    data: dict = Field(default_factory=dict)


class NetworkQueued(BaseModel):
    command_id: str
    action_id: str | None = None
    status: str


class NetworkAck(BaseModel):
    agent_id: str
    schema_version: Literal[1]
    command_id: HexId
    snapshot_id: HexId | None = None
    timestamp: datetime
    status: Literal["success", "failed"]
    error: str | None = Field(default=None, max_length=500)
    transaction: dict | None = None
