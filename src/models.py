"""Serializable records shared by capture, detection, and storage."""
from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    message: str


@dataclass
class PacketRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    payload: bytes = b""
    tcp_flags: int = 0
    alerts: list[Alert] = field(default_factory=list)

    def to_dict(self):
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        result["payload"] = self.payload.hex()
        return result
