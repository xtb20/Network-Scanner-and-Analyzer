"""Convert Scapy packets and feed a bounded queue without blocking live capture."""
import logging
from datetime import datetime, timezone
from queue import Full

from scapy.all import IP, IPv6, TCP, UDP

from src.models import PacketRecord
from src.utils import normalize_ip

LOG = logging.getLogger(__name__)


def packet_to_record(packet, payload_limit=2048):
    if payload_limit < 0:
        raise ValueError("payload_limit must be nonnegative")
    if IP in packet:
        network = packet[IP]
    elif IPv6 in packet:
        network = packet[IPv6]
    else:
        return None
    # Do not interpret tunneled inner transport as the outer connection.
    transport = network.payload
    while transport.__class__.__name__.startswith("IPv6ExtHdr"):
        transport = transport.payload
    is_transport = isinstance(transport, (TCP, UDP))
    protocol = "TCP" if isinstance(transport, TCP) else "UDP" if isinstance(transport, UDP) else transport.name
    return PacketRecord(
        timestamp=datetime.fromtimestamp(float(packet.time), timezone.utc),
        src_ip=normalize_ip(network.src), dst_ip=normalize_ip(network.dst),
        protocol=protocol,
        src_port=int(transport.sport) if is_transport else None,
        dst_port=int(transport.dport) if is_transport else None,
        length=int(getattr(packet, "wirelen", None) or len(packet)),
        payload=bytes(transport.payload)[:payload_limit] if is_transport else b"",
        tcp_flags=int(transport.flags) if isinstance(transport, TCP) else 0,
    )


class CaptureProducer:
    def __init__(self, queue, payload_limit=2048):
        self.queue = queue
        self.payload_limit = payload_limit
        self.accepted = self.dropped = self.ignored = self.malformed = 0

    def __call__(self, packet):
        try:
            record = packet_to_record(packet, self.payload_limit)
        except (ValueError, TypeError, AttributeError, OverflowError, OSError):
            self.malformed += 1
            LOG.debug("Skipping malformed packet", exc_info=True)
            return
        if record is None:
            self.ignored += 1
            return
        try:
            self.queue.put_nowait(record)
            self.accepted += 1
        except Full:
            self.dropped += 1
