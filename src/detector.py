"""Per-packet signatures and bounded, event-time port scan heuristics."""
from collections import OrderedDict
from importlib.resources import files
import math

import yaml

from src.models import Alert


class Detector:
    def __init__(self, rules):
        if not isinstance(rules, dict):
            raise ValueError("Rules must be a YAML mapping")
        ports = rules.get("flagged_ports", [])
        if not isinstance(ports, list) or any(type(p) is not int or not 0 <= p <= 65535 for p in ports):
            raise ValueError("flagged_ports must contain port integers from 0 to 65535")
        self.ports = set(ports)
        self.signatures = []
        signatures = rules.get("signatures", [])
        if not isinstance(signatures, list):
            raise ValueError("signatures must be a list")
        for item in signatures:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
                raise ValueError("Each signature needs a nonempty name")
            if ("text" in item) == ("hex" in item):
                raise ValueError("Each signature needs exactly one of text or hex")
            value = item.get("text", item.get("hex"))
            if not isinstance(value, str):
                raise ValueError("Signature text or hex must be a string")
            pattern = value.encode() if "text" in item else bytes.fromhex(value)
            sensitive = item.get("case_sensitive", True)
            if not pattern or type(sensitive) is not bool:
                raise ValueError("Signature must be nonempty and case_sensitive must be boolean")
            self.signatures.append((item["name"], pattern if sensitive else pattern.lower(), sensitive))
        scan = rules.get("port_scan", {})
        if not isinstance(scan, dict):
            raise ValueError("port_scan must be a mapping")
        self.window = scan.get("window_seconds", 10)
        self.threshold = scan.get("unique_ports", 20)
        self.max_sources = scan.get("max_sources", 10000)
        if type(self.window) not in (int, float) or not math.isfinite(self.window) or self.window <= 0:
            raise ValueError("window_seconds must be positive and finite")
        if any(type(v) is not int or v <= 0 for v in (self.threshold, self.max_sources)):
            raise ValueError("unique_ports and max_sources must be positive integers")
        self.sources = OrderedDict()
        self.watermark = float("-inf")

    @classmethod
    def from_yaml(cls, path=None):
        text = files("config").joinpath("rules.yaml").read_text(encoding="utf-8") if path is None else path.read_text(encoding="utf-8")
        return cls(yaml.safe_load(text))

    def inspect(self, packet):
        alerts = []
        if packet.src_port in self.ports or packet.dst_port in self.ports:
            alerts.append(Alert("flagged-port", "medium", f"Flagged port on {packet.src_port} -> {packet.dst_port}"))
        for name, pattern, sensitive in self.signatures:
            if pattern in (packet.payload if sensitive else packet.payload.lower()):
                alerts.append(Alert(name, "high", "Payload signature matched"))
        now = packet.timestamp.timestamp()
        self.watermark = max(self.watermark, now)
        cutoff = self.watermark - self.window
        # Ordered by last activity; expire quiet sources, cap remaining state.
        while self.sources and next(iter(self.sources.values()))[0] < cutoff:
            self.sources.popitem(last=False)
        if now >= cutoff and packet.protocol == "TCP" and packet.tcp_flags & 2 and not packet.tcp_flags & 16:
            key = (packet.src_ip, packet.dst_ip)
            last, ports, reported = self.sources.pop(key, (now, {}, False))
            ports = {p: t for p, t in ports.items() if t >= cutoff}
            if len(ports) < self.threshold:
                reported = False
            ports[packet.dst_port] = max(now, ports.get(packet.dst_port, now))
            if len(ports) >= self.threshold and not reported:
                alerts.append(Alert("port-scan", "high", f"At least {self.threshold} destination ports within {self.window}s"))
                reported = True
            # Retain only the most recent threshold ports: sufficient to detect threshold crossings.
            if len(ports) > self.threshold:
                del ports[min(ports, key=ports.get)]
            self.sources[key] = (max(last, self.watermark), ports, reported)
            while len(self.sources) > self.max_sources:
                self.sources.popitem(last=False)
        packet.alerts = alerts
        return alerts
