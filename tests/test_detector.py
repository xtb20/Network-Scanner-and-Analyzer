from datetime import datetime, timezone
import unittest

from src.detector import Detector
from src.models import PacketRecord


def record(port=80, time=100, payload=b"", src="192.0.2.1", dst="192.0.2.2", flags=2):
    return PacketRecord(datetime.fromtimestamp(time, timezone.utc), src, dst, "TCP", 50000, port, 60, payload, flags)


class DetectorTests(unittest.TestCase):
    def test_port_and_signatures(self):
        detector = Detector({"flagged_ports": [23], "signatures": [
            {"name": "text", "text": "Hello", "case_sensitive": False},
            {"name": "binary", "hex": "00 ff"}]})
        alerts = detector.inspect(record(23, payload=b"HELLO\x00\xff"))
        self.assertEqual([a.rule for a in alerts], ["flagged-port", "text", "binary"])

    def test_unique_ports_and_suppression(self):
        detector = Detector({"port_scan": {"unique_ports": 3, "window_seconds": 10}})
        for port in (1, 1, 2):
            self.assertEqual(detector.inspect(record(port)), [])
        self.assertEqual(detector.inspect(record(3))[0].rule, "port-scan")
        self.assertEqual(detector.inspect(record(4)), [])
        self.assertEqual(detector.inspect(record(5, time=111)), [])
        detector.inspect(record(6, time=112))
        self.assertEqual(detector.inspect(record(7, time=113))[0].rule, "port-scan")

    def test_destinations_and_syn_ack_are_separate(self):
        detector = Detector({"port_scan": {"unique_ports": 2}})
        detector.inspect(record(1))
        self.assertEqual(detector.inspect(record(2, dst="192.0.2.3")), [])
        self.assertEqual(detector.inspect(record(2, flags=18)), [])
        self.assertEqual(detector.inspect(record(2))[0].rule, "port-scan")

    def test_expiry_and_out_of_order_packets(self):
        detector = Detector({"port_scan": {"unique_ports": 2, "window_seconds": 10}})
        detector.inspect(record(1, time=100))
        self.assertEqual(detector.inspect(record(2, time=111)), [])
        self.assertEqual(detector.inspect(record(3, time=90)), [])
        self.assertEqual(detector.inspect(record(4, time=110))[0].rule, "port-scan")

    def test_state_is_bounded(self):
        detector = Detector({"port_scan": {"unique_ports": 3, "max_sources": 2}})
        for port in range(10):
            detector.inspect(record(port))
        self.assertEqual(len(next(iter(detector.sources.values()))[1]), 3)
        for index in range(10):
            detector.inspect(record(src=f"192.0.2.{index}"))
        self.assertEqual(len(detector.sources), 2)

    def test_invalid_rules(self):
        for rules in ([], {"flagged_ports": [65536]}, {"signatures": [{"name": "bad", "hex": "xz"}]},
                      {"port_scan": {"unique_ports": 0}}, {"signatures": [{"name": "empty", "text": ""}]}):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                Detector(rules)

    def test_default_rules_load(self):
        self.assertTrue(Detector.from_yaml().ports)


if __name__ == "__main__":
    unittest.main()
