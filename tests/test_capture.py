import unittest
from queue import Queue

from scapy.all import ARP, Ether, IP, IPv6, Raw, TCP, UDP

from src.capture import CaptureProducer, packet_to_record


class CaptureTests(unittest.TestCase):
    def test_tcp_metadata_and_payload_limit(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.1", dst="192.0.2.2")/TCP(sport=1234, dport=23, flags="S")/Raw(b"abcdef")
        packet.time = 100
        record = packet_to_record(packet, 3)
        self.assertEqual((record.src_ip, record.dst_port, record.protocol), ("192.0.2.1", 23, "TCP"))
        self.assertEqual(record.payload, b"abc")
        self.assertEqual(record.tcp_flags, 2)
        self.assertEqual(record.timestamp.timestamp(), 100)
        self.assertEqual(record.length, len(packet))

    def test_ipv6_udp(self):
        record = packet_to_record(IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(dport=53)/Raw(b"query"))
        self.assertEqual(record.protocol, "UDP")
        self.assertEqual(record.src_ip, "2001:db8::1")
        self.assertEqual(record.payload, b"query")

    def test_non_ip_is_ignored(self):
        self.assertIsNone(packet_to_record(Ether()/ARP()))

    def test_tunnel_does_not_leak_inner_ports(self):
        record = packet_to_record(IP(src="192.0.2.1")/IP()/TCP(dport=23))
        self.assertIsNone(record.dst_port)

    def test_full_queue_drops_without_blocking(self):
        queue = Queue(maxsize=1)
        producer = CaptureProducer(queue)
        producer(IP()/TCP())
        producer(IP()/TCP())
        producer(Ether()/ARP())
        self.assertEqual((producer.accepted, producer.dropped, producer.ignored), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
