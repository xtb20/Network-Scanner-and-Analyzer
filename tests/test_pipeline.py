import io
import json
import os
from pathlib import Path
from queue import Queue
import subprocess
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import MagicMock, patch

from scapy.all import IP, TCP, Raw, wrpcap

from config.settings import Settings
from src.capture import packet_to_record
from src.database import BatchWorker, JsonSink, PostgresSink
from src.detector import Detector


class PipelineTests(unittest.TestCase):
    def test_idle_flush_does_not_wait_for_shutdown(self):
        queue = Queue()
        flushed = Event()
        sink = MagicMock()
        sink.write.side_effect = lambda records: flushed.set()
        worker = BatchWorker(queue, Detector({}), sink, 100, 0.02)
        queue.put(packet_to_record(IP()/TCP()))
        worker.start()
        try:
            self.assertTrue(flushed.wait(2))
        finally:
            worker.stopping.set()
            worker.join(2)
        self.assertEqual(worker.written, 1)

    def test_shutdown_flushes_partial_batch(self):
        queue = Queue()
        output = io.StringIO()
        worker = BatchWorker(queue, Detector({"flagged_ports": [23]}), JsonSink(output), 100)
        queue.put(packet_to_record(IP()/TCP(dport=23)))
        worker.start()
        worker.stopping.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertIsNone(worker.error)
        self.assertEqual(worker.written, 1)
        self.assertEqual(queue.unfinished_tasks, 0)
        self.assertEqual(json.loads(output.getvalue())["alerts"][0]["rule"], "flagged-port")

    def test_storage_failure_is_reported(self):
        queue = Queue()
        sink = MagicMock()
        sink.write.side_effect = OSError("disk full")
        worker = BatchWorker(queue, Detector({}), sink, 1)
        queue.put(packet_to_record(IP()/TCP()))
        worker.start()
        self.assertTrue(worker.failed.wait(2))
        worker.join(2)
        self.assertIsInstance(worker.error, OSError)
        self.assertEqual(worker.written, 0)

    def test_postgres_transaction_and_pool_release(self):
        with patch("psycopg2.pool.ThreadedConnectionPool") as pool_type, patch("psycopg2.extras.execute_values") as insert:
            sink = PostgresSink("postgresql://unused")
            connection = pool_type.return_value.getconn.return_value
            sink.write([packet_to_record(IP()/TCP())])
            self.assertEqual(len(insert.call_args.args[2]), 1)
            connection.__exit__.assert_called_with(None, None, None)
            pool_type.return_value.putconn.assert_called_with(connection)
            insert.side_effect = RuntimeError("database unavailable")
            with self.assertRaises(RuntimeError):
                sink.write([packet_to_record(IP()/TCP())])
            self.assertEqual(connection.__exit__.call_args.args[0], RuntimeError)
            self.assertEqual(pool_type.return_value.putconn.call_count, 2)
            sink.close()
            pool_type.return_value.closeall.assert_called_once()

    def test_environment_validation(self):
        with patch.dict(os.environ, {"BATCH_SIZE": "0"}):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_offline_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap, output = Path(directory)/"input.pcap", Path(directory)/"output.jsonl"
            packets = [IP(src="192.0.2.1", dst="192.0.2.2")/TCP(dport=23)/Raw(b"PACKET_INSPECTOR_TEST"),
                       IP(src="192.0.2.1", dst="192.0.2.2")/TCP(dport=443)]
            wrpcap(str(pcap), packets)
            result = subprocess.run([sys.executable, "main.py", "--pcap", str(pcap), "--output", str(output)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(len(rows[0]["alerts"]), 2)
            self.assertEqual(rows[1]["alerts"], [])
            self.assertIn("Saved 2 packets", result.stderr)
            rejected = subprocess.run([sys.executable, "main.py", "--pcap", str(pcap), "--output", str(pcap)],
                                      capture_output=True, text=True, timeout=15)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("must not overwrite", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
