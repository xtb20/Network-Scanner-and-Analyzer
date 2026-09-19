"""Transactional batch storage and queue consumer. Failures propagate to the CLI."""
from dataclasses import asdict
from importlib.resources import files
import json
from queue import Empty
from threading import Thread, Event
from time import monotonic


class PostgresSink:
    def __init__(self, dsn):
        from psycopg2.pool import ThreadedConnectionPool
        self.pool = ThreadedConnectionPool(1, 2, dsn, connect_timeout=5)

    def initialize(self):
        connection = self.pool.getconn()
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(files("db").joinpath("schema.sql").read_text(encoding="utf-8"))
        finally:
            self.pool.putconn(connection)

    def write(self, records):
        from psycopg2.extras import Json, execute_values
        if not records:
            return
        rows = [(p.timestamp, p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port,
                 p.length, p.payload, p.tcp_flags, Json([asdict(a) for a in p.alerts])) for p in records]
        connection = self.pool.getconn()
        try:
            with connection:
                with connection.cursor() as cursor:
                    execute_values(cursor, """INSERT INTO packets
                        (captured_at, src_ip, dst_ip, protocol, src_port, dst_port,
                         wire_length, payload, tcp_flags, alerts) VALUES %s""", rows)
        finally:
            self.pool.putconn(connection)

    def close(self):
        self.pool.closeall()


class JsonSink:
    def __init__(self, stream):
        self.stream = stream

    def write(self, records):
        for record in records:
            self.stream.write(json.dumps(record.to_dict()) + "\n")
        self.stream.flush()

    def close(self):
        self.stream.flush()


class BatchWorker(Thread):
    def __init__(self, queue, detector, sink, batch_size=100, flush_interval=1.0):
        super().__init__(name="packet-storage", daemon=True)
        if batch_size <= 0 or flush_interval <= 0:
            raise ValueError("Batch size and flush interval must be positive")
        self.queue, self.detector, self.sink = queue, detector, sink
        self.batch_size, self.flush_interval = batch_size, flush_interval
        self.stopping = Event()
        self.failed = Event()
        self.error = None
        self.written = self.alert_count = 0

    def run(self):
        batch = []
        deadline = monotonic() + self.flush_interval
        try:
            while not self.stopping.is_set() or not self.queue.empty():
                try:
                    record = self.queue.get(timeout=min(0.1, max(0, deadline - monotonic())))
                    self.alert_count += len(self.detector.inspect(record))
                    batch.append(record)
                except Empty:
                    pass
                if len(batch) >= self.batch_size or monotonic() >= deadline:
                    if batch:
                        self.sink.write(batch)
                        self.written += len(batch)
                        for _ in batch:
                            self.queue.task_done()
                        batch.clear()
                    deadline = monotonic() + self.flush_interval
            if batch:
                self.sink.write(batch)
                self.written += len(batch)
                for _ in batch:
                    self.queue.task_done()
        except Exception as error:
            self.error = error
            self.failed.set()
