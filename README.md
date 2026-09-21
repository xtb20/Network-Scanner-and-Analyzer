# Network Scanner and Analyzer

A passive packet inspector built with Scapy. Capture live traffic or replay a
PCAP/PCAPNG file, detect suspicious patterns, and write JSON lines or PostgreSQL
records. It observes traffic; it does not probe hosts or perform active scans.

## Architecture

'''text
Live Scapy capture -- nonblocking enqueue --+
                                            +-- bounded queue -- detector -- batch writer
Offline PCAP reader -- blocking enqueue ----+                                 |
                                                                    JSONL or PostgreSQL
'''
- `src/capture.py`: IPv4/IPv6 metadata, TCP/UDP payload extraction, bounded capture queue.
- `src/models.py`: shared records, UTC timestamps, and hex JSON payloads.
- `src/detector.py`: flagged ports, text/binary signatures, sliding-window SYN scan heuristic.
- `src/database.py`: connection pool, transactional inserts, timed batch flushing, failure reporting.
- `config/settings.py`, `config/rules.yaml`: environment configuration and validated detection rules.
- `db/schema.sql`: packet table with address, timestamp, and JSON alert indexes.
- `main.py`: CLI, offline replay, live capture, and shutdown orchestration.

## Install

Python 3.11 or newer is required. With uv:

```powershell
uv sync
uv run network-scanner-and-analyzer --help
```

Alternatively, in an activated virtual environment:

```powershell
python -m pip install -e .
network-scanner-and-analyzer --help
```

`python main.py` also works from this repository after installing dependencies.
Live Windows capture needs Npcap and suitable capture permissions. On Linux/macOS,
live capture requires appropriate permissions; BPF filters require libpcap.
Offline replay needs neither capture privileges nor Npcap/libpcap.

## Analyze a capture

```powershell
uv run network-scanner-and-analyzer --pcap traffic.pcap --output packets.jsonl
uv run network-scanner-and-analyzer --pcap traffic.pcap --count 100
```

Without `--output` or `--postgres`, JSON lines go to stdout. Status messages go to
stderr. `--output` replaces an existing output file. `--count` limits input
packets, including non-IP packets that are subsequently ignored; zero is unlimited.
Offline replay waits for queue space instead of dropping records.

## Capture live traffic

```powershell
uv run network-scanner-and-analyzer --list-interfaces
uv run network-scanner-and-analyzer --interface "Ethernet" --duration 30 --filter "tcp or udp" --output packets.jsonl
```

Use an interface name returned by `--list-interfaces`. Omit `--duration` and
`--count` for continuous capture. Ctrl+C stops capture and drains accepted packets
through the writer. When storage cannot keep pace, live capture drops new packets
instead of growing memory without limit. The final status reports saved packets,
alerts, application queue drops, ignored non-IP packets, and malformed packets.
It does not report operating-system capture drops.

## PostgreSQL

Create a database and a role with permission to create its tables, then set a
connection URL. The application creates tables, not databases or roles.

```powershell
$env:DATABASE_URL = 'postgresql://inspector:change-me@localhost:5432/packet_inspector'
uv run network-scanner-and-analyzer --init-db
uv run network-scanner-and-analyzer --pcap traffic.pcap --postgres
```

Initialization is explicit and safe to repeat. Each batch commits atomically;
failed batches roll back and cause a nonzero exit. Failed writes are not retried
and pending records are not durably spooled. Replaying a capture again inserts
additional rows. JSON write failures can leave a partial batch on disk.

```sql
SELECT captured_at, src_ip, dst_ip, dst_port, alerts
FROM packets
WHERE alerts <> '[]'::jsonb
ORDER BY captured_at DESC
LIMIT 100;
```

## Settings and rules

`.env.example` is a template. Set environment variables in your shell or process
manager; the application does not automatically load `.env` files.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | unset | Connection URL; required only for database commands |
| `CAPTURE_INTERFACE` | Scapy default | Interface unless overridden on the CLI |
| `BATCH_SIZE` | 100 | Maximum records per write |
| `QUEUE_SIZE` | 10000 | Maximum pending packets |
| `FLUSH_INTERVAL` | 1.0 | Seconds before flushing a partial batch |
| `PAYLOAD_LIMIT` | 2048 | Maximum application payload bytes retained and inspected per packet |

Numeric settings must be positive and finite. Supply `--rules path/to/rules.yaml`
to replace the bundled rules. Example:

```yaml
flagged_ports: [23, 2323, 3389]
signatures:
  - name: test-marker
    text: PACKET_INSPECTOR_TEST
    case_sensitive: true
  - name: binary-marker
    hex: "de ad be ef"
port_scan:
  window_seconds: 10
  unique_ports: 20
  max_sources: 10000
```

Flagged ports match either endpoint. Signatures match literal bytes, with optional
ASCII case folding, and need exactly one of `text` or `hex`. The scan heuristic
counts distinct destination ports in TCP SYN packets without ACK for each
source/destination pair. It alerts when the threshold is reached, then suppresses
repeats until the active count falls below the threshold. `max_sources` caps
tracked pairs, evicting the least recently observed pair.

Time windows use capture timestamps. Packets older than the latest timestamp minus
the window still receive signature checks but do not contribute to scan detection.
Detection state is bounded by tracked pairs and the configured port threshold.

These are indicators, not determinations of malicious activity. Encrypted payloads,
TCP stream reconstruction, IP fragment reassembly, and cross-packet signatures
are outside this implementation. Payload beyond `PAYLOAD_LIMIT` is not inspected.
Captured payload bytes are stored in output records; choose output locations and
retention appropriate for the traffic being observed.

## Tests and performance checks

```powershell
uv run python -m unittest discover -s tests -v
uv build
```

Tests construct local packets and replay a temporary PCAP through the CLI. They
cover IPv4/IPv6 parsing, payload limits, queue pressure, signatures, scan expiry,
bounded detection state, batch flushing, worker failures, and PostgreSQL transaction
handling with mocks. They do not require network capture or a running database.
Validate live capture and PostgreSQL against your deployment separately.

To measure offline throughput on your own capture in PowerShell:

```powershell
Measure-Command { uv run network-scanner-and-analyzer --pcap traffic.pcap --output benchmark.jsonl }
```

Divide the reported saved packet count by elapsed seconds. Compare batch sizes
and payload limits using the same capture and output sink. No throughput claim is
made: disk speed, database latency, packet sizes, and rule counts affect results.
