# Network-Scanner-and-Analyzer

packet-inspector/
├── config/
│   ├── settings.py           # Database credentials, batch sizes, interface settings
│   └── rules.yaml            # Detection rules (e.g., flagged ports, signatures)
├── src/
│   ├── __init__.py
│   ├── capture.py            # Scapy sniffer & queue producer
│   ├── database.py           # PostgreSQL connection pool & batch insertion worker
│   ├── detector.py           # Signature & anomaly detection engine
│   ├── models.py             # Data classes / Data Transfer Objects (DTOs)
│   └── utils.py              # Helper functions (IP formatting, hex dumping)
├── db/
│   └── schema.sql            # PostgreSQL table definitions and indexes
├── tests/
│   ├── test_capture.py
│   └── test_detector.py
├── .env.example              # Environment variable template
├── main.py                   # Application entry point & thread orchestration
├── requirements.txt          # Python dependencies (scapy, psycopg2-binary, pyyaml)
└── README.md                 # Architecture diagram, setup guide, and benchmarks