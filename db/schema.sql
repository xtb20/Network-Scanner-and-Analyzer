CREATE TABLE IF NOT EXISTS packets (
    id BIGSERIAL PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER CHECK (src_port BETWEEN 0 AND 65535),
    dst_port INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
    wire_length INTEGER NOT NULL CHECK (wire_length >= 0),
    payload BYTEA NOT NULL,
    tcp_flags INTEGER NOT NULL,
    alerts JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS packets_captured_at_idx ON packets (captured_at);
CREATE INDEX IF NOT EXISTS packets_src_ip_idx ON packets (src_ip, captured_at);
CREATE INDEX IF NOT EXISTS packets_alerts_idx ON packets USING GIN (alerts);
