"""Environment configuration. Existing environment variables are authoritative."""
import math
import os
from dataclasses import dataclass


def positive_number(name, default, cast=int):
    value = cast(os.environ.get(name, default))
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str | None = None
    interface: str | None = None
    batch_size: int = 100
    queue_size: int = 10000
    flush_interval: float = 1.0
    payload_limit: int = 2048

    @classmethod
    def from_env(cls):
        return cls(
            database_url=os.environ.get("DATABASE_URL") or None,
            interface=os.environ.get("CAPTURE_INTERFACE") or None,
            batch_size=positive_number("BATCH_SIZE", 100),
            queue_size=positive_number("QUEUE_SIZE", 10000),
            flush_interval=positive_number("FLUSH_INTERVAL", 1.0, float),
            payload_limit=positive_number("PAYLOAD_LIMIT", 2048),
        )
