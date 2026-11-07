"""Log parser: reads exported security events and normalizes them.

Reads JSON or CSV exports, unifies field names, validates the required
fields, and reports records that cannot be used. The source file is
never modified.
"""
import csv
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("log_parser")

# Field names differ between exports. Keys are compared after lower-casing
# and removing underscores and spaces.
FIELD_ALIASES = {
    "timestamp": ("timestamp", "timecreated", "time", "date"),
    "event_id": ("eventid", "id"),
    "computer": ("computer", "machinename", "host", "hostname"),
    "provider": ("provider", "providername"),
    "log_name": ("logname", "channel"),
    "user": ("user", "username", "targetusername", "account"),
    "logon_type": ("logontype",),
    "status": ("status",),
    "sub_status": ("substatus",),
    "source_ip": ("sourceip", "ipaddress", "ip"),
}

# A usable record needs a valid timestamp and event id. These fields are
# expected on most events, so their absence is reported, not rejected.
CORE_FIELDS = ("computer", "log_name", "user")


class LogParserError(Exception):
    """Raised when a whole file cannot be read."""


@dataclass
class Event:
    timestamp: datetime
    event_id: int
    computer: Optional[str] = None
    provider: Optional[str] = None
    log_name: Optional[str] = None
    user: Optional[str] = None
    logon_type: Optional[int] = None
    status: Optional[str] = None
    sub_status: Optional[str] = None
    source_ip: Optional[str] = None
    missing_fields: tuple = ()
    record_number: int = 0

    def key(self):
        """Identity used to detect exact duplicates."""
        return (self.timestamp, self.event_id, self.computer, self.user,
                self.logon_type, self.status, self.sub_status, self.source_ip)


@dataclass
class ParseResult:
    source_file: str
    total_records: int = 0
    events: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    duplicates_removed: int = 0
    naive_timestamps: int = 0


def load_raw_records(path):
    """Read a JSON or CSV file and return a list of raw records."""
    path = Path(path)
    if not path.is_file():
        raise LogParserError("File not found: " + str(path))
    suffix = path.suffix.lower()
    if suffix not in (".json", ".csv"):
        raise LogParserError("Unsupported file type: " + (suffix or "none"))
    try:
        if suffix == ".json":
            with path.open("r", encoding="utf-8-sig") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                data = [data]
            if not isinstance(data, list):
                raise LogParserError("JSON root must be a list or an object")
            return data
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LogParserError("Cannot read " + str(path) + ": " + str(exc)) from exc


def parse_timestamp(value):
    """Return (aware datetime, assumed_utc). Raises ValueError if invalid."""
    parsed = datetime.fromisoformat(str(value).strip())
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc), True
    return parsed, False


def normalize_record(record):
    """Return (Event, assumed_utc) or raise ValueError with the reason."""
    if not isinstance(record, dict):
        raise ValueError("record is not an object")
    lowered = {}
    for key, value in record.items():
        lowered[str(key).lower().replace("_", "").replace(" ", "")] = value

    def pick(name):
        for alias in FIELD_ALIASES[name]:
            value = lowered.get(alias)
            if value is not None and str(value).strip() != "":
                return str(value).strip()
        return None

    raw_time = pick("timestamp")
    if raw_time is None:
        raise ValueError("missing timestamp")
    try:
        timestamp, assumed_utc = parse_timestamp(raw_time)
    except ValueError:
        raise ValueError("invalid timestamp: " + raw_time) from None

    raw_id = pick("event_id")
    if raw_id is None:
        raise ValueError("missing event_id")
    try:
        event_id = int(raw_id)
    except ValueError:
        raise ValueError("invalid event_id: " + raw_id) from None

    raw_logon = pick("logon_type")
    try:
        logon_type = int(raw_logon) if raw_logon is not None else None
    except ValueError:
        logon_type = None

    event = Event(
        timestamp=timestamp,
        event_id=event_id,
        computer=pick("computer"),
        provider=pick("provider"),
        log_name=pick("log_name"),
        user=pick("user"),
        logon_type=logon_type,
        status=pick("status"),
        sub_status=pick("sub_status"),
        source_ip=pick("source_ip"),
    )
    event.missing_fields = tuple(n for n in CORE_FIELDS if getattr(event, n) is None)
    return event, assumed_utc


def parse_file(path):
    """Parse a log export and return a ParseResult. The file is not modified."""
    raw_records = load_raw_records(path)
    result = ParseResult(source_file=str(path), total_records=len(raw_records))
    seen = set()
    for number, record in enumerate(raw_records, start=1):
        try:
            event, assumed_utc = normalize_record(record)
        except ValueError as exc:
            result.rejected.append({"record_number": number, "reason": str(exc)})
            logger.warning("Record %d rejected: %s", number, exc)
            continue
        if assumed_utc:
            result.naive_timestamps += 1
        identity = event.key()
        if identity in seen:
            result.duplicates_removed += 1
            logger.info("Record %d is an exact duplicate and was skipped", number)
            continue
        seen.add(identity)
        event.record_number = number
        result.events.append(event)
    return result


def summary(result):
    """Return a small dictionary describing what was processed."""
    return {
        "total_records": result.total_records,
        "usable_events": len(result.events),
        "rejected": len(result.rejected),
        "duplicates_removed": result.duplicates_removed,
        "naive_timestamps_assumed_utc": result.naive_timestamps,
        "events_with_missing_core_fields": sum(1 for e in result.events if e.missing_fields),
    }
