import csv
from os.path import join, exists
from os import makedirs
from time import time
from typing import Any


OUTPUT_DIR: str = "telemetry"

# CSV file paths
PORT_STATS_FILE: str = join(OUTPUT_DIR, "port_stats.csv")
PORT_DESC_FILE: str = join(OUTPUT_DIR, "port_desc.csv")
FLOW_STATS_FILE: str = join(OUTPUT_DIR, "flow_stats.csv")
TABLE_STATS_FILE: str = join(OUTPUT_DIR, "table_stats.csv")
EVENTS_FILE: str = join(OUTPUT_DIR, "events.csv")

makedirs(OUTPUT_DIR, exist_ok=True)


def init_csv(file: str, header: list[str]) -> None:
    """Initialize CSV with header if it doesn't exist."""
    if not exists(file):
        with open(file, "w", newline="") as f:
            csv.writer(f).writerow(header)


def initialize_all_csv_files() -> None:
    """Initialize all CSV files with proper headers."""
    init_csv(PORT_STATS_FILE, [
        "ts_utc", "switch_dpid", "port_no",
        "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
        "rx_errors", "tx_errors", "rx_frame_err", "rx_over_err",
        "rx_crc_err", "collisions", "duration_sec", "duration_nsec"
    ])

    init_csv(PORT_DESC_FILE, [
        "ts_utc", "switch_dpid", "port_no", "hw_addr", "name",
        "config", "state", "curr", "advertised", "supported",
        "peer", "curr_speed", "max_speed"
    ])

    init_csv(FLOW_STATS_FILE, [
        "ts_utc", "switch_dpid", "table_id", "duration_sec", "duration_nsec",
        "idle_timeout", "hard_timeout", "flags", "cookie",
        "packet_count", "byte_count", "priority", "match", "instructions", "length"
    ])

    init_csv(TABLE_STATS_FILE, [
        "ts_utc", "switch_dpid", "table_id",
        "active_count", "lookup_count", "matched_count"
    ])

    init_csv(EVENTS_FILE, [
        "ts_utc", "switch_dpid", "event_type", "details"
    ])


def write_port_stats(dpid: int, stats: list[Any]) -> None:
    """Write port statistics to CSV."""
    ts: float = time()
    with open(PORT_STATS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        for stat in stats:
            writer.writerow([
                ts, dpid, stat.port_no,
                stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes,
                stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err,
                stat.rx_crc_err, stat.collisions,
                getattr(stat, "duration_sec", ""), getattr(stat, "duration_nsec", "")
            ])


def write_port_desc(dpid: int, ports: list[Any]) -> None:
    """Write port description to CSV."""
    ts: float = time()
    with open(PORT_DESC_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        for p in ports:
            writer.writerow([
                ts, dpid, p.port_no, p.hw_addr, p.name,
                p.config, p.state, p.curr, p.advertised, p.supported,
                p.peer, p.curr_speed, p.max_speed
            ])


def write_flow_stats(dpid: int, stats: list[Any]) -> None:
    """Write flow statistics to CSV."""
    ts: float = time()
    with open(FLOW_STATS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        for stat in stats:
            writer.writerow([
                ts, dpid, stat.table_id,
                getattr(stat, "duration_sec", ""), getattr(stat, "duration_nsec", ""),
                stat.idle_timeout, stat.hard_timeout, stat.flags, stat.cookie,
                stat.packet_count, stat.byte_count, stat.priority,
                str(stat.match), str(stat.instructions), stat.length
            ])


def write_table_stats(dpid: int, stats: list[Any]) -> None:
    """Write table statistics to CSV."""
    ts: float = time()
    with open(TABLE_STATS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        for stat in stats:
            writer.writerow([
                ts, dpid, stat.table_id,
                stat.active_count, stat.lookup_count, stat.matched_count
            ])


def log_event(dpid: int, event_type: str, details: str) -> None:
    """Log an event to the events CSV file."""
    ts: float = time()
    with open(EVENTS_FILE, "a", newline="") as f:
        csv.writer(f).writerow([ts, dpid, event_type, details])


# Initialize all CSV files when module is imported
initialize_all_csv_files()
