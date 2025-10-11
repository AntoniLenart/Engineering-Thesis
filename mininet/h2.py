#!/usr/bin/env python3
"""
h2_server.py - Server Simulator Script
Run this on h2 to set up all server services
Compatible with Python 3.5.2
"""

import subprocess
import signal
import sys
import time
from datetime import datetime

# Global list to track running processes
processes = []


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[*] Shutting down servers...")
    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()
    sys.exit(0)


def log_message(msg):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("[{0}] {1}".format(timestamp, msg))


def start_http_server():
    """Start simple HTTP server on port 80"""
    log_message("Starting HTTP server on port 80...")
    try:
        proc = subprocess.Popen(
            ["python3", "-m", "http.server", "80"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(proc)
        log_message("HTTP server started successfully")
        return proc
    except Exception as e:
        log_message("Error starting HTTP server: {0}".format(e))
        return None


def start_iperf_server():
    """Start iperf server"""
    log_message("Starting iperf server on port 5001...")
    try:
        proc = subprocess.Popen(
            ["iperf", "-s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(proc)
        log_message("iperf server started successfully")
        return proc
    except Exception as e:
        log_message("Error starting iperf server: {0}".format(e))
        return None


def start_iperf_udp_server():
    """Start iperf UDP server on different port"""
    log_message("Starting iperf UDP server on port 5002...")
    try:
        proc = subprocess.Popen(
            ["iperf", "-s", "-u", "-p", "5002"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        processes.append(proc)
        log_message("iperf UDP server started successfully")
        return proc
    except Exception as e:
        log_message("Error starting iperf UDP server: {0}".format(e))
        return None


def main():
    """Main server setup function"""
    signal.signal(signal.SIGINT, signal_handler)

    log_message("=" * 60)
    log_message("H2 SERVER SIMULATOR - Starting all services")
    log_message("=" * 60)

    # Start all servers
    start_http_server()
    time.sleep(1)

    start_iperf_server()
    time.sleep(1)

    start_iperf_udp_server()
    time.sleep(1)

    log_message("=" * 60)
    log_message("All servers running. Press Ctrl+C to stop.")
    log_message("=" * 60)

    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
