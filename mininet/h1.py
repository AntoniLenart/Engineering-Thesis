#!/usr/bin/env python3
"""
h1_traffic_generator.py - Traffic Generator and Attack Simulator
Run this on h1 to generate regular traffic and SYN flood attacks
Compatible with Python 3.5.2

Usage:
    python3 h1_traffic_generator.py --target 10.0.0.2 --duration 3600
    python3 h1_traffic_generator.py --target 10.0.0.2 --duration 1800 --log traffic_log.txt
"""

import subprocess
import random
import time
import argparse
import signal
import sys
from datetime import datetime

# Global flag for graceful shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n[*] Stopping traffic generation...")
    running = False


def log_message(msg, log_file=None):
    """Print and optionally write timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = "[{0}] {1}".format(timestamp, msg)
    print(log_line)

    if log_file:
        with open(log_file, 'a') as f:
            f.write(log_line + "\n")


def run_command(cmd, timeout=30):
    """Run a command with timeout"""
    try:
        # Python 3.5 doesn't have timeout parameter in subprocess.run
        # Use Popen with communicate instead
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            proc.communicate(timeout=timeout)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return False

    except Exception as e:
        print("Error running command: {0}".format(e))
        return False


def ping_traffic(target, duration=None):
    """Generate ICMP ping traffic"""
    if duration:
        cmd = "ping -c {0} -i {1:.2f} {2}".format(
            random.randint(5, 20),
            random.uniform(0.2, 1.0),
            target
        )
    else:
        count = random.randint(3, 10)
        cmd = "ping -c {0} {1}".format(count, target)

    log_message("Running ping: {0}".format(cmd))
    return run_command(cmd, timeout=30)


def iperf_tcp_traffic(target, duration=None):
    """Generate TCP traffic using iperf"""
    if duration is None:
        duration = random.randint(5, 20)

    bandwidth = random.choice(["1M", "5M", "10M", "20M"])
    cmd = "iperf -c {0} -t {1} -b {2}".format(target, duration, bandwidth)

    log_message("Running iperf TCP: duration={0}s, bandwidth={1}".format(duration, bandwidth))
    return run_command(cmd, timeout=duration + 10)


def iperf_udp_traffic(target, duration=None):
    """Generate UDP traffic using iperf"""
    if duration is None:
        duration = random.randint(5, 15)

    bandwidth = random.choice(["1M", "5M", "10M"])
    cmd = "iperf -c {0} -u -t {1} -b {2} -p 5002".format(target, duration, bandwidth)

    log_message("Running iperf UDP: duration={0}s, bandwidth={1}".format(duration, bandwidth))
    return run_command(cmd, timeout=duration + 10)


def http_requests(target, count=None):
    """Generate HTTP requests"""
    if count is None:
        count = random.randint(5, 30)

    log_message("Sending {0} HTTP requests".format(count))

    for i in range(count):
        if not running:
            break
        cmd = "curl -s -o /dev/null http://{0}/".format(target)
        run_command(cmd, timeout=5)
        time.sleep(random.uniform(0.1, 0.5))

    return True


def hping3_traffic(target):
    """Generate various traffic patterns using hping3"""
    patterns = [
        "hping3 -c {0} -i u{1} {2}".format(
            random.randint(10, 50),
            random.randint(1000, 10000),
            target
        ),
        "hping3 -c {0} --udp -p 80 {1}".format(random.randint(10, 30), target),
        "hping3 -c {0} -p 80 {1}".format(random.randint(10, 30), target)
    ]

    cmd = random.choice(patterns)
    log_message("Running hping3: {0}".format(cmd))
    return run_command(cmd, timeout=30)


def tcp_syn_flood(target, duration=None):
    """Generate TCP SYN flood attack"""
    if duration is None:
        duration = random.randint(10, 30)

    # Using hping3 for SYN flood
    # -S: SYN flag, --flood: send packets as fast as possible, -p: target port
    port = random.choice([80, 443, 22, 8080])

    log_message("!!! ATTACK: TCP SYN Flood to port {0} for {1}s".format(port, duration))

    cmd = "timeout {0} hping3 -S --flood -p {1} {2}".format(duration, port, target)
    return run_command(cmd, timeout=duration + 5)


def regular_traffic_window(target, log_file=None):
    """Execute a window of regular traffic"""
    log_message(">>> Starting REGULAR traffic window", log_file)

    # Random duration between 30 and 120 seconds
    window_duration = random.randint(30, 120)
    start_time = time.time()

    traffic_functions = [
        ping_traffic,
        iperf_tcp_traffic,
        iperf_udp_traffic,
        http_requests,
        hping3_traffic
    ]

    while (time.time() - start_time) < window_duration and running:
        # Pick random traffic type
        traffic_func = random.choice(traffic_functions)

        try:
            traffic_func(target)
        except Exception as e:
            log_message("Error in traffic generation: {0}".format(e), log_file)

        # Random sleep between operations
        sleep_time = random.uniform(1, 5)
        time.sleep(sleep_time)

    log_message("<<< Ending REGULAR traffic window", log_file)


def attack_window(target, log_file=None):
    """Execute a window of attack traffic"""
    log_message("!!! Starting ATTACK window (TCP SYN Flood)", log_file)

    # Attack duration between 20 and 60 seconds
    duration = random.randint(20, 60)

    try:
        tcp_syn_flood(target, duration)
    except Exception as e:
        log_message("Error in attack generation: {0}".format(e), log_file)

    log_message("!!! Ending ATTACK window", log_file)


def main():
    """Main traffic generation loop"""
    parser = argparse.ArgumentParser(description='H1 Traffic Generator with Attack Simulation')
    parser.add_argument('--target', required=True, help='Target IP address (h2)')
    parser.add_argument('--duration', type=int, default=3600,
                        help='Total duration in seconds (default: 3600 = 1 hour)')
    parser.add_argument('--log', default='traffic_simulation.log',
                        help='Log file name (default: traffic_simulation.log)')
    parser.add_argument('--attack-ratio', type=float, default=0.1,
                        help='Attack probability (default: 0.1 = 10%%)')

    args = parser.parse_args()

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Log simulation start
    start_time = datetime.now()
    log_message("=" * 70, args.log)
    log_message("TRAFFIC SIMULATION STARTED", args.log)
    log_message("Target: {0}".format(args.target), args.log)
    log_message("Duration: {0} seconds ({1:.2f} hours)".format(
        args.duration, args.duration / 3600.0), args.log)
    log_message("Attack Ratio: {0:.1f}%".format(args.attack_ratio * 100), args.log)
    log_message("Start Time: {0}".format(start_time.strftime('%Y-%m-%d %H:%M:%S')), args.log)
    log_message("=" * 70, args.log)

    # Main simulation loop
    end_time = time.time() + args.duration

    try:
        while time.time() < end_time and running:
            # Decide: regular traffic or attack (90% regular, 10% attack by default)
            if random.random() < args.attack_ratio:
                attack_window(args.target, args.log)
            else:
                regular_traffic_window(args.target, args.log)

            # Small pause between windows
            if running:
                time.sleep(random.uniform(2, 5))

    except KeyboardInterrupt:
        log_message("Simulation interrupted by user", args.log)

    # Log simulation end
    end_time_actual = datetime.now()
    elapsed = (end_time_actual - start_time).total_seconds()

    log_message("=" * 70, args.log)
    log_message("TRAFFIC SIMULATION ENDED", args.log)
    log_message("End Time: {0}".format(end_time_actual.strftime('%Y-%m-%d %H:%M:%S')), args.log)
    log_message("Total Duration: {0:.2f} seconds ({1:.2f} hours)".format(
        elapsed, elapsed / 3600.0), args.log)
    log_message("=" * 70, args.log)


if __name__ == "__main__":
    main()
