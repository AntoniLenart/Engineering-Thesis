#!/usr/bin/env python3
"""
h1_traffic_generator.py - Traffic Generator and Attack Simulator
Run this on h1 to generate regular traffic and SYN flood attacks
Compatible with Python 3.5.2

Usage:
    python3 h1_traffic_generator.py --target 10.0.0.2 --duration 3600
    python3 h1_traffic_generator.py --target 10.0.0.2 --duration 1800 --log traffic_log.txt
Options:
    --target <IP>        Target IP address (h2)
    --duration <secs>   Total duration in seconds (default: 3600 = 1 hour)
    --log <filename>    Log file name (default: traffic_simulation.log)
    --attack-ratio <float> Attack probability (default: 0.1 = 10%)
    --min-sleep <float> Minimum sleep time between windows in seconds (default: 0.5)
    --max-sleep <float> Maximum sleep time between windows in seconds (default: 3.0)
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


def run_command(cmd, timeout=30, log_file=None):
    """Run a command with timeout and log stdout/stderr and returncode."""
    log_message("CMD START: {}".format(cmd), log_file)
    start_ts = datetime.now()
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            out, err = proc.communicate(timeout=timeout)
            rc = proc.returncode
            end_ts = datetime.now()
            # decode safely
            try:
                out_s = out.decode('utf-8', errors='replace').strip()
            except Exception:
                out_s = "<binary or undecodable stdout>"
            try:
                err_s = err.decode('utf-8', errors='replace').strip()
            except Exception:
                err_s = "<binary or undecodable stderr>"

            if out_s:
                log_message("CMD STDOUT: {}".format(out_s), log_file)
            if err_s:
                log_message("CMD STDERR: {}".format(err_s), log_file)

            log_message("CMD END: rc={} duration={}s".format(
                rc, (end_ts - start_ts).total_seconds()), log_file)
            return rc == 0

        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            log_message("CMD TIMEOUT: killed after {}s: {}".format(timeout, cmd), log_file)
            try:
                err_s = err.decode('utf-8', errors='replace').strip()
                if err_s:
                    log_message("CMD STDERR AFTER KILL: {}".format(err_s), log_file)
            except Exception:
                pass
            return False

    except Exception as e:
        log_message("Error running command '{}': {}".format(cmd, e), log_file)
        return False


def ping_traffic(target, duration=None, log_file=None):
    """Generate ICMP ping traffic"""
    if duration:
        count = random.randint(5, 20)
        interval = random.uniform(0.2, 1.0)
        cmd = "ping -c {0} -i {1:.2f} {2}".format(count, interval, target)
    else:
        count = random.randint(3, 10)
        cmd = "ping -c {0} {1}".format(count, target)

    log_message("Running ping: {}".format(cmd), log_file)
    return run_command(cmd, timeout=30, log_file=log_file)


def iperf_tcp_traffic(target, duration=None, log_file=None):
    """Generate TCP traffic using iperf"""
    if duration is None:
        duration = random.randint(5, 20)

    bandwidth = random.choice(["1M", "5M", "10M", "20M"])
    cmd = "iperf -c {0} -t {1} -b {2}".format(target, duration, bandwidth)

    log_message("Running iperf TCP: duration={0}s, bandwidth={1}".format(duration, bandwidth), log_file)
    return run_command(cmd, timeout=duration + 10, log_file=log_file)


def iperf_udp_traffic(target, duration=None, log_file=None):
    """Generate UDP traffic using iperf"""
    if duration is None:
        duration = random.randint(5, 15)

    bandwidth = random.choice(["1M", "5M", "10M"])
    cmd = "iperf -c {0} -u -t {1} -b {2} -p 5002".format(target, duration, bandwidth)

    log_message("Running iperf UDP: duration={0}s, bandwidth={1}".format(duration, bandwidth), log_file)
    return run_command(cmd, timeout=duration + 10, log_file=log_file)


def http_requests(target, count=None, log_file=None):
    """Generate HTTP requests"""
    if count is None:
        count = random.randint(5, 30)

    log_message("Sending {0} HTTP requests".format(count), log_file)

    for i in range(count):
        if not running:
            break
        cmd = "curl -s -o /dev/null http://{0}/".format(target)
        log_message("HTTP request [{}/{}]: {}".format(i+1, count, cmd), log_file)
        run_command(cmd, timeout=5, log_file=log_file)
        time.sleep(random.uniform(0.1, 0.5))

    return True


def hping3_traffic(target, log_file=None):
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
    log_message("Running hping3: {0}".format(cmd), log_file)
    return run_command(cmd, timeout=30, log_file=log_file)


def tcp_syn_flood(target, duration=None):
    """Randomized TCP SYN flood across multiple ports and parallel processes.

    All parameters are randomized if not provided:
      - duration: seconds to run (random 10..60 by default)
      - ports: randomly sampled from a common port pool (1..6 ports)
      - concurrency: number of parallel hping3 processes (1..num_ports*2)
      - rand_src: randomly choose whether to spoof source (--rand-source)
    Returns True on completion (best-effort).
    """
    if duration is None:
        duration = random.randint(10, 60)

    port_pool = [80, 443, 22, 8080, 53, 25, 110, 123, 21, 445, 3389, 5900]

    num_ports = random.randint(1, min(6, len(port_pool)))
    ports = random.sample(port_pool, num_ports)
    concurrency = random.randint(1, max(1, num_ports * 2))
    rand_src = random.choice([False, True])
    rand_src_flag = "--rand-source" if rand_src else ""

    log_message("!!! ATTACK (randomized): duration={0}s ports={1} concurrency={2} rand_src={3}"
                .format(duration, ports, concurrency, rand_src))

    procs = []
    try:
        start_time = time.time()
        # Launch `concurrency` flood processes in parallel. Each process picks a random port
        for i in range(concurrency):
            # choose a port for this process at random from chosen set
            port = str(random.choice(ports))

            # build hping3 command; timeout wrapper ensures process ends after duration
            cmd = "timeout {dur} hping3 -S --flood -p {port} {rand} {target}".format(
                dur=duration, port=port, rand=rand_src_flag, target=target)

            log_message("Launching flood process: {0}".format(cmd))
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append(p)

        # Wait for duration (or until processes exit). Poll so we can be responsive.
        while time.time() - start_time < duration:
            if all(p.poll() is not None for p in procs):
                # all processes finished early
                break
            time.sleep(0.2)

    except Exception as e:
        log_message("Error during randomized SYN flood: {0}".format(e))

    finally:
        # Ensure all processes are terminated/cleaned up
        for p in procs:
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=1)
                    except Exception:
                        p.kill()
            except Exception:
                pass

    log_message("!!! ATTACK COMPLETE (randomized): duration={0}s ports={1} concurrency={2} rand_src={3}"
                .format(duration, ports, concurrency, rand_src))
    return True


def regular_traffic_window(target, log_file=None):
    """Execute a window of regular traffic with per-operation logging"""
    log_message(">>> Starting REGULAR traffic window", log_file)

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
        traffic_func = random.choice(traffic_functions)

        try:
            # call with log_file so the function logs details
            log_message("REGULAR: selected traffic function: {}".format(traffic_func.__name__), log_file)
            traffic_func(target, log_file=log_file)
        except Exception as e:
            log_message("Error in traffic generation: {0}".format(e), log_file)

        # Random sleep between operations and log it
        sleep_time = random.uniform(0.5, 3.0)
        log_message("REGULAR: sleeping for {:.2f}s".format(sleep_time), log_file)
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
    parser.add_argument('--target',
                        required=True,
                        help='Target IP address (h2)')
    parser.add_argument('--duration',
                        type=int,
                        default=3600,
                        help='Total duration in seconds (default: 3600 = 1 hour)')
    parser.add_argument('--log',
                        default='traffic_simulation.log',
                        help='Log file name (default: traffic_simulation.log)')
    parser.add_argument('--attack-ratio',
                        type=float,
                        default=0.1,
                        help='Attack probability (default: 0.1 = 10%%)')
    parser.add_argument('--min-sleep',
                        type=float,
                        default=0.5,
                        help='Minimum sleep time between windows in seconds (default: 0.5)')
    parser.add_argument('--max-sleep',
                        type=float,
                        default=3.0,
                        help='Maximum sleep time between windows in seconds (default: 3.0)')

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
    log_message("Min Sleep: {0:.2f}s, Max Sleep: {1:.2f}s".format(
        args.min_sleep, args.max_sleep), args.log)
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
                time.sleep(random.uniform(args.min_sleep, args.max_sleep))

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
