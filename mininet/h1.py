#!/usr/bin/env python3
"""
h1_traffic_generator.py - Traffic Generator and Attack Simulator
Run this on h1 to generate regular traffic and SYN flood attacks
Compatible with Python 3.5+

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

import argparse
import signal
import time
import random
from datetime import datetime

from utils import log_message
from regular_traffic import regular_traffic_window
from attack_traffic import attack_window

# Global flag for graceful shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print("\n[*] Stopping traffic generation...")
    running = False


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
                        default=0,
                        help='Minimum sleep time between windows in seconds (default: 0)')
    parser.add_argument('--max-sleep',
                        type=float,
                        default=1,
                        help='Maximum sleep time between windows in seconds (default: 1.0)')

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
            # Decide: regular traffic or attack
            if random.random() < args.attack_ratio:
                attack_window(args.target, args.log, running)
            else:
                regular_traffic_window(args.target, args.log, running)

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
