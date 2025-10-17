import random
import time
from utils import log_message, run_command


def regular_traffic_window(target, log_file=None, running=None):
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
        sleep_time = random.uniform(0, 1.0)
        log_message("REGULAR: sleeping for {:.2f}s".format(sleep_time), log_file)
        time.sleep(sleep_time)

    log_message("<<< Ending REGULAR traffic window", log_file)


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
