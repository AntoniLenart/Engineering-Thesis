#!/usr/bin/env python3
"""
utils.py - shared helpers for logging and running commands
"""

from datetime import datetime
import subprocess


def log_message(msg, log_file=None):
    """Print and optionally write timestamped log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = "[{0}] {1}".format(timestamp, msg)
    print(log_line)

    if log_file:
        try:
            with open(log_file, 'a') as f:
                f.write(log_line + "\n")
        except Exception as e:
            # If logging to file fails, still print an informative message
            print("[{0}] Failed to write to log file {1}: {2}".format(timestamp, log_file, e))


def run_command(cmd, timeout=30, log_file=None):
    """Run a command with timeout and log stdout/stderr and return boolean success."""
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
