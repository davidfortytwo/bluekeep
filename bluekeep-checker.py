#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3

# Distinct outcomes. The important property is that UNREACHABLE is never
# conflated with a negative result: a host that did not answer is not evidence
# of anything about its patch status.
VULNERABLE = "VULNERABLE"
PATCHED = "PATCHED"
UNREACHABLE = "UNREACHABLE"
ERROR = "ERROR"


def check_bluekeep_vuln(target_ip):
    """Probe a single target.

    Returns a (status, message) tuple. status is one of VULNERABLE, PATCHED,
    UNREACHABLE or ERROR.
    """
    sock = None
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((target_ip, 3389))
        except socket.timeout:
            # Connection timed out: the host did not answer.
            return UNREACHABLE, "[?] %s is UNREACHABLE (connection timed out); patch status unknown" % target_ip
        except socket.gaierror as e:
            # Name resolution failure, not a patch signal.
            return UNREACHABLE, "[?] %s is UNREACHABLE (%s); patch status unknown" % (target_ip, e)
        except OSError as e:
            # Connection refused / route unreachable / reset. Also not a patch
            # signal: a patched-but-RDP-enabled host and a host with RDP off
            # look identical here, and a filtered port looks the same again.
            return UNREACHABLE, "[?] %s is UNREACHABLE (%s); patch status unknown" % (target_ip, e)

        try:
            pre_auth_pkt = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            sock.send(pre_auth_pkt)
            data = sock.recv(1024)
        except socket.timeout:
            # TCP connected but no RDP negotiation response within TIMEOUT.
            return UNREACHABLE, "[?] %s accepted TCP/3389 but sent no RDP response; patch status unknown" % target_ip
        except OSError as e:
            return ERROR, "[!] %s probe failed after connecting (%s)" % (target_ip, e)

        if b"\x03\x00\x00\x0c" in data:
            return VULNERABLE, "[+] %s is likely VULNERABLE to BlueKeep!" % target_ip
        return PATCHED, "[-] %s is likely patched :(" % target_ip
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def scan_ips(targets):
    """Scan every target and print one line each.

    Returns a dict of status -> count so callers (and the exit code below) can
    tell "nothing found" apart from "nothing was actually tested".
    """
    counts = {VULNERABLE: 0, PATCHED: 0, UNREACHABLE: 0, ERROR: 0}
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_bluekeep_vuln, target): target for target in targets}

        for future in as_completed(futures):
            status, message = future.result()
            counts[status] = counts.get(status, 0) + 1
            print(message)

    print("\nSummary: %d vulnerable, %d patched, %d unreachable, %d error"
          % (counts[VULNERABLE], counts[PATCHED], counts[UNREACHABLE], counts[ERROR]))
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--targets", required=True, nargs='+', help="List of target IP addresses separated by space")
    args = parser.parse_args()
    counts = scan_ips(args.targets)

    # Non-zero exit when at least one target could not be tested, so a scanner
    # or CI job does not read an inconclusive scan as a clean bill of health.
    if counts[UNREACHABLE] or counts[ERROR]:
        sys.exit(2)