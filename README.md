# Description

This script checks multiple IP addresses for the BlueKeep vulnerability (CVE-2019-0708), which is a critical Remote Desktop Protocol (RDP) vulnerability found in older versions of Windows operating systems. The vulnerability allows attackers to remotely execute code on a target machine without any user interaction, potentially leading to full system compromise.

This repository contains a **checker only**. There is no exploit code here. The repository description used to read "Checker and exploit for Bluekeep CVE-2019-0708 vulnerability", which was inaccurate.

# Instructions

Install Python 3.x if you haven't already (https://www.python.org/downloads/).

Clone the repository with:

  git clone https://github.com/davidfortytwo/bluekeep.git

Open a terminal or command prompt.

Navigate to the directory where the script is located using the cd command.

Run the script by providing a list of target IP addresses as space-separated arguments. For example:

  python3 bluekeep-checker.py -t 192.168.1.1 192.168.1.2 192.168.1.3

The script reports one of four distinct outcomes per target:

| Marker | Meaning |
|---|---|
| `[+]` | likely vulnerable to BlueKeep |
| `[-]` | likely patched |
| `[?]` | **unreachable** — the host did not answer, so its patch status is unknown |
| `[!]` | probe error |

An unreachable target is deliberately *not* reported as "patched". Previously a connection timeout produced the same message as a genuine negative result, which made a failed scan indistinguishable from a clean one.

Each run also prints a summary line and exits with status **2** if any target was unreachable or errored, so scanners and CI jobs can detect an inconclusive run.

Please note that scanning IP addresses without proper authorization may be illegal in some jurisdictions. Use this script responsibly and only for authorized purposes.  
