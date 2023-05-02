# Description

This script checks multiple IP addresses for the BlueKeep vulnerability (CVE-2019-0708), which is a critical Remote Desktop Protocol (RDP) vulnerability found in older versions of Windows operating systems. The vulnerability allows attackers to remotely execute code on a target machine without any user interaction, potentially leading to full system compromise.

# Instructions

Install Python 3.x if you haven't already (https://www.python.org/downloads/).

Clone the repository with:

  git clone https://github.com/davidfortytwo/bluekeep.git

Open a terminal or command prompt.

Navigate to the directory where the script is located using the cd command.

Run the script by providing a list of target IP addresses as space-separated arguments. For example:

  python3 bluekeep-checker.py -t 192.168.1.1 192.168.1.2 192.168.1.3
  
The script will display the results for each IP address, indicating whether it is likely vulnerable to BlueKeep, patched, or not up/accessible.

Please note that scanning IP addresses without proper authorization may be illegal in some jurisdictions. Use this script responsibly and only for authorized purposes.  
