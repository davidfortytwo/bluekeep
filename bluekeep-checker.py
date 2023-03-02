import argparse
import socket

def check_bluekeep_vuln(target_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_ip, 3389))
        pre_auth_pkt = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
        sock.send(pre_auth_pkt)
        data = sock.recv(1024)
        if b"\x03\x00\x00\x0c" in data:
            print(f"[+] {target_ip} is likely VULNERABLE to BlueKeep!")
        else:
            print(f"[-] {target_ip} is likely patched :(")
    except:
        print(f"[-] {target_ip} is either not up or not vulnerable")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    args = parser.parse_args()
    check_bluekeep_vuln(args.target)
