#!/usr/bin/env python3
import os
import socket
import fcntl
import struct
import select
import subprocess
import signal
import logging
import json
import getpass
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vpn-client")

def derive_key(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=200_000,
        backend=default_backend()
    ).derive(password)

def setup_tun(iface):
    TUNSETIFF = 0x400454ca
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", iface.encode(), IFF_TUN | IFF_NO_PI))
    return fd

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError()
        buf += chunk
    return buf

def recv_frame(sock):
    length, = struct.unpack("!I", recv_exact(sock, 4))
    return recv_exact(sock, length)

def send_frame(sock, data):
    sock.sendall(struct.pack("!I", len(data)) + data)

def get_default_route():
    out = subprocess.check_output("ip route | grep default", shell=True).decode().split()
    return out[2], out[4]

def add_routes(iface, client_ip, server_ip):
    gw, dev = get_default_route()
    os.system(f"ip addr add {client_ip}/24 dev {iface}")
    os.system(f"ip link set dev {iface} up")
    os.system(f"ip route add {server_ip} via {gw} dev {dev}")
    os.system("ip route del default")
    os.system(f"ip route add default dev {iface}")
    return gw, dev

def restore_routes(gw, dev, server_ip):
    os.system("ip route del default")
    os.system(f"ip route add default via {gw} dev {dev}")
    os.system(f"ip route del {server_ip}")

def disable_ipv6():
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

def enable_ipv6():
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

def cleanup(sock, tun_fd, gw, dev, server_ip):
    restore_routes(gw, dev, server_ip)
    try: sock.close()
    except: pass
    try: os.close(tun_fd)
    except: pass
    enable_ipv6()

def main():
    with open("config_client.json") as f:
        config = json.load(f)

    password = getpass.getpass("Enter VPN session password: ").encode()
    disable_ipv6()

    sock = socket.create_connection((config["server"], config["port"]))
    salt = recv_frame(sock)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    frame = recv_frame(sock)
    client_ip = aesgcm.decrypt(frame[:12], frame[12:], None).decode().strip()
    logger.info(f"Assigned VPN IP: {client_ip}")

    tun_fd = setup_tun(config["tun"])
    gw, dev = add_routes(config["tun"], client_ip, config["server"])

    def sig_handler(signum, frame):
        cleanup(sock, tun_fd, gw, dev, config["server"])
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        while True:
            r, _, _ = select.select([sock, tun_fd], [], [])
            if sock in r:
                data = recv_frame(sock)
                pkt = aesgcm.decrypt(data[:12], data[12:], None)
                os.write(tun_fd, pkt)
            if tun_fd in r:
                pkt = os.read(tun_fd, 1500)
                nonce = os.urandom(12)
                send_frame(sock, nonce + aesgcm.encrypt(nonce, pkt, None))
    except:
        pass
    finally:
        cleanup(sock, tun_fd, gw, dev, config["server"])

if __name__ == "__main__":
    main()
