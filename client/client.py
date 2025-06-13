#!/usr/bin/env python3
import os
import socket
import fcntl
import struct
import select
import subprocess
import signal
import argparse
import logging
import json
import getpass
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("vpn-client")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

def derive_key(password: bytes, salt: bytes = b"salt_is_sweet") -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def setup_tun(iface: str) -> int:
    TUNSETIFF = 0x400454ca
    IFF_TUN   = 0x0001
    IFF_NO_PI = 0x1000
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", iface.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    logger.info(f"TUN {iface} created")
    return fd

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed in recv_exact")
        buf += chunk
    return buf

def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    length, = struct.unpack("!I", hdr)
    return recv_exact(sock, length)

def send_frame(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def get_default_route():
    out = subprocess.check_output("ip route | grep default", shell=True).decode().split()
    gw = out[2]
    dev = out[4]
    return gw, dev

def add_routes(iface: str, client_ip: str, server_ip: str):
    gw, dev = get_default_route()
    os.system(f"ip addr add {client_ip}/24 dev {iface}")
    os.system(f"ip link set dev {iface} up")
    os.system(f"ip route add {server_ip} via {gw} dev {dev}")
    os.system("ip route del default")
    os.system(f"ip route add default dev {iface}")
    logger.info("Routes adjusted for VPN")
    return gw, dev

def restore_routes(gw: str, dev: str, server_ip: str):
    os.system("ip route del default")
    os.system(f"ip route add default via {gw} dev {dev}")
    os.system(f"ip route del {server_ip}")
    logger.info("Original routes restored")

def disable_ipv6():
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    logger.info("IPv6 disabled")

def enable_ipv6():
    os.system("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
    logger.info("IPv6 restored")

def cleanup(sock, tun_fd, old_gw, old_dev, server_ip):
    try:
        restore_routes(old_gw, old_dev, server_ip)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass
    try:
        enable_ipv6()
    except Exception:
        pass

def main():
    with open("./config_client.json") as f:
        config = json.load(f)

    password = getpass.getpass("Enter VPN session password: ").encode()
    key = derive_key(password)

    disable_ipv6()

    sock = socket.create_connection((config["server"], config["port"]))
    logger.info(f"Connected to VPN server {config['server']}:{config['port']}")

    frame = recv_frame(sock)
    nonce = frame[:12]
    ct = frame[12:]
    aesgcm = AESGCM(key)
    client_ip = aesgcm.decrypt(nonce, ct, None).decode().strip()
    logger.info(f"Assigned VPN IP: {client_ip}")

    tun_fd = setup_tun(config["tun"])

    old_gw, old_dev = add_routes(config["tun"], client_ip, config["server"])

    def sig_handler(signum, frame):
        logger.warning(f"Signal {signum} received, exiting...")
        cleanup(sock, tun_fd, old_gw, old_dev, config["server"])
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        while True:
            r, _, _ = select.select([sock, tun_fd], [], [])
            if sock in r:
                frame = recv_frame(sock)
                nonce = frame[:12]
                ct = frame[12:]
                pkt = aesgcm.decrypt(nonce, ct, None)
                os.write(tun_fd, pkt)
            if tun_fd in r:
                pkt = os.read(tun_fd, 1500)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, pkt, None)
                send_frame(sock, nonce + ct)
    except Exception as e:
        logger.warning(f"Disconnected: {e}")
    finally:
        cleanup(sock, tun_fd, old_gw, old_dev, config["server"])

if __name__ == "__main__":
    main()
