#!/usr/bin/env python3
import os
import socket
import threading
import select
import struct
import signal
import logging
import fcntl
import json
import getpass
from ipaddress import IPv4Network
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import pyroute2

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vpn-server")

def setup_tun(iface, addr, prefix):
    TUNSETIFF = 0x400454ca
    IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", iface.encode(), IFF_TUN | IFF_NO_PI))
    ipr = pyroute2.IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.addr("add", index=idx, address=addr, prefixlen=prefix)
    ipr.link("set", index=idx, state="up")
    return fd, ipr

def enable_nat(subnet, ext_if, tun):
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system(f"iptables -t nat -A POSTROUTING -s {subnet} -o {ext_if} -j MASQUERADE")
    os.system(f"iptables -A FORWARD -i {ext_if} -o {tun} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system(f"iptables -A FORWARD -i {tun} -o {ext_if} -j ACCEPT")

def cleanup_nat(subnet, ext_if, tun):
    os.system("sysctl -w net.ipv4.ip_forward=0")
    os.system(f"iptables -t nat -D POSTROUTING -s {subnet} -o {ext_if} -j MASQUERADE")
    os.system(f"iptables -D FORWARD -i {ext_if} -o {tun} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system(f"iptables -D FORWARD -i {tun} -o {ext_if} -j ACCEPT")

def derive_key(password, salt):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=200_000, backend=default_backend()
    ).derive(password)

def send_frame(sock, data):
    sock.sendall(struct.pack("!I", len(data)) + data)

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

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, ip, password, tun_fd):
        super().__init__(daemon=True)
        self.conn, self.addr, self.ip = conn, addr, ip
        self.password = password
        self.tun_fd = tun_fd

    def run(self):
        try:
            salt = os.urandom(16)
            send_frame(self.conn, salt)
            key = derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, self.ip.encode(), None)
            send_frame(self.conn, nonce + ct)
            logger.info(f"[{self.addr}] connected with {self.ip}")
            while True:
                r, _, _ = select.select([self.conn, self.tun_fd], [], [])
                if self.conn in r:
                    data = recv_frame(self.conn)
                    pt = aesgcm.decrypt(data[:12], data[12:], None)
                    os.write(self.tun_fd, pt)
                if self.tun_fd in r:
                    pkt = os.read(self.tun_fd, 1500)
                    nonce = os.urandom(12)
                    send_frame(self.conn, nonce + aesgcm.encrypt(nonce, pkt, None))
        except:
            pass
        finally:
            self.conn.close()

def main():
    with open("config_server.json") as f:
        config = json.load(f)

    password = getpass.getpass("Enter session password: ").encode()

    tun = config["tun"]
    tun_ip = config["tun_ip"]
    prefix = config["prefix"]
    subnet = config["subnet"]
    ext_if = config["ext_if"]
    port = config["port"]

    tun_fd, ipr = setup_tun(tun, tun_ip, prefix)
    enable_nat(subnet, ext_if, tun)

    net = IPv4Network(subnet)
    pool = iter([str(ip) for ip in net.hosts()][1:])
    server = socket.create_server(("", port), reuse_port=True)

    def shutdown(signum, frame):
        cleanup_nat(subnet, ext_if, tun)
        try:
            idx = ipr.link_lookup(ifname=tun)[0]
            ipr.addr("del", index=idx, address=tun_ip, prefixlen=prefix)
            ipr.link("set", index=idx, state="down")
        except:
            pass
        server.close()
        os.close(tun_fd)
        ipr.close()
        exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        conn, addr = server.accept()
        ip = next(pool, None)
        if not ip:
            conn.close()
            continue
        ClientHandler(conn, addr, ip, password, tun_fd).start()

if __name__ == "__main__":
    main()