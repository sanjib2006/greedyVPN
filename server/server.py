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
from cryptography.hazmat.backends import default_backend
from ipaddress import IPv4Network
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyroute2

logger = logging.getLogger("vpn-server")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

def setup_tun(iface: str, addr: str, prefix: int):
    TUNSETIFF = 0x400454ca
    IFF_TUN   = 0x0001
    IFF_NO_PI = 0x1000

    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", iface.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)

    ipr = pyroute2.IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.addr("add", index=idx, address=addr, prefixlen=prefix)
    ipr.link("set", index=idx, state="up")
    logger.info(f"TUN {iface} set up with {addr}/{prefix}")
    return fd, ipr

def enable_nat(subnet: str, ext_if: str, tun: str):
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system(f"iptables -t nat -A POSTROUTING -s {subnet} -o {ext_if} -j MASQUERADE")
    os.system(f"iptables -A FORWARD -i {ext_if} -o {tun} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system(f"iptables -A FORWARD -i {tun} -o {ext_if} -j ACCEPT")
    logger.info(f"NAT enabled: {subnet} → {ext_if}")

def derive_master_key(password: bytes, salt: bytes = b"salt_is_sweet"):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during recv_exact")
        buf += chunk
    return buf

def send_frame(sock, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_frame(sock) -> bytes:
    hdr = recv_exact(sock, 4)
    length, = struct.unpack("!I", hdr)
    return recv_exact(sock, length)

class ClientHandler(threading.Thread):
    def __init__(self, conn, addr, tid, key, tun_fd):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.tid = tid
        self.key = key
        self.tun_fd = tun_fd
        self.aesgcm = AESGCM(key)
        self.nonce_size = 12

    def run(self):
        logger.info(f"[{self.addr}] assigned 10.8.0.{self.tid}")
        try:
            nonce = os.urandom(self.nonce_size)
            client_ip = f"10.8.0.{self.tid}".encode()
            ct = self.aesgcm.encrypt(nonce, client_ip, None)
            send_frame(self.conn, nonce + ct)

            while True:
                r, _, _ = select.select([self.conn, self.tun_fd], [], [])
                if self.conn in r:
                    data = recv_frame(self.conn)
                    nonce = data[:self.nonce_size]
                    ct = data[self.nonce_size:]
                    pt = self.aesgcm.decrypt(nonce, ct, None)
                    os.write(self.tun_fd, pt)
                if self.tun_fd in r:
                    pkt = os.read(self.tun_fd, 1500)
                    nonce = os.urandom(self.nonce_size)
                    ct = self.aesgcm.encrypt(nonce, pkt, None)
                    send_frame(self.conn, nonce + ct)
        except Exception as e:
            logger.warning(f"[{self.addr}] disconnecting: {e}")
        finally:
            self.conn.close()
            logger.info(f"[{self.addr}] handler shutdown")

def main():
    with open("config_server.json", "r") as f:
        config = json.load(f)

    password = getpass.getpass("Enter session password: ").encode()
    key = derive_master_key(password)

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
    logger.info(f"Listening on port {port} for VPN clients")

    def shutdown(signum, frame):
        logger.info("Shutting down...")
        server.close()
        os.close(tun_fd)
        ipr.close()
        exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    tid = 2
    while True:
        conn, addr = server.accept()
        ip = next(pool, None)
        if not ip:
            logger.error("No more IPs in pool — rejecting client")
            conn.close()
            continue
        threading.Thread(
            target=ClientHandler(conn, addr, tid, key, tun_fd).run,
            daemon=True
        ).start()
        tid += 1

if __name__ == "__main__":
    main()
