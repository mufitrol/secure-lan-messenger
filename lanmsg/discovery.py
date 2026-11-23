"""UDP broadcast peer announcements on a single LAN subnet."""
import asyncio
import json
import socket
import time

DISCOVERY_PORT = 37027
INTERVAL = 2
STALE_AFTER = 10


class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner

    def datagram_received(self, data, addr):
        try:
            if len(data) > 2048:
                return
            item = json.loads(data.decode("utf-8"))
            if item.get("v") != 1 or item.get("fingerprint") == self.owner.fingerprint:
                return
            name = item["name"]
            port = item["port"]
            fp = item["fingerprint"]
            if not isinstance(name, str) or not (1 <= len(name) <= 40):
                return
            if not isinstance(port, int) or not (1 <= port <= 65535):
                return
            if not isinstance(fp, str) or len(fp) != 64 or any(c not in '0123456789abcdef' for c in fp):
                return
            self.owner.peers[fp] = {"name": name, "host": addr[0], "port": port,
                                    "fingerprint": fp, "last_seen": time.monotonic()}
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            return


async def start_discovery(owner, broadcast="255.255.255.255"):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)
    sock.bind(("", DISCOVERY_PORT))
    transport, _ = await loop.create_datagram_endpoint(lambda: DiscoveryProtocol(owner), sock=sock)

    async def announce():
        while True:
            data = json.dumps({"v": 1, "name": owner.name, "port": owner.port,
                               "fingerprint": owner.fingerprint}).encode()
            transport.sendto(data, (broadcast, DISCOVERY_PORT))
            now = time.monotonic()
            for fp in list(owner.peers):
                if now - owner.peers[fp]["last_seen"] > STALE_AFTER:
                    del owner.peers[fp]
            await asyncio.sleep(INTERVAL)

    return transport, asyncio.create_task(announce())
