"""Runnable CLI research prototype. Use only on a private, approved test LAN."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from .security import (SecureChannel, TrustStore, derive_keys, fingerprint, load_identity,
                       public_bytes, sign, unwrap_secret, verify, wrap_secret)
from .transport import receive_frame, read_json, send_frame, send_json
from .discovery import start_discovery
from .files import CHUNK, MAX_FILE, file_sha256, safe_filename

TEXT, OFFER, DECISION, CHUNK_FRAME, FINISH, NOTICE = range(1, 7)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(data):
    return base64.b64decode(data, validate=True)


class Session:
    def __init__(self, app, reader, writer, name, fp, channel):
        self.app, self.reader, self.writer = app, reader, writer
        self.name, self.fp, self.channel = name, fp, channel
        self.lock = asyncio.Lock()
        self.pending_in = {}
        self.pending_out = {}
        self.incoming = {}

    async def send(self, kind, content: bytes):
        async with self.lock:
            await send_frame(self.writer, self.channel.encrypt(kind, content))

    async def send_obj(self, kind, obj):
        await self.send(kind, json.dumps(obj, separators=(",", ":")).encode())

    async def serve(self):
        try:
            while True:
                kind, content = self.channel.decrypt(await receive_frame(self.reader))
                if kind == TEXT:
                    print(f"\n[{self.name}] {content.decode('utf-8')}")
                elif kind == OFFER:
                    value = json.loads(content)
                    tid = value['id']
                    value['name'] = safe_filename(value['name'])
                    if (not isinstance(tid, str) or len(tid) != 32 or
                            not isinstance(value['size'], int) or not 0 <= value['size'] <= MAX_FILE or
                            len(value['sha256']) != 64 or tid in self.pending_in):
                        raise ValueError("Invalid file offer")
                    self.pending_in[tid] = value
                    print(f"\nFile offer from {self.name}: {value['name']} ({value['size']} bytes), ID {tid}")
                    print(f"  accept {self.name} {tid}  |  reject {self.name} {tid}")
                elif kind == DECISION:
                    value = json.loads(content)
                    tid = value['id']
                    pending = self.pending_out.pop(tid, None)
                    if pending and value.get('accepted') is True:
                        asyncio.create_task(self._send_file(tid, pending))
                    elif pending:
                        print(f"File rejected by {self.name}: {pending}")
                elif kind == CHUNK_FRAME:
                    if len(content) < 32:
                        raise ValueError("Invalid chunk")
                    tid = content[:32].decode('ascii')
                    record = self.incoming.get(tid)
                    if not record or record['received'] + len(content[32:]) > record['size']:
                        raise ValueError("Unexpected chunk")
                    record['stream'].write(content[32:])
                    record['digest'].update(content[32:])
                    record['received'] += len(content[32:])
                elif kind == FINISH:
                    tid = json.loads(content)['id']
                    record = self.incoming.pop(tid, None)
                    if not record:
                        raise ValueError("Unexpected completion")
                    record['stream'].close()
                    valid = record['received'] == record['size'] and record['digest'].hexdigest() == record['sha256']
                    if valid:
                        record['temp'].replace(record['target'])
                        print(f"\nFile saved: {record['target']} (SHA-256 MATCH)")
                    else:
                        record['temp'].unlink(missing_ok=True)
                        print(f"\nFile rejected: SHA-256/length mismatch from {self.name}")
                else:
                    raise ValueError("Unknown encrypted frame type")
        except (EOFError, ConnectionError, asyncio.IncompleteReadError, ValueError,
                OSError, UnicodeDecodeError, KeyError, TypeError) as exc:
            print(f"\nConnection with {self.name} closed: {type(exc).__name__}")
        finally:
            for record in self.incoming.values():
                record['stream'].close()
                record['temp'].unlink(missing_ok=True)
            self.writer.close()
            self.app.sessions.pop(self.name, None) if self.app.sessions.get(self.name) is self else None

    async def _send_file(self, tid, path):
        try:
            with path.open('rb') as inp:
                while data := inp.read(CHUNK):
                    await self.send(CHUNK_FRAME, tid.encode('ascii') + data)
            await self.send_obj(FINISH, {'id': tid})
            print(f"File transfer sent to {self.name}: {path.name}")
        except (OSError, ConnectionError) as exc:
            print(f"File transfer interrupted: {exc}")

    async def offer(self, path):
        path = Path(path).expanduser().resolve()
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError("File missing or exceeds 100 MiB")
        tid = secrets.token_hex(16)
        self.pending_out[tid] = path
        await self.send_obj(OFFER, {'id': tid, 'name': path.name, 'size': path.stat().st_size,
                                    'sha256': file_sha256(path)})
        print(f"Offer {tid} sent; awaiting explicit acceptance")

    async def decide(self, tid, accept):
        offer = self.pending_in.pop(tid)
        if accept:
            self.app.downloads.mkdir(parents=True, exist_ok=True)
            target = self.app.downloads / safe_filename(offer['name'])
            if target.exists():
                target = self.app.downloads / (tid[:8] + '_' + target.name)
            temp = self.app.downloads / ('.' + tid + '.part')
            self.incoming[tid] = {'stream': temp.open('xb'), 'temp': temp, 'target': target,
                                  'size': offer['size'], 'received': 0,
                                  'sha256': offer['sha256'], 'digest': hashlib.sha256()}
        await self.send_obj(DECISION, {'id': tid, 'accepted': accept})


class Messenger:
    def __init__(self, name, port, folder, broadcast):
        self.name, self.port, self.folder, self.broadcast = name, port, folder, broadcast
        self.private = load_identity(folder)
        self.pub = public_bytes(self.private)
        self.fingerprint = fingerprint(self.pub)
        self.trust = TrustStore(folder)
        self.peers, self.sessions = {}, {}
        self.downloads = folder / 'downloads'

    async def handshake(self, reader, writer, initiator):
        hello = {'v': 1, 'name': self.name, 'public': b64(self.pub)}
        if initiator:
            await send_json(writer, hello)
            response = await read_json(reader)
        else:
            response = await read_json(reader)
            await send_json(writer, hello)
        if response.get('v') != 1:
            raise ValueError('Incompatible protocol version')
        name = response['name']
        if not isinstance(name, str) or not 1 <= len(name) <= 40:
            raise ValueError('Invalid peer identity')
        peer_data = unb64(response['public'])
        if len(peer_data) > 1024:
            raise ValueError('Oversized public key')
        peer_public = serialization.load_der_public_key(peer_data)
        peer_fp = fingerprint(peer_data)
        if peer_fp == self.fingerprint:
            raise ValueError('Cannot connect to self')
        status = self.trust.check(name, peer_fp)
        print(f"\nPeer {name}: SHA-256 fingerprint {peer_fp} [{status}]")
        client_fp = self.fingerprint if initiator else peer_fp
        server_fp = peer_fp if initiator else self.fingerprint
        if initiator:
            secret = os.urandom(32)
            wrapped = wrap_secret(peer_public, secret)
            # Signature includes BOTH identities and wrapped key to bind the exchange.
            context = b'lanmsg-v1-keyex' + bytes.fromhex(client_fp) + bytes.fromhex(server_fp) + wrapped
            await send_json(writer, {'wrapped': b64(wrapped), 'signature': b64(sign(self.private, context))})
            ack = await read_json(reader)
            if ack.get('result') != 'ok':
                raise ValueError('Invalid key-exchange acknowledgement')
            verify(peer_public, unb64(ack['signature']), context + b'ack')
        else:
            data = await read_json(reader)
            wrapped = unb64(data['wrapped'])
            context = b'lanmsg-v1-keyex' + bytes.fromhex(client_fp) + bytes.fromhex(server_fp) + wrapped
            verify(peer_public, unb64(data['signature']), context)
            secret = unwrap_secret(self.private, wrapped)
            if len(secret) != 32:
                raise ValueError('Invalid session key')
            await send_json(writer, {'result': 'ok', 'signature': b64(sign(self.private, context + b'ack'))})
        channel = SecureChannel(*derive_keys(secret, client_fp, server_fp, initiator))
        session = Session(self, reader, writer, name, peer_fp, channel)
        previous = self.sessions.get(name)
        if previous:
            previous.writer.close()
        self.sessions[name] = session
        print(f"Encrypted session established with {name}")
        return session

    async def accept_connection(self, reader, writer):
        try:
            session = await asyncio.wait_for(
                self.handshake(reader, writer, False), timeout=None
            )
            await session.serve()
        except (Exception,) as exc:
            print(f"Incoming connection rejected: {type(exc).__name__}: {exc}")
            writer.close()

    async def connect(self, host, port):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 8)
        asyncio.create_task(self._connect_task(reader, writer))

    async def _connect_task(self, reader, writer):
        try:
            # Handshake has its own short timeout; chat is long-lived.
            await self._start_session(reader, writer)
        except (Exception,) as exc:
            print(f"Outgoing connection failed: {type(exc).__name__}: {exc}")
            writer.close()

    async def _start_session(self, reader, writer):
        session = await asyncio.wait_for(
            self.handshake(reader, writer, True), timeout=15
        )
        await session.serve()

    async def command(self, command):
        parts = command.strip().split(maxsplit=2)
        if not parts:
            return True
        verb = parts[0].lower()
        if verb == 'help':
            print('peers | chats | connect NAME | direct IP PORT | send NAME MESSAGE | file NAME PATH')
            print('accept NAME ID | reject NAME ID | verify NAME | fingerprint | quit')
        elif verb == 'peers':
            if not self.peers:
                print('No announcements: check firewall, same subnet, Wi-Fi isolation')
            for p in self.peers.values():
                print(f"{p['name']}: {p['host']}:{p['port']} fingerprint={p['fingerprint'][:16]}...")
        elif verb == 'chats':
            print(', '.join(self.sessions) or 'No active sessions')
        elif verb == 'fingerprint':
            print(self.fingerprint)
        elif verb == 'connect' and len(parts) >= 2:
            matches = [p for p in self.peers.values() if p['name'] == parts[1]]
            if len(matches) != 1:
                raise ValueError('Peer not found or ambiguous; use direct IP PORT')
            await self.connect(matches[0]['host'], matches[0]['port'])
        elif verb == 'direct' and len(parts) == 3:
            await self.connect(parts[1], int(parts[2]))
        elif verb == 'send' and len(parts) == 3:
            await self.sessions[parts[1]].send(TEXT, parts[2].encode('utf-8'))
        elif verb == 'file' and len(parts) == 3:
            await self.sessions[parts[1]].offer(parts[2])
        elif verb in ('accept', 'reject') and len(parts) == 3:
            await self.sessions[parts[1]].decide(parts[2], verb == 'accept')
        elif verb == 'verify' and len(parts) >= 2:
            s = self.sessions[parts[1]]
            print(f'Compare this fingerprint via an independent channel: {s.fp}')
            confirm = await asyncio.to_thread(input, 'Type full fingerprint to mark verified: ')
            if confirm == s.fp:
                self.trust.mark_verified(s.name, s.fp)
                print('Fingerprint marked verified')
            else:
                print('Verification cancelled')
        elif verb == 'quit':
            return False
        else:
            print('Unknown command. Type help')
        return True

    async def run(self):
        server = await asyncio.start_server(self.accept_connection, '0.0.0.0', self.port)
        broadcast_transport, task = await start_discovery(self, self.broadcast)
        print(f'LAN Messenger: {self.name} | TCP {self.port} | discovery UDP 37027')
        print(f'Fingerprint: {self.fingerprint}\nType help for commands')
        try:
            while True:
                cmd = await asyncio.to_thread(input, '> ')
                try:
                    if not await self.command(cmd):
                        break
                except (ValueError, KeyError, OSError, ConnectionError) as exc:
                    print(f'Error: {exc}')
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            task.cancel()
            broadcast_transport.close()
            server.close()
            await server.wait_closed()
            for s in self.sessions.values():
                s.writer.close()


def main():
    parser = argparse.ArgumentParser(description='Private-LAN P2P encrypted messenger prototype')
    parser.add_argument('--name', required=True)
    parser.add_argument('--port', type=int, default=39001)
    parser.add_argument('--data-dir', type=Path, default=Path.home() / '.lanmsg')
    parser.add_argument('--broadcast', default='255.255.255.255')
    args = parser.parse_args()
    if not 1 <= len(args.name) <= 40 or not 1 <= args.port <= 65535:
        parser.error('Invalid name or TCP port')
    asyncio.run(Messenger(args.name, args.port, args.data_dir, args.broadcast).run())


if __name__ == '__main__':
    main()
