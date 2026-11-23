"""Bounded length-prefixed TCP framing; asyncio handles partial reads."""
import asyncio
import json
import struct

MAX_FRAME = 1024 * 1024
MAX_HANDSHAKE = 16384


async def send_frame(writer, data: bytes, limit=MAX_FRAME):
    if len(data) > limit:
        raise ValueError("Oversized frame")
    writer.write(struct.pack("!I", len(data)) + data)
    await writer.drain()


async def receive_frame(reader, limit=MAX_FRAME):
    length = struct.unpack("!I", await reader.readexactly(4))[0]
    if length > limit:
        raise ValueError("Oversized frame")
    return await reader.readexactly(length)


async def send_json(writer, obj):
    await send_frame(writer, json.dumps(obj, separators=(",", ":")).encode(), MAX_HANDSHAKE)


async def read_json(reader):
    return json.loads((await receive_frame(reader, MAX_HANDSHAKE)).decode())
