import asyncio
import tempfile
import unittest
from pathlib import Path
from cryptography.exceptions import InvalidTag
from lanmsg.security import (SecureChannel, TrustStore, derive_keys, fingerprint, load_identity,
                             public_bytes, sign, unwrap_secret, verify, wrap_secret)
from lanmsg.transport import receive_frame, send_frame
from lanmsg.files import safe_filename


class CryptographyTests(unittest.TestCase):
    def test_authenticated_key_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            a = load_identity(Path(temp) / 'a')
            b = load_identity(Path(temp) / 'b')
            secret = b'a' * 32
            encrypted = wrap_secret(b.public_key(), secret)
            verify(a.public_key(), sign(a, encrypted), encrypted)
            self.assertEqual(unwrap_secret(b, encrypted), secret)
            a_fp, b_fp = fingerprint(public_bytes(a)), fingerprint(public_bytes(b))
            ab = SecureChannel(*derive_keys(secret, a_fp, b_fp, True))
            ba = SecureChannel(*derive_keys(secret, a_fp, b_fp, False))
            frame = ab.encrypt(1, b'secret text')
            self.assertNotIn(b'secret text', frame)
            self.assertEqual(ba.decrypt(frame), (1, b'secret text'))
            with self.assertRaises(ValueError):
                ba.decrypt(frame)
            bad = bytearray(ab.encrypt(1, b'new secret'))
            bad[-1] ^= 1
            with self.assertRaises(InvalidTag):
                ba.decrypt(bytes(bad))

    def test_trust_store_key_change(self):
        with tempfile.TemporaryDirectory() as temp:
            store = TrustStore(Path(temp))
            self.assertIn('NEW', store.check('Alice', 'a' * 64))
            store.mark_verified('Alice', 'a' * 64)
            self.assertEqual(store.check('Alice', 'a' * 64), 'VERIFIED')
            with self.assertRaises(ValueError):
                store.check('Alice', 'b' * 64)

    def test_safe_filename(self):
        self.assertEqual(safe_filename('../hello.txt'), 'hello.txt')
        with self.assertRaises(ValueError):
            safe_filename('..')


class FramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_read_and_limit(self):
        async def handler(reader, writer):
            await send_frame(writer, b'hello')
            writer.close()
        server = await asyncio.start_server(handler, '127.0.0.1', 0)
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', server.sockets[0].getsockname()[1])
            self.assertEqual(await receive_frame(reader), b'hello')
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()
        with self.assertRaises(ValueError):
            await send_frame(None, b'abc', limit=2)


if __name__ == '__main__':
    unittest.main()
