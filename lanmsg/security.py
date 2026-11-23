"""RSA-OAEP key transport, RSA-PSS authentication and directional AES-256-GCM."""
import hashlib
import json
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_identity(folder: Path):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "identity.pem"
    if path.exists():
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        data = private.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
        # Exclusive creation prevents accidental overwrites; owner-only on POSIX.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return private


def public_bytes(private):
    return private.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(data: bytes):
    return hashlib.sha256(data).hexdigest()


def wrap_secret(public, secret: bytes):
    return public.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                               algorithm=hashes.SHA256(), label=None))


def unwrap_secret(private, wrapped: bytes):
    return private.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                 algorithm=hashes.SHA256(), label=None))


def sign(private, content: bytes):
    return private.sign(content, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


def verify(public, signature: bytes, content: bytes):
    public.verify(signature, content, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                   salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


def derive_keys(secret: bytes, client_fp: str, server_fp: str, initiator: bool):
    """Bind key derivation to two identities, and separate send/receive keys."""
    context = bytes.fromhex(client_fp) + bytes.fromhex(server_fp)
    result = HKDF(algorithm=hashes.SHA256(), length=64, salt=context,
                  info=b"lanmsg-v1-directional-aesgcm").derive(secret)
    return (result[:32], result[32:]) if initiator else (result[32:], result[:32])


class SecureChannel:
    """Each direction has an independent key and monotonic 96-bit nonce counter."""
    def __init__(self, send_key: bytes, recv_key: bytes):
        self.sender = AESGCM(send_key)
        self.receiver = AESGCM(recv_key)
        self.send_seq = 0
        self.recv_seq = 0

    def encrypt(self, kind: int, payload: bytes) -> bytes:
        if self.send_seq >= 2**64:
            raise ValueError("Sequence counter exhausted")
        seq = self.send_seq
        self.send_seq += 1
        aad = struct.pack("!BQ", kind, seq)
        nonce = seq.to_bytes(12, "big")
        return aad + nonce + self.sender.encrypt(nonce, payload, aad)

    def decrypt(self, data: bytes):
        if len(data) < 1 + 8 + 12 + 16:
            raise ValueError("Truncated encrypted frame")
        kind, seq = struct.unpack("!BQ", data[:9])
        if seq != self.recv_seq:
            raise ValueError("Replay or reordered frame")
        nonce = data[9:21]
        if nonce != seq.to_bytes(12, "big"):
            raise ValueError("Unexpected nonce")
        plaintext = self.receiver.decrypt(nonce, data[21:], data[:9])
        self.recv_seq += 1
        return kind, plaintext


class TrustStore:
    """TOFU: first-seen fingerprints retained by display name; changes rejected."""
    def __init__(self, folder: Path):
        self.path = folder / "known_peers.json"
        self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    def check(self, name: str, fp: str):
        known = self.data.get(name)
        if known is not None and known["fingerprint"] != fp:
            raise ValueError(f"KEY CHANGED for {name}; connection blocked")
        if known is None:
            self.data[name] = {"fingerprint": fp, "verified": False}
            self._save()
            return "NEW - compare fingerprint out of band before trusting"
        return "VERIFIED" if known["verified"] else "UNVERIFIED"

    def mark_verified(self, name: str, fp: str):
        if name not in self.data or self.data[name]["fingerprint"] != fp:
            raise ValueError("No matching stored fingerprint")
        self.data[name]["verified"] = True
        self._save()

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        if os.name == "posix":
            os.chmod(self.path, 0o600)
