"""File-transfer bookkeeping, no untrusted path traversal."""
import hashlib
from pathlib import Path

CHUNK = 48 * 1024
MAX_FILE = 100 * 1024 * 1024


def safe_filename(value: str):
    name = Path(value.replace("\\", "/")).name
    if name in ("", ".", "..") or len(name) > 180:
        raise ValueError("Unsafe filename")
    return name


def file_sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as inp:
        while data := inp.read(CHUNK):
            h.update(data)
    return h.hexdigest()
