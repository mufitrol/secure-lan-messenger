# Secure LAN Messenger - research prototype

Implements the proposed four layers: UDP discovery, asyncio TCP, authenticated RSA-OAEP/PSS + AES-256-GCM, and CLI-based chat/file exchange.

## Ethics / status
The research document says implementation and network testing must not begin before confirmed ethics approval. This is a **code draft for review**, not evidence that deployment, ethics approval, or LAN testing has occurred. Do not run it on a network until approval and permission are confirmed. No security audit has been conducted.

## Setup (after approval)
Python 3.10+; only external dependency is `cryptography`.

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Two terminals on one test laptop (different identities and ports):

```powershell
python -m lanmsg --name Alice --port 39001 --data-dir .alice
python -m lanmsg --name Bob --port 39002 --data-dir .bob
```

The same UDP discovery port is shared; on some Windows networks a second local socket cannot bind or broadcast reflection may not work. For a more representative run use two personally owned devices on the same private Wi-Fi, or use `direct 127.0.0.1 39002` without discovery.

Commands: `help`, `peers`, `connect Bob`, `direct IP PORT`, `send Bob Hello`, `file Bob ./example.txt`, `accept Bob OFFER_ID`, `reject Bob OFFER_ID`, `verify Bob`, `fingerprint`, `quit`.

## Important limitations
* **TOFU** stores unverified first-seen keys and prints fingerprints. Verify them out-of-band before sharing sensitive information. Changes to stored identities are blocked. Display names must be unique per local profile.
* RSA key transport lacks forward secrecy. Private keys are stored unencrypted with restrictive POSIX permissions; Windows ACLs must be reviewed. Password-protected storage is future work.
* UDP announcements are not authenticated, reveal peer names and fingerprints and do not traverse routed subnets. Some firewalls and AP client-isolation configurations block discovery.
* File transfers require explicit consent, limit size to 100 MiB, use 48 KiB chunks, and compare SHA-256 before moving the temporary file into downloads. Disk resource exhaustion and DoS protection are limited.
* Handshake timeout for inbound connections is not enforced in this draft; untrusted peers could retain an idle connection. This must be addressed before production.
* Concurrent simultaneous connections to the **same** name may replace a session; this prototype does not implement robust connection arbitration or message persistence.
* The project claims cross-platform targets, but **only local unit tests in this environment** can be stated here; cross-OS or LAN evidence requires the author's tests.
