#!/usr/bin/env python3
"""
UniFi Travel Router (UTR) BLE config client

"""

import asyncio
import base64
import gzip
import hashlib
import json
import logging
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field
from typing import Optional

import msgpack
from bleak import BleakClient, BleakScanner
from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base, randombytes
from nacl.secret import SecretBox
from passlib.hash import sha512_crypt

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("utr_ble")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UUID_READ  = "d587c47f-ac6e-4388-a31c-e6cd380ba043"  # device->phone (notify)
UUID_WRITE = "9280f26c-a56f-43ea-b769-d5d732e1ac67"  # phone->device (write)
SERVICE_DATA_UUID = "0000252a-0000-1000-8000-00805f9b34fb"

# Bootstrap transport key — hardcoded in firmware.
# Same value used by G3 Instant (zerotypic/unifi-ble-client confirms this).
DEFAULT_KEY = bytes([
    0xa7, 0x81, 0xf8, 0xa4, 0xa6, 0x27, 0x37, 0x3b,
    0x70, 0x74, 0x57, 0x38, 0xcd, 0xff, 0xdd, 0x1d,
    0xe9, 0xae, 0x35, 0x25, 0x17, 0xc3, 0x74, 0xca,
    0x9a, 0xfc, 0x21, 0x5c, 0x39, 0xc6, 0x26, 0x37,
])

# Protocol bytes
PROTO_AUTH   = 0x00
PROTO_BINARY = 0x03

# UiCommV4 part types/formats
PART_HEADER = 1
PART_BODY   = 2
FMT_JSON    = 1
FMT_STRING  = 2

# Shell auth nonce seed: 0x756E6975 = ASCII "uniu"
# Keep this constant for reference, but do not use it as the runtime counter start.
SHELL_NONCE_SEED = 0x756E6975

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

def make_transport_nonce(counter: int) -> bytes:
    """24-byte nonce: counter as 2B BE + 22 zero bytes (reference impl style)."""
    return struct.pack(">H", counter & 0xFFFF) + b"\x00" * 22


def make_shell_nonce(counter: int) -> bytes:
    """24-byte nonce: 20 zero bytes + counter as 4B BE."""
    return b"\x00" * 20 + struct.pack(">I", counter & 0xFFFFFFFF)


def secretbox_enc(msg: bytes, nonce: bytes, key: bytes) -> bytes:
    return SecretBox(key).encrypt(msg, nonce).ciphertext


def secretbox_dec(ct: bytes, nonce: bytes, key: bytes) -> bytes:
    return SecretBox(key).decrypt(ct, nonce)


def compute_session_key(cli_priv: bytes, cli_pub: bytes, srv_pub: bytes,
                        extra: Optional[bytes] = None) -> bytes:
    """
    BLAKE2b( X25519(cli_priv, srv_pub) || cli_pub || srv_pub [|| extra] )
    extra=None for transport layer, extra=pw_hash for shell layer.
    """
    dh = crypto_scalarmult(cli_priv, srv_pub)
    h = hashlib.blake2b(digest_size=32)
    h.update(dh)
    h.update(cli_pub)
    h.update(srv_pub)
    if extra:
        h.update(extra)
    return h.digest()


def sha512crypt_hash_field(password: str, salt: str) -> bytes:
    """
    Return the final hash field from standard SHA-512 crypt ($6$).

    The UTR app uses $6$ SHA512-crypt and then takes only the trailing
    hash field after the final '$'.
    """
    full = sha512_crypt.using(salt=salt, rounds=5000).hash(password)
    return full.split("$")[-1].encode("ascii")

def btlev2_encode(seq: int, protocol: int, payload: bytes,
                  key: bytes, nonce_ctr: int) -> bytes:
    """Encrypt [seq:2BE][proto:1][payload], prepend total_len."""
    plaintext = struct.pack(">HB", seq, protocol) + payload
    nonce = make_transport_nonce(nonce_ctr)
    ct = secretbox_enc(plaintext, nonce, key)
    return struct.pack(">H", 2 + len(ct)) + ct


def btlev2_decode(data: bytes, key: bytes, nonce_ctr: int) -> tuple:
    """Decrypt a BTLEv2 frame. Returns (seq, protocol, payload)."""
    total_len = struct.unpack_from(">H", data, 0)[0]
    ct = data[2:total_len]
    nonce = make_transport_nonce(nonce_ctr)
    pt = secretbox_dec(ct, nonce, key)
    seq      = struct.unpack_from(">H", pt, 0)[0]
    protocol = pt[2]
    payload  = pt[3:]
    return seq, protocol, payload


# ---------------------------------------------------------------------------
# Transport DH msgpack messages
# ---------------------------------------------------------------------------

def pack_dh_pubkey(pubkey: bytes) -> bytes:
    p = msgpack.Packer()
    return p.pack_array_header(3) + p.pack("DHPK") + p.pack(False) + p.pack(bytes(pubkey))


def unpack_dh_pubkey(data: bytes) -> bytes:
    header, _, pubkey = msgpack.loads(data, raw=False)
    assert header == "DHPK", f"Expected DHPK, got {header!r}"
    return pubkey


def pack_auth_ok(pubkey: bytes) -> bytes:
    p = msgpack.Packer()
    return p.pack_array_header(3) + p.pack("AUTH") + p.pack("DH") + p.pack(bytes(pubkey))


def unpack_auth_ok(data: bytes) -> bool:
    obj = msgpack.loads(data, raw=False)
    return isinstance(obj, (list, tuple)) and len(obj) >= 2 and obj[0] == "AUTH" and obj[1] == "DH"


# ---------------------------------------------------------------------------
# UiCommV4 message framing
# ---------------------------------------------------------------------------

def pack_part(part_type: int, fmt: int, compress: bool, data: bytes) -> bytes:
    return struct.pack(">BBBBI", part_type, fmt, int(compress), 0, len(data)) + data


def unpack_part(buf: bytes) -> tuple:
    ptype, pfmt, compress, _, size = struct.unpack_from(">BBBBI", buf)
    return {"type": ptype, "fmt": pfmt, "compress": bool(compress),
            "data": buf[8:8 + size]}, 8 + size


def pack_action_msg(guid: str, action: str, body_dict: dict) -> bytes:
    """Pack a UiCommV4 Request message (hdshkStart, hdshkFinish).
      @JsonName("id") = guid, @JsonName("timestamp") = timestamp, "action", "type"
    """
    hdr  = json.dumps({
        "id":        guid,
        "timestamp": int(time.time() * 1000),
        "type":      "request",
        "action":    action,
    }).encode()
    body = json.dumps(body_dict).encode()
    return pack_part(PART_HEADER, FMT_JSON, True, zlib.compress(hdr)) + \
           pack_part(PART_BODY,   FMT_JSON, True, zlib.compress(body))


def pack_cmd_msg(guid: str, cmd: str) -> bytes:
    """Pack a UiCommV4 Cmd message.
      @JsonName("id") = guid, @JsonName("timestamp") = timestamp
    Body is STRING type, not compressed (shell commands are short).
    """
    hdr = json.dumps({
        "id":        guid,
        "timestamp": int(time.time() * 1000),
        "type":      "cmd",
    }).encode()
    return pack_part(PART_HEADER, FMT_JSON,   True,  zlib.compress(hdr)) + \
           pack_part(PART_BODY,   FMT_STRING,  False, cmd.encode())


def unpack_msg(buf: bytes) -> tuple:
    """Unpack a UiCommV4 message -> (header_dict, body_bytes).
    Header field 'id' is the guid (confirmed from @JsonName annotations).
    Decompresses parts where compress flag is set.
    """
    hdr_info, consumed = unpack_part(buf)
    body_info, _       = unpack_part(buf[consumed:])
    hdr_data  = zlib.decompress(hdr_info["data"]) if hdr_info["compress"] else hdr_info["data"]
    body_data = zlib.decompress(body_info["data"]) if body_info["compress"] else body_info["data"]
    return json.loads(hdr_data), body_data


# ---------------------------------------------------------------------------
# Config encoding
# ---------------------------------------------------------------------------

def parse_config(raw: str) -> dict:
    cfg = {}
    for line in raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg


def serialize_config(cfg: dict) -> str:
    return "".join(f"{k}={v}\n" for k, v in cfg.items())


def encode_config(cfg: dict) -> str:
    return base64.b64encode(gzip.compress(serialize_config(cfg).encode())).decode()


def decode_config_b64(b64: str) -> dict:
    return parse_config(gzip.decompress(base64.b64decode(b64)).decode())


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

@dataclass
class UtrSession:
    client:          BleakClient
    seq:             int   = 0
    tx_nonce:        int   = 0
    rx_nonce:        int   = 0
    tx_key:          bytes = field(default_factory=lambda: bytes(DEFAULT_KEY))
    rx_key:          bytes = field(default_factory=lambda: bytes(DEFAULT_KEY))
    shell_nonce:     int   = 1969385077
    _msg_id:         int   = 0
    transport_local_pub:  bytes = field(default_factory=bytes)
    transport_server_pub: bytes = field(default_factory=bytes)
    _rx_buf:         bytearray = field(default_factory=bytearray)
    _rx_q:           asyncio.Queue = field(default_factory=asyncio.Queue)

    def _new_guid(self) -> str:
        self._msg_id += 1
        return f"utr-{self._msg_id:04d}"

    def _on_notify(self, _handle, data: bytearray):
        self._rx_buf.extend(data)
        while len(self._rx_buf) >= 2:
            total_len = struct.unpack_from(">H", self._rx_buf)[0]
            if len(self._rx_buf) < total_len:
                break
            self._rx_q.put_nowait(bytes(self._rx_buf[:total_len]))
            del self._rx_buf[:total_len]

    async def _recv(self, timeout: float = 10.0) -> tuple:
        frame = await asyncio.wait_for(self._rx_q.get(), timeout=timeout)
        seq, proto, payload = btlev2_decode(frame, self.rx_key, self.rx_nonce)
        self.rx_nonce += 1
        log.debug(f"<- seq={seq} proto=0x{proto:02x} ({len(payload)}B)")
        return seq, proto, payload

    async def _send(self, protocol: int, payload: bytes):
        frame = btlev2_encode(self.seq, protocol, payload, self.tx_key, self.tx_nonce)
        self.seq      = (self.seq + 1) & 0xFFFF
        self.tx_nonce += 1
        log.debug(f"-> proto=0x{protocol:02x} ({len(payload)}B)")
        await self.client.write_gatt_char(UUID_WRITE, frame, response=True)

    # -----------------------------------------------------------------------
    # Layer 1: Transport DH
    # -----------------------------------------------------------------------

    async def transport_handshake(self):
        """Establish per-session transport key using DEFAULT_KEY as bootstrap."""
        log.info("Transport DH handshake...")

        priv = randombytes(32)
        pub  = crypto_scalarmult_base(priv)

        await self._send(PROTO_AUTH, pack_dh_pubkey(pub))

        _, _, srv_payload = await self._recv()
        srv_pub = unpack_dh_pubkey(srv_payload)

        session_key = compute_session_key(priv, pub, srv_pub)

        await self._send(PROTO_AUTH, pack_auth_ok(pub))

        _, _, ack = await self._recv()
        assert unpack_auth_ok(ack), "Transport DH auth-ok not echoed"

        self.tx_key = self.rx_key = session_key
        self.transport_local_pub  = bytes(pub)
        self.transport_server_pub = bytes(srv_pub)
        log.info("Transport DH complete.")

    # -----------------------------------------------------------------------
    # Layer 2: Shell authentication
    # -----------------------------------------------------------------------

    async def _shell_handshake(self, username: str, password: str) -> bool:
        """
        Attempt one shell handshake with the given password.
        Returns True on success, False on BadSecret (wrong password).
        Raises on other errors.

        The default password for the device is "ui"
        """
        priv = randombytes(32)
        pub  = crypto_scalarmult_base(priv)

        # hdshkStart
        guid = self._new_guid()
        await self._send(PROTO_BINARY,
                         pack_action_msg(guid, "hdshkStart",
                                         {"user": "ui",
                                          "key": pub.hex()}))

        _, resp_body = await self._recv_response()
        resp = json.loads(resp_body)
        log.debug(f"hdshkStart resp: {resp}")

        srv_pub = bytes.fromhex(resp["key"])
        auth    = resp["auth"]
        assert int(auth["type"]) == 3 and int(auth["id"]) == 6

        pw_hash   = sha512crypt_hash_field(password, auth["salt"]).decode("ascii").encode("iso-8859-1")
        shell_key = compute_session_key(priv, pub, srv_pub, extra=pw_hash)

        #   secret = Base64( secretbox_encrypt(message=SHA256(transport_local_pub),
        #                                     nonce=f(counter),
        #                                     key=shell_key) )
        n0        = make_shell_nonce(self.shell_nonce); self.shell_nonce += 1
        plaintext = hashlib.sha256(self.transport_local_pub).digest()
        secret    = base64.b64encode(secretbox_enc(plaintext, n0, shell_key)).decode("ascii")

        guid2 = self._new_guid()
        await self._send(PROTO_BINARY,
                         pack_action_msg(guid2, "hdshkFinish", {"secret": secret}))

        _, resp2_body = await self._recv_response()
        resp2 = json.loads(resp2_body)

        #   decrypt with shell_key and require plaintext == SHA256(transport_server_pub)
        n1       = make_shell_nonce(self.shell_nonce); self.shell_nonce += 1
        srv_ct   = base64.b64decode(resp2["secret"])
        expected = hashlib.sha256(self.transport_server_pub).digest()
        try:
            decrypted = secretbox_dec(srv_ct, n1, shell_key)
            if decrypted != expected:
                log.debug("Server secret mismatch after decrypt")
                return False
            log.debug("Server secret ok")
            return True
        except Exception:
            return False  # BadSecret — wrong password

    async def shell_authenticate(self, username: str = "ui", password: Optional[str] = None):
        """
        Match the decompiled app more closely:
        - user defaults to "ui"
        - password defaults to "ui"

        """
        effective_password = "ui" if password in (None, "") else password
        log.info(f"Shell authentication...")
        success = await self._shell_handshake(username, effective_password)
        if not success:
            raise RuntimeError("Shell auth failed: bad secret / wrong password.")

    async def _recv_response(self, timeout: float = 10.0) -> tuple:
        """Receive frames, logging events, until we get a non-event response.
          'id' = guid, 'type' = FA.c id string, 'error'/'errorCode' for responses.
        """
        while True:
            _, proto, payload = await self._recv(timeout=timeout)
            hdr, body = unpack_msg(payload)
            log.debug("response header: %s", hdr)
            log.debug("response body: %r", body)
            msg_type = hdr.get("type", "")
            if msg_type == "event":
                log.info(f"[event] {hdr.get('name', '')} {body[:80]}")
                continue
            error_code = hdr.get("errorCode", 0)
            error_msg  = hdr.get("error", "")
            if error_code and error_code != 0:
                raise RuntimeError(f"Device error {error_code}: {error_msg}")
            return hdr, body

    async def shell(self, cmd: str, timeout: float = 30.0) -> str:
        guid = self._new_guid()
        await self._send(PROTO_BINARY, pack_cmd_msg(guid, cmd))
        _, body = await self._recv_response(timeout=timeout)
        return body.decode("utf-8", errors="replace")

    # -----------------------------------------------------------------------
    # Config operations
    # -----------------------------------------------------------------------

    async def read_config(self) -> dict:
        log.info("Reading config...")
        resp = await self.shell("cat /tmp/system.cfg | gzip | base64")
        return decode_config_b64(resp.strip())

    async def write_config(self, cfg: dict):
        encoded = encode_config(cfg)
        log.info("Writing config...")
        await self.shell(f"echo {encoded} | base64 -d | gunzip  > /tmp/system.cfg")

    async def apply_config(self):
        log.info("Applying config...")
        await self.shell("syswrapper.sh apply-config")

    async def set_ssh(self, enabled: bool):
        cfg = await self.read_config()
        cfg["sshd.status"] = "enabled" if enabled else "disabled"
        log.info(f"sshd.status -> {cfg['sshd.status']}")
        await self.write_config(cfg)
        await self.apply_config()


# ---------------------------------------------------------------------------
# Connection  (fixed: callback-based scan + forced LE connect)
# ---------------------------------------------------------------------------

async def find_and_connect(target: Optional[str], user: str, pw: Optional[str]) -> UtrSession:
    log.info("Searching for UTR over LE...")
    target_clean = target.replace(":", "").lower() if target else None
    if not target_clean:
        log.warning("No address specified — will connect to the first UTR device found")
    target_dev = None
    stop_event = asyncio.Event()

    identity_mac = None

    def detection_callback(dev, adv):
        nonlocal target_dev, identity_mac
        if target_dev:
            return
        if SERVICE_DATA_UUID in adv.service_data:
            raw = adv.service_data[SERVICE_DATA_UUID]
            identity = "".join(f"{b:02x}" for b in raw)
            if not target_clean or target_clean == identity:
                target_dev = dev
                identity_mac = ":".join(f"{b:02X}" for b in raw)
                log.info("Found UTR %s", identity_mac)
                stop_event.set()

    scanner = BleakScanner(
        detection_callback,
        scanning_mode="active",
        bluez={"filters": {"Transport": "le", "DuplicateData": True}},
    )

    await scanner.start()
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=15.0)
    except asyncio.TimeoutError:
        pass
    await scanner.stop()

    if not target_dev:
        raise RuntimeError("UTR not found based on provided Identity.")

    # Give BlueZ time to fully tear down the scan before issuing a connection
    # request — without this pause, BlueZ may dispatch a BR/EDR Create Connection
    # instead of LE Create Connection for public-address devices.
    await asyncio.sleep(1.0)

    client = BleakClient(
        target_dev,
        timeout=20.0,
        bluez={"address_type": "public"},
    )
    log.info(f"Connecting to {identity_mac}...")
    try:
        await client.connect()
    except (TimeoutError, asyncio.TimeoutError):
        if sys.platform.startswith("linux"):
            log.error(
                f"Connection to {identity_mac} timed out. BlueZ may have attempted "
                f"a BR/EDR connection instead of LE. "
                f"Fix: set 'ControllerMode = le' in /etc/bluetooth/main.conf "
                f"and restart bluetooth, or run: sudo btmgmt bredr off"
            )
        else:
            log.error(f"Connection to {identity_mac} timed out.")
        sys.exit(1)
    except BaseException as e:
        log.error(f"Connection to {identity_mac} failed: {e}")
        sys.exit(1)
    log.info(f"Connected to {identity_mac}")

    s = UtrSession(client=client)
    await client.start_notify(UUID_READ, s._on_notify)
    await s.transport_handshake()
    await s.shell_authenticate(user, pw)
    return s


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def main():
    import argparse

    p = argparse.ArgumentParser(description="UniFi Travel Router BLE config tool")
    p.add_argument("--address",  help="Identity MAC from sticker or scan")
    p.add_argument("--user", default="ui", help="Shell username (default: ui)")
    p.add_argument("--password", default=None,
                   help="Device admin password (omit if no password has been set)")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")

    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan", help="Continuous scan for UTRs (Ctrl+C to stop)")
    sub.add_parser("dump", help="Print all config keys")

    sp = sub.add_parser("ssh", help="Enable or disable SSH")
    sp.add_argument("state", choices=["on", "off"])

    sp2 = sub.add_parser("set", help="Set a config key")
    sp2.add_argument("key"); sp2.add_argument("value")

    sp3 = sub.add_parser("run", help="Run an arbitrary shell command")
    sp3.add_argument("command", nargs=argparse.REMAINDER)

    args = p.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    if args.cmd == "scan":
        log.info("Scan started (Identity MACs only). Press Ctrl+C to stop.")
        seen = set()
        try:
            async with BleakScanner(
                scanning_mode="active",
                bluez={"filters": {"Transport": "le", "DuplicateData": True}},
            ) as scanner:
                while True:
                    found = False
                    for dev, adv in scanner.discovered_devices_and_advertisement_data.values():
                        if SERVICE_DATA_UUID in adv.service_data:
                            identity = ":".join(f"{b:02X}" for b in adv.service_data[SERVICE_DATA_UUID])
                            if identity not in seen:
                                seen.add(identity)
                                print(f"[{time.strftime('%H:%M:%S')}] UTR Identity: {identity} | RSSI: {adv.rssi} dBm")
                            found = True
                    if not found:
                        print(f"[{time.strftime('%H:%M:%S')}] Scanning...", end="\r")
                    await asyncio.sleep(3.0)
        except KeyboardInterrupt:
            print("\nScan stopped.")
        return

    session = await find_and_connect(args.address, args.user, args.password)
    try:
        if args.cmd == "dump":
            for k, v in sorted((await session.read_config()).items()):
                print(f"{k}={v}")

        elif args.cmd == "ssh":
            await session.set_ssh(args.state == "on")

        elif args.cmd == "set":
            cfg = await session.read_config()
            cfg[args.key] = args.value
            await session.write_config(cfg)
            await session.apply_config()

        elif args.cmd == "run":
            print(await session.shell(" ".join(args.command)))

    except Exception as e:
        if log.isEnabledFor(logging.DEBUG):
            log.exception(f"Error: {e}")
        else:
            log.error(f"Error: {e}")
        sys.exit(1)
    finally:
        await session.client.stop_notify(UUID_READ)
        await session.client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
