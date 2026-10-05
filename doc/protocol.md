# UniFi Travel Router (UTR) BLE Protocol Documentation

## Overview

The UniFi Travel Router (UTR) uses a **two-layer encrypted BLE
protocol**:

1.  **Transport Layer (DH handshake)**
2.  **Shell Authentication Layer**

All communication is encrypted.

------------------------------------------------------------------------

## BLE Characteristics

-   READ (notify): d587c47f-ac6e-4388-a31c-e6cd380ba043\
-   WRITE: 9280f26c-a56f-43ea-b769-d5d732e1ac67

------------------------------------------------------------------------

## Frame Format

\[ total_len: 2B BE \]\[ encrypted_payload \]

Decrypted:

\[ seq:2 \]\[ proto:1 \]\[ payload \]

Encryption: XSalsa20-Poly1305 (NaCl SecretBox)

------------------------------------------------------------------------

## Protocol Types

-   0x00 = AUTH (transport)
-   0x03 = BINARY_MESSAGE (shell)

------------------------------------------------------------------------

## MAGIC VALUES / CONSTANTS

DEFAULT_KEY (transport bootstrap key):
a781f8a4a627373b70745738cdffdd1de9ae352517c374ca9afc

Shell nonce start: 1969385077

SHA512-crypt rounds: 5000

Encoding: - pubKey = HEX (not base64) - compression = zlib (not gzip)

------------------------------------------------------------------------

## Transport Handshake

Client → Device: \["DHPK", false, client_pub\]

Device → Client: \["DHPK", flag, server_pub\]

Key derivation: shared = X25519(client_priv, server_pub) session_key =
BLAKE2b(shared \|\| client_pub \|\| server_pub)

Mutual confirm: \["AUTH","DH"\]

------------------------------------------------------------------------

## Shell Authentication

hdshkStart: { "username": "ui", "pubKey": "`<hex>`{=html}" }

Response: { "auth": {"id":"6","salt":"examplesalt","type":3}, "key":
"`<hex>`{=html}" }

------------------------------------------------------------------------

## Password Hashing

The UTR uses standard Linux `$6$` SHA-512 crypt (sha512-crypt).

Example:

$6$examplesalt\$OWkVUq1OcxZhWcSG7E6eg0.3YvhufXqTtq1ijHDWLSkJUYxlhwERFwTcpe8ff7R3zVqpyWSydzKZ29tRNzrwA/

IMPORTANT: - Only the final hash field is used:
OWkVUq1OcxZhWcSG7E6eg0.3YvhufXqTtq1ijHDWLSkJUYxlhwERFwTcpe8ff7R3zVqpyWSydzKZ29tRNzrwA/ -
The "$6$" prefix and salt are NOT included in the payload - Default
rounds = 5000 - Salt is provided by the device during hdshkStart

Python example:

from passlib.hash import sha512_crypt hash =
sha512_crypt.using(salt="examplesalt", rounds=5000).hash("ui") hash_field =
hash.split("\$")\[-1\]

------------------------------------------------------------------------

## hdshkFinish

shell_shared = X25519(shell_priv, device_pub) shell_key =
BLAKE2b(shell_shared)

secret = encrypt( key = SHA256(transport_local_pub), plaintext =
shell_key )

Server check: decrypt == SHA256(transport_server_pub)

------------------------------------------------------------------------

## Nonce Behavior

Transport nonce starts at 0\
Shell nonce starts at 1969385077

------------------------------------------------------------------------

## UiComm / Binme Format

\[type:1\]\[format:1\]\[compress:1\]\[pad:1\]\[len:4\]\[data\]

Compression: - zlib (Deflate) - NOT gzip

------------------------------------------------------------------------

## Errors

3 = Invalid payload / bad key\
7 = Bad secret

------------------------------------------------------------------------

## Flow

BLE connect → Transport DH → Encrypted tunnel → Shell handshake →
Commands

------------------------------------------------------------------------

## Gotchas

-   pubKey must be HEX encoded (not base64)
-   SHA512-crypt must use correct salt + rounds
-   Only final hash field is used
-   zlib compression required
-   Shell nonce must start at 1969385077

------------------------------------------------------------------------

## Summary

The protocol is fully standard crypto primitives layered in a specific
way:

-   X25519 for key exchange
-   BLAKE2b for key derivation
-   XSalsa20-Poly1305 for encryption
-   SHA512-crypt for password authentication

The main difficulty is strict adherence to formatting and message
structure.

------------------------------------------------------------------------

## Web Bluetooth Port (`web/utr_ble_client.html`)

A single-file browser client in `web/` reimplements the full stack
(msgpack, Curve25519, BLAKE2b, SHA512-crypt, BTLEv2 + UiCommV4 framing)
in JavaScript and uses **Web Bluetooth** for the GATT transport. It is
kept protocol-identical to `python/utr_ble_client.py`.

### Platform support

-   Works: Chrome / Edge on desktop (macOS, Windows, Linux) and Android.
-   Does not work: Safari (all platforms) and any browser on iOS —
    Apple does not implement Web Bluetooth.
-   Requires a secure context: serve over `https://`, or open from
    `http://localhost` / `file://`.

### Advertisement

Observed UTR advertisement (bleak scan):

-   Service UUIDs: `69b6a9f0-b7fa-4f67-b188-1d001bd30123` (the GATT
    service is advertised).
-   The service UUID depends on the model and on whether the router is
    adopted. The firmware picks it from
    `/usr/share/unifi-anywhere/sys-db.txt`: the "factory-default" column
    while `mgmt.is_default` is not `false`, otherwise the
    "user-configured" column. The characteristics are the same in all
    of them.

    | Model  | System ID | Factory default                        | Adopted                                |
    |--------|-----------|----------------------------------------|----------------------------------------|
    | UTR    | `ea06`    | `69b6a9f0-b7fa-4f67-b188-1d001bd30123` | `f1d3710a-cc01-43ee-b433-340d79b8effb` |
    | UTR-LR | `ea08`    | `34aa91eb-a289-4655-a4f8-0a5571e5b208` | `0048f117-48e1-40bc-9da0-5544fc383f8d` |
-   Service data under `0x252A`: 6 bytes, the Identity MAC (what the
    Python scanner matches on).
-   No manufacturer data. The device name is `UTR`, but nothing relies
    on it.

### Differences from the Python client (Web Bluetooth limitations)

-   **Device chooser instead of a scan.** Web Bluetooth has no passive
    scan and cannot read advertisement contents, so the user picks the
    device in the browser's chooser. The chooser is filtered with
    one `{ services: [<service UUID>] }` filter per UUID in the table
    above, which lists only devices advertising one of them (no name
    matching). A service named in a filter is also accessible after
    connecting, and the client opens whichever one the device has.
    `serviceData` filters are in the spec but were rejected by current
    Chrome ("A filter must restrict the devices in some way"), so they
    are not used.
-   **512-byte write limit.** Chrome rejects any single characteristic
    write over 512 bytes. A full config as one
    `echo <b64> | base64 -d | gunzip > /tmp/system.cfg` command is
    several KB for a typical config, so the web client writes
    the config in stages:
    1.  `printf %s '<≤320 base64 chars>' >> /tmp/.utr_cfg.b64`, repeated
    2.  `base64 -d < /tmp/.utr_cfg.b64 | gunzip > /tmp/.utr_cfg.new`
    3.  read `/tmp/.utr_cfg.new` back and compare it with what was sent
    4.  only if it matches: `mv /tmp/.utr_cfg.new /tmp/system.cfg`, then
        `syswrapper.sh apply-config`

    A mismatch aborts before `system.cfg` is touched.
-   **One request at a time.** Responses are matched to requests in
    order, so the client serialises commands. After a receive timeout,
    a late response whose header `id` matches the abandoned request is
    discarded.
-   **Offline.** pako and tweetnacl are inlined (unmodified, versions
    and cdnjs SRI hashes noted in the file), so no internet is needed to
    connect.

### Status commands

Both run over the normal shell channel and print one JSON object.

-   **`utrv2`**: the status command the official app polls
    periodically. About 4-5 KB. Includes `internet`, `wan_table`
    (uplinks; the active one has `is_default_route`), `clients` (with
    hostname, IP and a `wifi` block: `signal` in dBm, `tx_rate` /
    `rx_rate` in kbps, byte counters, `uptime`), `broadcast_clients`
    (per-SSID counts), `lan_table` (radio channel/width),
    `system_stats` (`cpu`, `mem` as percent strings, `uptime` in
    seconds), `openvpn` / `wireguard` / `teleport` states,
    `ntp_synced`, `upgrade_state`, `apply_in_progress`, `version`,
    `model_display` and `cfg_md5`. Client counters are from the
    router's side: `tx_*` is traffic to the client.
-   **`mca-dump`**: the standard UniFi device dump. About 12 KB. Adds
    `serial`, `mac`, `kernel_version`, `architecture`, `sys_stats`
    (load averages, `mem_used` / `mem_total` in bytes), `gateway_ip`,
    `radio_table` (`radio` is `ng` for 2.4 GHz and `na` for 5 GHz;
    `athstats.noise_floor`, `athstats.cu_total` channel utilization,
    `athstats.satisfaction`, which is -1 when there is nothing to score)
    and `vap_table` (per-SSID channel, width, `num_sta`, `sta_table`).
    Client hostnames are only in `utrv2`.

The web client polls `utrv2` every 10 s and `mca-dump` every 60 s, both
quietly (no per-frame log lines) and never while a user action is
running.

### Protocol details that must match the Python reference

These are the points where an incorrect browser port silently fails:

-   Characteristic roles: subscribe (notify) on
    `d587c47f-…` (device → phone); write on `9280f26c-…`
    (phone → device).
-   Writes use **write-with-response** on `9280f26c`.
-   Transport auth-ok echoes the client pubkey:
    `["AUTH", "DH", client_pub]` (3-element array).
-   `hdshkStart` body is `{ "user": <name>, "key": <pubkey hex> }`.
-   Transport framing (`pack_action_msg` / `pack_cmd_msg`) uses **zlib**
    (`pako.deflate`); config transfer over the shell uses **gzip**.
