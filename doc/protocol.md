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

Response: { "auth": {"id":"6","salt":"Dk5MxT/s","type":3}, "key":
"`<hex>`{=html}" }

------------------------------------------------------------------------

## Password Hashing

The UTR uses standard Linux `$6$` SHA-512 crypt (sha512-crypt).

Example:

$6$Dk5MxT/s\$odfXltkvaLfU0ANt52iOcqatZrOZrETUAsaeLa01w7Cua2MA7NOVmlk6BFcKdUTVbNu0O1LAvneWI0t8OL2Ac1

IMPORTANT: - Only the final hash field is used:
odfXltkvaLfU0ANt52iOcqatZrOZrETUAsaeLa01w7Cua2MA7NOVmlk6BFcKdUTVbNu0O1LAvneWI0t8OL2Ac1 -
The "$6$" prefix and salt are NOT included in the payload - Default
rounds = 5000 - Salt is provided by the device during hdshkStart

Python example:

from passlib.hash import sha512_crypt hash =
sha512_crypt.using(salt="Dk5MxT/s", rounds=5000).hash("ui") hash_field =
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
