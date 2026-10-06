# UTR BLE Python Client

## Overview

This script connects to a **UniFi Travel Router (UTR)** over Bluetooth
Low Energy (BLE), performs the required cryptographic handshakes, and
allows you to:

-   Dump configuration
-   Modify settings
-   Run shell commands

------------------------------------------------------------------------

## Requirements

-   Python 3.9+
-   macOS or Linux (BLE support required)
-   Linux note: You may have to force low energy (LE) mode in BlueZ either by setting "ControllerMode = le" in /etc/bluetooth/main.conf or running: sudo btmgmt bredr off

### Python dependencies

``` bash
pip install bleak pynacl passlib msgpack
```

------------------------------------------------------------------------

## Usage

### Basic scan + dump

``` bash
python3 utr_ble_client.py dump
```

------------------------------------------------------------------------

### Specify device address

``` bash
python3 utr_ble_client.py --address <BLE_ADDR> dump
```

------------------------------------------------------------------------

### Enable verbose debugging

``` bash
python3 utr_ble_client.py --verbose dump
```

------------------------------------------------------------------------

### Provide credentials

``` bash
python3 utr_ble_client.py --user ui --password ui dump
```

Notes: - Default username: `ui` - Default password: `ui` (if unset on
device)

------------------------------------------------------------------------

## Commands

### Dump configuration

``` bash
python3 utr_ble_client.py dump
```

------------------------------------------------------------------------

### Enable / disable SSH

``` bash
python3 utr_ble_client.py ssh on
python3 utr_ble_client.py ssh off
```

------------------------------------------------------------------------

### Set a configuration value

``` bash
python3 utr_ble_client.py set <key> <value>
```

------------------------------------------------------------------------

### Run shell command

``` bash
python3 utr_ble_client.py run <command>
```

Example:

``` bash
python3 utr_ble_client.py run uname -a
```

------------------------------------------------------------------------

## How it Works (High Level)

1.  BLE connect
2.  Transport Diffie-Hellman handshake
3.  Encrypted tunnel established
4.  Shell authentication (SHA512-crypt + X25519)
5.  Commands executed inside encrypted session

------------------------------------------------------------------------

## Common Issues

### Device not found

-   Ensure BLE is enabled
-   Move closer to device
-   Try specifying address manually

------------------------------------------------------------------------

### Authentication failure ("Bad secret")

-   Check username/password
-   Ensure password matches device
-   Ensure correct SHA512-crypt handling

------------------------------------------------------------------------

### Disconnects / write errors

-   BLE on macOS can be unstable
-   Retry connection
-   Ensure no other app is connected

------------------------------------------------------------------------

## Notes

-   All communication is encrypted
-   Uses standard crypto primitives:
    -   X25519
    -   BLAKE2b
    -   XSalsa20-Poly1305
    -   SHA512-crypt

------------------------------------------------------------------------

## Browser Client (Web Bluetooth)

A single-file, no-build browser port lives at
[`web/utr_ble_client.html`](web/utr_ble_client.html). It reimplements the
entire protocol stack in JavaScript (msgpack, Curve25519, BLAKE2b,
SHA512-crypt, BTLEv2 + UiCommV4 framing) and talks to the device over
**Web Bluetooth**. The crypto is verified against the same test vectors
and produces byte-identical session keys to the Python client. Its
libraries are bundled in the file, so it works without internet.

### Running it

A hosted copy is at **https://divinehawk.github.io/utr/**. It's
published from `web/` by the Pages workflow on every push to `main`,
and runs entirely in your browser; nothing is sent to the server.

To run it yourself, open it over a secure context — `https://`,
`http://localhost`, or a local static server:

``` bash
cd web && python3 -m http.server 8777
# then open http://localhost:8777/utr_ble_client.html
```

Click **Connect** and pick the router from the browser chooser. The
chooser only lists devices advertising a UTR or UTR-LR service (each
model uses a different service UUID before and after adoption; see
[`doc/protocol.md`](doc/protocol.md#advertisement)). The app then runs the
handshake and loads the config. Features:

- Searchable, editable **config editor** with pending-change tracking,
  add/delete keys, and export / import of `system.cfg`. Changes are
  written in small chunks, read back and verified, and only then
  applied.
- A **shell** with command history, quick-command chips, and copy.
- A live **dashboard**: internet and uplink status, CPU, memory, uptime,
  Wi-Fi networks, radios, VPN states, device details and a clients
  table. It polls the router's `utrv2` status command every 10 seconds
  (the command the official app polls) and `mca-dump` once a minute,
  and warns in the config editor if the router's config changes after
  you loaded it.
- An SSH on/off switch that shows the router's current setting, and a
  log tab.
- A **firmware** tab for units running the OpenWrt port alongside stock
  (see below).
- Light and dark themes (follows the OS; toggle in the sidebar).

### Firmware tab

The OpenWrt port installs itself in the `kernel1` slot and leaves stock in
`kernel0`; a small `bs` partition picks which one boots. The tab reads
which firmware is running, what each slot holds and where the selector
points, and offers what is safe from there:

| Running | Actions |
|---|---|
| OpenWrt (with utrd) | upgrade OpenWrt (sysupgrade, settings kept or not), switch to stock, back up / restore settings |
| Stock, OpenWrt installed | switch to OpenWrt, remove OpenWrt |
| Stock, no OpenWrt | upgrade stock, install OpenWrt |

Images are never sent over Bluetooth: the router downloads them itself,
and refuses one whose SHA-256 is not the expected one. Stock versions
come from Ubiquiti's firmware service, OpenWrt images from a GitHub
repository's releases, OpenWrt snapshots, or a URL with its SHA-256.

On OpenWrt the router's utrd does the work (`utr-fw` commands). On stock
the tab uploads a short script and runs stock's own tools; installing
OpenWrt writes and checks the slot and the boot chooser before the boot
selector moves, so a failure part way leaves stock booting.

Stock cannot be written from OpenWrt, and stock always upgrades into the
slot it is not running from, which is OpenWrt's. The tab's guide walks
through upgrading stock anyway: back up OpenWrt's settings to the
browser, remove OpenWrt, upgrade stock twice (once into `kernel1`, once
back into `kernel0`), reinstall OpenWrt and restore the settings. TFTP
recovery, which always writes `kernel0`, is the way that keeps OpenWrt.

The firmware logic is tested without a router, its stock-side scripts run
for real under busybox and dash against a fake one:

``` bash
node --test web/test/
```

### Platform support

- Works: Chrome / Edge on desktop (macOS, Windows, Linux) and Android.
- Does **not** work: Safari (all platforms) and any browser on iOS —
  Apple does not implement Web Bluetooth.

See [`doc/protocol.md`](doc/protocol.md#web-bluetooth-port-webutr_ble_clienthtml)
for the porting notes and Web Bluetooth limitations.

------------------------------------------------------------------------

## Disclaimer

This tool is not officially supported by Ubiquiti. Use at your own risk.
