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

## Disclaimer

This tool is not officially supported by Ubiquiti. Use at your own risk.
