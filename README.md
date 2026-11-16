# Fleet Provisioning: materials for the assignment

What's in this repository:

| Path | What it is |
|---|---|
| `simulator/device_sim.py` | A simulated device. One process is one physical device. Talks over TCP, standing in for a USB serial port. |
| `escrow/escrow.py` | Helper for encrypting secrets to the escrow key. You can use it or write your own; either way, you are responsible for the result. |
| `keys/TEST_ONLY_escrow_*.pem` | Test escrow key pair, RSA-3072. In production the private key lives offline only. |
| `wordlist/words.txt` | 256 words for the kit secret (5 words = 40 bits). |
| `tests/` | Tests for the materials above. |

## Running it

```bash
uv sync
uv run pytest
uv run python simulator/device_sim.py --port 7700 --type sensor
uv run python simulator/device_sim.py --port 7701 --type gateway --fault reboot
```

Each device keeps its state in `device-<port>.json` (or the file given with `--state`), so the state survives a restart, the way flash survives a power cycle. Delete the file to get a factory-new device with a new serial.

## Device protocol

The protocol is UTF-8 text, one command per line, ending with `\n`, and a line can be at most 4096 bytes. When you connect, the device sends `BOOT fw=<version> protocol=<n>`.

Every reply is one line, either `OK <json>` or `ERR <CODE> <text>`.

| Command | When | Reply |
|---|---|---|
| `HELLO` | always | `serial`, `device_type`, `fw_version`, `protocol`, `provisioned`, `fleet_id` (or `null`) |
| `PROVISION <json> <crc32>` | unprovisioned only | `{"fleet_id": N}`; the identity is written atomically |
| `READBACK` | provisioned | `serial`, `device_type`, `fleet_id`, `config`, `kit_secret_check`, `fw_version`. Secrets are never returned. |
| `DECOMMISSION <fleet_id>` | provisioned | `{}`; the identity is erased. Repeating the `fleet_id` is the confirmation. |

`PROVISION` payload, followed by the CRC-32 of the JSON bytes exactly as sent, as 8 hex digits:

```json
{"fleet_id": 100, "device_type": "sensor", "kit_secret": "five words from the list",
 "device_password": "12 characters", "config": {}}
```

`kit_secret_check` is the first 8 hex digits of `SHA-256("kit-check:" + kit_secret)`. It lets you check that the secret was written correctly without reading the secret back.

Error codes: `CRC`, `BAD_FORMAT`, `BAD_JSON`, `BAD_PAYLOAD`, `WRONG_TYPE`, `ALREADY_PROVISIONED`, `NOT_PROVISIONED`, `CONFIRM`, `UNKNOWN`, `TOO_LONG`.

## Fault modes

Set a fault mode with `--fault`. It applies to the first `PROVISION` only; add `--fault-always` to make it apply to every `PROVISION`.

| Mode | Behaviour |
|---|---|
| `silent` | No reply, and nothing is written. |
| `bad_crc` | `ERR CRC`, even when the CRC is correct. |
| `reboot` | The connection drops before the write. The device stays unprovisioned. |
