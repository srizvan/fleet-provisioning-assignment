"""Simulated field device for the provisioning assignment.

Speaks a line protocol over TCP (stand-in for a USB serial port). See README.md.
One process = one physical device. State is kept in a JSON file so it survives
restarts, like flash memory survives a power cycle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import socketserver
import threading
import zlib
from pathlib import Path

PROTOCOL_VERSION = 1
FW_VERSION = "1.4.2"
MAX_LINE = 4096

FAULTS = ("none", "silent", "bad_crc", "reboot")


def kit_secret_check(kit_secret: str) -> str:
    """Non-secret 8-hex-digit check value of a kit secret, reported by READBACK."""
    return hashlib.sha256(b"kit-check:" + kit_secret.encode()).hexdigest()[:8]


class Device:
    def __init__(self, state_path: Path, device_type: str, fault: str, fault_once: bool):
        self.state_path = state_path
        self.fault = fault
        self.fault_once = fault_once
        self.lock = threading.Lock()
        if state_path.exists():
            self.state = json.loads(state_path.read_text())
        else:
            self.state = {
                "serial": "SN-" + secrets.token_hex(4).upper(),
                "device_type": device_type,
                "identity": None,
            }
            self._save()

    def _save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state))
        tmp.replace(self.state_path)

    def _take_fault(self, name: str) -> bool:
        if self.fault != name:
            return False
        if self.fault_once:
            self.fault = "none"
        return True

    def hello(self) -> dict:
        ident = self.state["identity"]
        return {
            "serial": self.state["serial"],
            "device_type": self.state["device_type"],
            "fw_version": FW_VERSION,
            "protocol": PROTOCOL_VERSION,
            "provisioned": ident is not None,
            "fleet_id": ident["fleet_id"] if ident else None,
        }

    def readback(self) -> dict:
        ident = self.state["identity"]
        if ident is None:
            raise ProtocolError("NOT_PROVISIONED", "device is not provisioned")
        return {
            "serial": self.state["serial"],
            "device_type": self.state["device_type"],
            "fleet_id": ident["fleet_id"],
            "config": ident["config"],
            "kit_secret_check": kit_secret_check(ident["kit_secret"]),
            "fw_version": FW_VERSION,
        }

    def provision(self, arg: str) -> dict | None:
        if self.state["identity"] is not None:
            raise ProtocolError("ALREADY_PROVISIONED", "decommission first")
        try:
            body, crc_hex = arg.rsplit(" ", 1)
            crc = int(crc_hex, 16)
        except ValueError:
            raise ProtocolError("BAD_FORMAT", "expected: PROVISION <json> <crc32-hex>")
        if zlib.crc32(body.encode()) != crc or self._take_fault("bad_crc"):
            raise ProtocolError("CRC", "crc mismatch")
        try:
            p = json.loads(body)
        except json.JSONDecodeError:
            raise ProtocolError("BAD_JSON", "payload is not valid JSON")
        _validate(p, self.state["device_type"])
        if self._take_fault("silent"):
            return None  # no reply, nothing written
        if self._take_fault("reboot"):
            raise Reboot()  # power lost before the write: stays unprovisioned
        self.state["identity"] = {
            "fleet_id": p["fleet_id"],
            "kit_secret": p["kit_secret"],
            "device_password": p["device_password"],
            "config": p.get("config", {}),
        }
        self._save()
        return {"fleet_id": p["fleet_id"]}

    def decommission(self, arg: str) -> dict:
        ident = self.state["identity"]
        if ident is None:
            raise ProtocolError("NOT_PROVISIONED", "device is not provisioned")
        if arg.strip() != str(ident["fleet_id"]):
            raise ProtocolError("CONFIRM", "repeat the device's fleet_id to confirm")
        self.state["identity"] = None
        self._save()
        return {}


def _validate(p: object, device_type: str) -> None:
    if not isinstance(p, dict):
        raise ProtocolError("BAD_PAYLOAD", "payload must be an object")
    fid = p.get("fleet_id")
    if not isinstance(fid, int) or not 1 <= fid <= 65535:
        raise ProtocolError("BAD_PAYLOAD", "fleet_id must be an integer 1..65535")
    if p.get("device_type") != device_type:
        raise ProtocolError("WRONG_TYPE", f"this device is a {device_type}")
    for key in ("kit_secret", "device_password"):
        if not isinstance(p.get(key), str) or not p[key]:
            raise ProtocolError("BAD_PAYLOAD", f"{key} must be a non-empty string")
    if not isinstance(p.get("config", {}), dict):
        raise ProtocolError("BAD_PAYLOAD", "config must be an object")


class ProtocolError(Exception):
    def __init__(self, code: str, text: str):
        super().__init__(text)
        self.code = code
        self.text = text


class Reboot(Exception):
    pass


def handle_line(device: Device, line: str) -> str | None:
    """Return the reply line (without newline), or None for no reply."""
    cmd, _, arg = line.partition(" ")
    try:
        with device.lock:
            if cmd == "HELLO":
                result = device.hello()
            elif cmd == "READBACK":
                result = device.readback()
            elif cmd == "PROVISION":
                result = device.provision(arg)
            elif cmd == "DECOMMISSION":
                result = device.decommission(arg)
            else:
                raise ProtocolError("UNKNOWN", f"unknown command {cmd!r}")
    except ProtocolError as e:
        return f"ERR {e.code} {e.text}"
    if result is None:
        return None
    return "OK " + json.dumps(result, separators=(",", ":"))


def make_server(host: str, port: int, device: Device) -> socketserver.ThreadingTCPServer:
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.wfile.write(f"BOOT fw={FW_VERSION} protocol={PROTOCOL_VERSION}\n".encode())
            while True:
                raw = self.rfile.readline(MAX_LINE + 1)
                if not raw:
                    return
                if len(raw) > MAX_LINE:
                    self.wfile.write(b"ERR TOO_LONG line exceeds 4096 bytes\n")
                    return
                try:
                    reply = handle_line(device, raw.decode().rstrip("\r\n"))
                except Reboot:
                    return  # connection drops, like a USB port during a reset
                except UnicodeDecodeError:
                    reply = "ERR BAD_FORMAT not UTF-8"
                if reply is not None:
                    self.wfile.write((reply + "\n").encode())

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((host, port), Handler)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=7700)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--type", choices=("sensor", "gateway"), default="sensor")
    ap.add_argument("--state", type=Path, default=None, help="state file (default: device-<port>.json)")
    ap.add_argument("--fault", choices=FAULTS, default="none")
    ap.add_argument("--fault-always", action="store_true", help="fault on every PROVISION, not just the first")
    a = ap.parse_args()
    device = Device(a.state or Path(f"device-{a.port}.json"), a.type, a.fault, not a.fault_always)
    print(f"device {device.state['serial']} ({device.state['device_type']}) on {a.host}:{a.port}, fault={a.fault}")
    with make_server(a.host, a.port, device) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
