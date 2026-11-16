import json
import socket
import threading
import zlib

import pytest

import device_sim as sim


def provision_line(payload: dict) -> str:
    body = json.dumps(payload)
    return f"PROVISION {body} {zlib.crc32(body.encode()):08x}"


PAYLOAD = {
    "fleet_id": 100,
    "device_type": "sensor",
    "kit_secret": "maple river otter tango zinc",
    "device_password": "x7Kp2mQr9wLt",
    "config": {"channel": 3},
}


@pytest.fixture
def device(tmp_path):
    return sim.Device(tmp_path / "dev.json", "sensor", "none", True)


def ok(reply):
    assert reply.startswith("OK "), reply
    return json.loads(reply[3:])


def test_hello_unprovisioned(device):
    h = ok(sim.handle_line(device, "HELLO"))
    assert h["provisioned"] is False and h["fleet_id"] is None
    assert h["serial"].startswith("SN-") and h["protocol"] == 1


def test_provision_readback_decommission(device):
    ok(sim.handle_line(device, provision_line(PAYLOAD)))
    rb = ok(sim.handle_line(device, "READBACK"))
    assert rb["fleet_id"] == 100 and rb["config"] == {"channel": 3}
    assert rb["kit_secret_check"] == sim.kit_secret_check(PAYLOAD["kit_secret"])
    assert "kit_secret" not in rb and "device_password" not in rb
    assert sim.handle_line(device, provision_line(PAYLOAD)).startswith("ERR ALREADY_PROVISIONED")
    assert sim.handle_line(device, "DECOMMISSION 99").startswith("ERR CONFIRM")
    ok(sim.handle_line(device, "DECOMMISSION 100"))
    assert ok(sim.handle_line(device, "HELLO"))["provisioned"] is False


def test_state_survives_restart(tmp_path):
    d = sim.Device(tmp_path / "dev.json", "sensor", "none", True)
    ok(sim.handle_line(d, provision_line(PAYLOAD)))
    d2 = sim.Device(tmp_path / "dev.json", "gateway", "none", True)
    h = ok(sim.handle_line(d2, "HELLO"))
    assert h["provisioned"] and h["serial"] == d.state["serial"] and h["device_type"] == "sensor"


@pytest.mark.parametrize(
    "line, code",
    [
        ("PROVISION {} 00000000", "CRC"),
        ("PROVISION nocrc", "BAD_FORMAT"),
        (provision_line({**PAYLOAD, "device_type": "gateway"}), "WRONG_TYPE"),
        (provision_line({**PAYLOAD, "fleet_id": 0}), "BAD_PAYLOAD"),
        (provision_line({**PAYLOAD, "kit_secret": ""}), "BAD_PAYLOAD"),
        ("READBACK", "NOT_PROVISIONED"),
        ("FLY", "UNKNOWN"),
    ],
)
def test_errors(device, line, code):
    assert sim.handle_line(device, line).startswith(f"ERR {code} ")


def test_fault_bad_crc_once(tmp_path):
    d = sim.Device(tmp_path / "dev.json", "sensor", "bad_crc", True)
    assert sim.handle_line(d, provision_line(PAYLOAD)).startswith("ERR CRC")
    ok(sim.handle_line(d, provision_line(PAYLOAD)))


def test_fault_silent(tmp_path):
    d = sim.Device(tmp_path / "dev.json", "sensor", "silent", True)
    assert sim.handle_line(d, provision_line(PAYLOAD)) is None
    assert ok(sim.handle_line(d, "HELLO"))["provisioned"] is False


def test_fault_reboot_leaves_unprovisioned(tmp_path):
    d = sim.Device(tmp_path / "dev.json", "sensor", "reboot", True)
    with pytest.raises(sim.Reboot):
        sim.handle_line(d, provision_line(PAYLOAD))
    assert ok(sim.handle_line(d, "HELLO"))["provisioned"] is False


def test_over_tcp(tmp_path):
    d = sim.Device(tmp_path / "dev.json", "sensor", "reboot", True)
    srv = sim.make_server("127.0.0.1", 0, d)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s, s.makefile("rw") as f:
            assert f.readline().startswith("BOOT ")
            f.write(provision_line(PAYLOAD) + "\n"); f.flush()
            assert f.readline() == ""  # connection dropped by the reboot
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s, s.makefile("rw") as f:
            f.readline()
            f.write(provision_line(PAYLOAD) + "\n"); f.flush()
            assert ok(f.readline().strip())["fleet_id"] == 100
    finally:
        srv.shutdown(); srv.server_close()
