"""Integration tests that run the framework against the real, compiled C
device simulator over a real TCP socket - not InMemoryDevice, not a mock.

Marked `integration` so they can be skipped for a fast unit-test-only run:
    pytest -m "not integration"
"""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

import pytest

from attack_orchestrator import (
    Attack,
    BestOddsSelector,
    DeviceConnectionError,
    Extractor,
    NoViableAttackError,
    Orchestrator,
    RemoteDevice,
    Requirements,
    Stage,
)

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parent.parent
SIMULATOR_DIR = REPO_ROOT / "device_simulator"
SIMULATOR_BIN = SIMULATOR_DIR / "device_simulator"

_CLI_FLAGS = {
    "device_id": "--device-id",
    "model": "--model",
    "ios_version": "--ios-version",
    "battery": "--battery",
    "seed": "--seed",
    "drop_on_stage": "--drop-on-stage",
}


def _ensure_built() -> None:
    if SIMULATOR_BIN.exists():
        return
    result = subprocess.run(["make"], cwd=SIMULATOR_DIR, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"failed to build device_simulator:\n{result.stdout}\n{result.stderr}")


def _free_port() -> int:
    # Bind to port 0 to let the OS hand back an unused port, then release it
    # immediately so the simulator subprocess can bind it a moment later.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_accepting(proc: subprocess.Popen, host: str, port: int, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"simulator exited early (code {proc.returncode}): {stderr}")
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.02)
    raise RuntimeError(f"simulator on port {port} never started accepting connections: {last_error}")


@pytest.fixture
def simulator():
    """Factory fixture: call to start a real device_simulator subprocess.

    Returns (host, port). Each call starts an independent process on its own
    port; all of them are torn down at the end of the test.

        host, port = simulator(battery=5, model="iPhone8,1")
        host, port = simulator(files={"/a": "hello"}, drop_on_stage="boom")

    Lives in this file rather than conftest.py since it's the only test file
    that needs it - conftest.py earns its keep once a fixture is shared
    across multiple test files, not before.
    """
    _ensure_built()
    procs: list[subprocess.Popen] = []

    def _start(**options) -> tuple[str, int]:
        port = _free_port()
        args = [str(SIMULATOR_BIN), "--port", str(port)]

        if options.pop("jailbroken", False):
            args.append("--jailbroken")
        for path, content in options.pop("files", {}).items():
            args += ["--file", f"{path}={content}"]
        for key, value in options.items():
            flag = _CLI_FLAGS.get(key)
            if flag is None:
                raise ValueError(f"unknown simulator option: {key}")
            args += [flag, str(value)]

        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        procs.append(proc)
        _wait_until_accepting(proc, "127.0.0.1", port)
        return "127.0.0.1", port

    yield _start

    for proc in procs:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def test_info_reports_the_configured_device(simulator):
    host, port = simulator(
        device_id="dev-42", model="iPhone8,1", ios_version="14.2", battery=55, jailbroken=True
    )

    with RemoteDevice(host, port) as device:
        info = device.get_info()

    assert info.device_id == "dev-42"
    assert info.model == "iPhone8,1"
    assert info.ios_version == "14.2"
    assert info.battery_percent == 55
    assert info.jailbroken is True


def test_successful_chain_unlocks_and_reads_the_right_bytes(simulator):
    host, port = simulator(files={"/loot": "top secret contents"})
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0), Stage("s2", 1.0)))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])
        assert result.success is True
        assert result.session.read_file("/loot") == b"top secret contents"


def test_read_is_refused_before_any_stage_has_run(simulator):
    host, port = simulator(files={"/loot": "secret"})

    with RemoteDevice(host, port) as device:
        with pytest.raises(PermissionError):
            device.read_file("/loot")


def test_failed_stage_aborts_the_chain_and_device_stays_locked(simulator):
    host, port = simulator(files={"/loot": "secret"})
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0), Stage("s2", 0.0), Stage("s3", 1.0)))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])
        assert result.success is False
        assert result.session is None
        assert len(result.stage_records) == 2  # s3 never ran

        # The device itself refuses to read, not just the orchestrator's bookkeeping.
        with pytest.raises(PermissionError):
            device.read_file("/loot")


def test_reading_an_unknown_path_after_unlock_is_not_found(simulator):
    host, port = simulator()
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0),))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])
        assert result.success is True
        with pytest.raises(FileNotFoundError):
            result.session.read_file("/does/not/exist")


def test_dropped_connection_mid_chain_is_reported_distinctly(simulator):
    host, port = simulator(drop_on_stage="boom")
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0), Stage("boom", 1.0), Stage("s3", 1.0)))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])

    assert result.success is False
    assert result.session is None
    assert "connection lost" in result.failure_reason
    assert len(result.stage_records) == 1  # s1 succeeded and was recorded; "boom" never replied


def test_no_viable_attack_for_a_real_device_that_fails_requirements(simulator):
    host, port = simulator(battery=5)
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0),), requirements=Requirements(min_battery=50))

    with RemoteDevice(host, port) as device:
        with pytest.raises(NoViableAttackError):
            Orchestrator(BestOddsSelector()).run(device, [attack])


def test_selector_picks_the_attack_that_actually_fits_the_real_device(simulator):
    host, port = simulator(model="iPhone14,5", ios_version="16.1", battery=50)
    wrong_model = Attack(
        "wrong-model", "Wrong model", stages=(Stage("s1", 1.0),),
        requirements=Requirements(models=frozenset({"iPhone8,1"})),
    )
    low_odds = Attack("low-odds", "Low odds", stages=(Stage("s1", 0.1), Stage("s2", 0.1)))
    high_odds = Attack("high-odds", "High odds", stages=(Stage("s1", 0.9), Stage("s2", 0.9)))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [wrong_model, low_odds, high_odds])

    assert result.attack.attack_id == "high-odds"


def test_extract_all_against_the_real_simulator(simulator, tmp_path):
    files = {"/a": "aaa contents", "/b": "bbb contents"}
    host, port = simulator(files=files)
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0),))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])
        assert result.success
        report = Extractor(result.session).extract_all(tmp_path, paths=["/a", "/b", "/missing"])

    assert report.success_count == 2
    assert report.error_count == 1
    assert report.extracted["/a"].read_bytes() == b"aaa contents"
    assert report.extracted["/b"].read_bytes() == b"bbb contents"


def test_read_response_is_byte_exact_even_with_embedded_newlines(simulator):
    # Proves the length-prefixed READ framing actually matters: a naive
    # readline()-based client would stop at the embedded '\n' and truncate
    # or desync the connection.
    tricky_content = "line one\nline two\nline three"
    host, port = simulator(files={"/tricky": tricky_content})
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0),))

    with RemoteDevice(host, port) as device:
        result = Orchestrator(BestOddsSelector()).run(device, [attack])
        data = result.session.read_file("/tricky")

    assert data == tricky_content.encode("utf-8")


def test_simulator_tolerates_garbage_input_without_crashing(simulator):
    host, port = simulator()

    with socket.create_connection((host, port), timeout=2) as sock:
        sock.sendall(b"NOT_A_REAL_COMMAND\n")
        reply = sock.recv(200)
        assert reply == b"ERR bad_request\n"

        # The connection - and the process - should still be usable afterwards.
        sock.sendall(b"INFO\n")
        reply = sock.recv(200)
        assert reply.startswith(b"INFO ")
