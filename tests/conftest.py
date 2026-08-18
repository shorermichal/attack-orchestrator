from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SIMULATOR_DIR = REPO_ROOT / "device_simulator"
SIMULATOR_BIN = SIMULATOR_DIR / "device_simulator"

_CLI_FLAGS = {
    "device_id": "--device-id",
    "model": "--model",
    "ios_version": "--ios-version",
    "battery": "--battery",
    "seed": "--seed",
    "drop_rate": "--drop-rate",
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
