from __future__ import annotations

import socket
from typing import Any

from .attack import Stage
from .device import Device, DeviceConnectionError, DeviceInfo, StageOutcome

_ENCODING = "utf-8"


class RemoteDevice(Device):
    """Talks to the C device simulator (or any device speaking the same
    protocol) over a single TCP connection.

    Wire format - one command per line, one line back per command, except a
    successful READ, which is followed by exactly `length` raw bytes:

      -> INFO
      <- INFO <device_id> <model> <ios_version> <battery_percent> <jailbroken:0/1>

      -> STAGE <name> <probability> <is_last:0/1>
      <- SUCCESS | FAILURE
         (or the connection is closed with no response, simulating a drop)

      -> READ <path>
      <- OK <length>\\n<raw bytes>   |   ERR locked   |   ERR not_found

      -> QUIT

    The device decides SUCCESS/FAILURE itself (given the probability), and
    only allows READ once it has seen a stage marked `is_last` succeed - the
    same rule `Orchestrator`/`DeviceSession` enforce on the Python side, now
    enforced by the thing actually holding the data.
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            raise DeviceConnectionError(f"could not connect to {host}:{port}: {exc}") from exc
        self._sock = sock
        self._reader = sock.makefile("rb")

    def close(self) -> None:
        try:
            self._send_line("QUIT")
        except DeviceConnectionError:
            pass
        finally:
            self._reader.close()
            self._sock.close()

    def __enter__(self) -> "RemoteDevice":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- Device interface ----------------------------------------------

    def get_info(self) -> DeviceInfo:
        self._send_line("INFO")
        line = self._recv_line()
        parts = line.split(" ")
        if len(parts) != 6 or parts[0] != "INFO":
            raise DeviceConnectionError(f"malformed INFO response: {line!r}")
        _, device_id, model, ios_version, battery_percent, jailbroken = parts
        return DeviceInfo(
            device_id=device_id,
            model=model,
            ios_version=ios_version,
            battery_percent=int(battery_percent),
            jailbroken=jailbroken == "1",
        )

    def execute_stage(self, attack_id: str, stage: Stage, is_last_stage: bool) -> StageOutcome:
        self._send_line(f"STAGE {stage.name} {stage.success_probability} {int(is_last_stage)}")
        line = self._recv_line()
        if line == "SUCCESS":
            return StageOutcome.SUCCESS
        if line == "FAILURE":
            return StageOutcome.FAILURE
        raise DeviceConnectionError(f"malformed STAGE response: {line!r}")

    def read_file(self, path: str) -> bytes:
        self._send_line(f"READ {path}")
        line = self._recv_line()
        if line.startswith("OK "):
            length = int(line[len("OK ") :])
            return self._recv_exact(length)
        if line == "ERR locked":
            raise PermissionError(f"device is locked, cannot read {path!r}")
        if line == "ERR not_found":
            raise FileNotFoundError(path)
        raise DeviceConnectionError(f"malformed READ response: {line!r}")

    # -- wire helpers -----------------------------------------------------

    def _send_line(self, line: str) -> None:
        try:
            self._sock.sendall((line + "\n").encode(_ENCODING))
        except OSError as exc:
            raise DeviceConnectionError(f"send failed: {exc}") from exc

    def _recv_line(self) -> str:
        try:
            raw = self._reader.readline()
        except OSError as exc:
            raise DeviceConnectionError(f"recv failed: {exc}") from exc
        if not raw:
            raise DeviceConnectionError("connection closed by device")
        return raw.decode(_ENCODING).rstrip("\r\n")

    def _recv_exact(self, n: int) -> bytes:
        try:
            data = self._reader.read(n)
        except OSError as exc:
            raise DeviceConnectionError(f"recv failed: {exc}") from exc
        if len(data) != n:
            raise DeviceConnectionError("connection closed mid-transfer")
        return data
