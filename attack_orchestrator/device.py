from __future__ import annotations

import random
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Stage lives in attack.py, which itself imports DeviceInfo from this
    # module - importing it for real here would be circular. It's only ever
    # used in type annotations (which `from __future__ import annotations`
    # keeps lazy), so a type-checking-only import is enough.
    from .attack import Stage


@dataclass(frozen=True)
class DeviceInfo:
    """State of a target device, as reported by the device itself.

    `extra` holds anything an attack might want to key a requirement off of
    without forcing every device implementation to agree on a fixed schema
    up front (e.g. region lock, storage free space).
    """

    device_id: str
    model: str
    ios_version: str
    battery_percent: int
    jailbroken: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class StageOutcome(Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class DeviceConnectionError(Exception):
    """Raised when the connection to a device is lost or unusable.

    Distinct from a stage failing: a stage failure is an expected outcome the
    framework models (bad odds), while a connection error is an infrastructure
    fault (e.g. a dropped TCP connection to the device simulator).
    """


class Device(ABC):
    """Everything the framework needs from a device, real or simulated.

    This is the seam between Part 1 (framework) and Part 2 (TCP simulator):
    `InMemoryDevice` below implements it in-process for design/testing, and
    a `RemoteDevice` implementing the same interface over TCP is a drop-in
    replacement - the orchestrator never needs to know which one it has.
    """

    @abstractmethod
    def get_info(self) -> DeviceInfo:
        """Query current device state (used for attack selection)."""

    @abstractmethod
    def execute_stage(self, attack_id: str, stage: Stage, is_last_stage: bool) -> StageOutcome:
        """Run one stage of an attack chain.

        `is_last_stage` tells the device whether this is the final stage of
        the chain, so a real device (or the simulator) can decide when to
        actually grant file access, rather than trusting the caller's word
        for it after the fact.

        Implementations should raise DeviceConnectionError for
        infrastructure failures (e.g. a dropped socket) rather than
        returning StageOutcome.FAILURE, since the two mean different things
        to the orchestrator.
        """

    @abstractmethod
    def read_file(self, path: str) -> bytes:
        """Read a file's contents off the device.

        Only meaningful once an attack chain has completed successfully;
        callers should go through a `DeviceSession` rather than calling this
        directly (see session semantics in orchestrator.py).
        """


class DeviceSession:
    """Capability handle granted only once an attack chain completes.

    There is deliberately no way to construct one except from a successful
    `Orchestrator.run()` - it exists so "you can read files" is only
    possible after "you successfully compromised the device", enforced by
    the type rather than by convention.
    """

    def __init__(self, device: Device, attack_id: str) -> None:
        self._device = device
        self.attack_id = attack_id

    def read_file(self, path: str) -> bytes:
        return self._device.read_file(path)


class InMemoryDevice(Device):
    """In-process fake device used by Part 1 and by unit tests.

    Stage outcomes are decided here by rolling against `stage.success_probability`.
    Note: `success_probability == 1.0` always succeeds and `== 0.0` always
    fails, since `random.random()` returns a value in [0.0, 1.0) - tests lean
    on this to get deterministic behavior without needing to seed anything.
    """

    def __init__(
        self,
        info: DeviceInfo,
        filesystem: dict[str, bytes] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._info = info
        self._filesystem = dict(filesystem or {})
        self._rng = rng or random.Random()

    def get_info(self) -> DeviceInfo:
        return self._info

    def execute_stage(self, attack_id: str, stage: Stage, is_last_stage: bool) -> StageOutcome:
        roll = self._rng.random()
        return StageOutcome.SUCCESS if roll < stage.success_probability else StageOutcome.FAILURE

    def read_file(self, path: str) -> bytes:
        try:
            return self._filesystem[path]
        except KeyError:
            raise FileNotFoundError(path) from None


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
