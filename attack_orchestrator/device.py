from __future__ import annotations

import random
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
