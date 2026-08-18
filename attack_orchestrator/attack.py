from __future__ import annotations

from dataclasses import dataclass, field

from .device import DeviceInfo
from .stage import Stage


def parse_ios_version(version: str) -> tuple[int, ...]:
    """Parse "16.4.1" -> (16, 4, 1) so versions compare numerically, not lexically."""
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise ValueError(f"invalid iOS version string: {version!r}") from exc


@dataclass(frozen=True)
class Requirements:
    """Preconditions a device must satisfy for an attack to be considered.

    Every field defaults to "don't care" so an attack only has to state the
    constraints that actually matter to it.
    """

    models: frozenset[str] | None = None
    min_ios: str | None = None
    max_ios: str | None = None
    min_battery: int = 0
    requires_jailbroken: bool | None = None

    def matches(self, info: DeviceInfo) -> bool:
        if self.models is not None and info.model not in self.models:
            return False
        if info.battery_percent < self.min_battery:
            return False
        if self.requires_jailbroken is not None and info.jailbroken != self.requires_jailbroken:
            return False

        if self.min_ios is not None or self.max_ios is not None:
            version = parse_ios_version(info.ios_version)
            if self.min_ios is not None and version < parse_ios_version(self.min_ios):
                return False
            if self.max_ios is not None and version > parse_ios_version(self.max_ios):
                return False

        return True


@dataclass(frozen=True)
class Attack:
    """A named, ordered chain of stages, gated by device requirements."""

    attack_id: str
    name: str
    stages: tuple[Stage, ...]
    requirements: Requirements = field(default_factory=Requirements)
    priority: int = 0

    def __post_init__(self) -> None:
        if not self.stages:
            raise ValueError(f"attack {self.attack_id!r} must have at least one stage")

    @property
    def estimated_success_probability(self) -> float:
        """Product of per-stage probabilities - the odds the full chain completes."""
        probability = 1.0
        for stage in self.stages:
            probability *= stage.success_probability
        return probability
