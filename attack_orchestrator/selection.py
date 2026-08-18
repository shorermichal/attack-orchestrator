from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from .attack import Attack
from .device import DeviceInfo


class AttackSelector(ABC):
    """Strategy for choosing one attack among those valid for a device.

    Kept as an interface rather than a single hardcoded policy because "how
    do you pick?" is explicitly open-ended in the assignment - a caller with
    different priorities (e.g. always prefer the fewest stages, or use
    historical success rates from past runs) can swap in their own selector
    without touching the orchestrator.
    """

    @abstractmethod
    def select(self, attacks: Iterable[Attack], info: DeviceInfo) -> Attack | None:
        """Return the attack to run, or None if nothing applies to this device."""


class BestOddsSelector(AttackSelector):
    """Default policy: among attacks whose requirements match, prefer the
    one most likely to complete end-to-end.

    Ties (equal estimated odds) are broken by explicit `priority`, then by
    preferring fewer stages - a shorter chain has fewer opportunities to be
    interrupted (e.g. by a dropped connection) even at equal odds.
    """

    def select(self, attacks: Iterable[Attack], info: DeviceInfo) -> Attack | None:
        candidates = [a for a in attacks if a.requirements.matches(info)]
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda a: (round(a.estimated_success_probability, 6), a.priority, -len(a.stages)),
        )
