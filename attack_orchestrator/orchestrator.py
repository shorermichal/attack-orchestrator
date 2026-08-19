from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .attack import Attack, Stage
from .device import Device, DeviceConnectionError, DeviceSession, StageOutcome
from .selection import AttackSelector


class NoViableAttackError(Exception):
    """Raised when no registered attack's requirements match the target device."""


@dataclass
class StageRecord:
    stage: Stage
    outcome: StageOutcome


@dataclass
class AttackRunResult:
    attack: Attack
    success: bool
    stage_records: list[StageRecord] = field(default_factory=list)
    session: DeviceSession | None = None
    failure_reason: str | None = None


class Orchestrator:
    """Picks an attack for a device and runs it to completion or failure.

    Design choice: a stage failing aborts the whole chain immediately. No
    automatic retry of the failed stage and no automatic fallback to the
    next-best attack. On a real device, a failed exploit attempt can change
    device state (trip a security counter, force a reboot, consume a
    one-shot vulnerability) - re-attempting blindly is not obviously safe,
    so that decision is left to the caller, who gets a full run report and
    can choose to re-select and retry deliberately.
    """

    def __init__(self, selector: AttackSelector) -> None:
        self._selector = selector

    def run(self, device: Device, attacks: Sequence[Attack]) -> AttackRunResult:
        info = device.get_info()
        attack = self._selector.select(attacks, info)
        if attack is None:
            raise NoViableAttackError(
                f"no attack matches device {info.device_id!r} "
                f"(model={info.model!r}, ios={info.ios_version!r}, "
                f"battery={info.battery_percent}, jailbroken={info.jailbroken})"
            )

        records: list[StageRecord] = []
        last_index = len(attack.stages) - 1
        for index, stage in enumerate(attack.stages):
            try:
                outcome = device.execute_stage(attack.attack_id, stage, index == last_index)
            except DeviceConnectionError as exc:
                return AttackRunResult(
                    attack=attack,
                    success=False,
                    stage_records=records,
                    failure_reason=f"connection lost during stage {stage.name!r}: {exc}",
                )

            records.append(StageRecord(stage, outcome))
            if outcome is StageOutcome.FAILURE:
                return AttackRunResult(
                    attack=attack,
                    success=False,
                    stage_records=records,
                    failure_reason=f"stage {stage.name!r} failed",
                )

        session = DeviceSession(device, attack.attack_id)
        return AttackRunResult(attack=attack, success=True, stage_records=records, session=session)
