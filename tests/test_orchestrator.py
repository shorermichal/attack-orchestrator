import pytest

from attack_orchestrator import (
    Attack,
    BestOddsSelector,
    Device,
    DeviceConnectionError,
    DeviceInfo,
    InMemoryDevice,
    NoViableAttackError,
    Orchestrator,
    Requirements,
    Stage,
    StageOutcome,
)


def make_info(**overrides):
    defaults = dict(
        device_id="dev-1",
        model="iPhone14,5",
        ios_version="16.1",
        battery_percent=50,
        jailbroken=False,
    )
    defaults.update(overrides)
    return DeviceInfo(**defaults)


def test_successful_chain_yields_a_readable_session():
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0), Stage("s2", 1.0)))
    device = InMemoryDevice(make_info(), filesystem={"/etc/hosts": b"127.0.0.1 localhost"})
    orchestrator = Orchestrator(BestOddsSelector())

    result = orchestrator.run(device, [attack])

    assert result.success is True
    assert [r.outcome for r in result.stage_records] == [StageOutcome.SUCCESS, StageOutcome.SUCCESS]
    assert result.session is not None
    assert result.session.read_file("/etc/hosts") == b"127.0.0.1 localhost"


def test_stage_failure_aborts_the_rest_of_the_chain():
    attack = Attack(
        "a1", "A1", stages=(Stage("s1", 1.0), Stage("s2", 0.0), Stage("s3", 1.0))
    )
    device = InMemoryDevice(make_info())
    orchestrator = Orchestrator(BestOddsSelector())

    result = orchestrator.run(device, [attack])

    assert result.success is False
    assert result.session is None
    assert len(result.stage_records) == 2  # s3 never ran
    assert result.stage_records[-1].outcome is StageOutcome.FAILURE
    assert "s2" in result.failure_reason


def test_no_viable_attack_raises():
    attack = Attack(
        "a1", "A1", stages=(Stage("s1", 1.0),), requirements=Requirements(min_ios="17.0")
    )
    device = InMemoryDevice(make_info(ios_version="16.1"))
    orchestrator = Orchestrator(BestOddsSelector())

    with pytest.raises(NoViableAttackError):
        orchestrator.run(device, [attack])


class _DropsConnectionDevice(Device):
    """Stub device that simulates a connection drop partway through a chain."""

    def __init__(self, info: DeviceInfo, fail_on_stage: str) -> None:
        self._info = info
        self._fail_on_stage = fail_on_stage

    def get_info(self) -> DeviceInfo:
        return self._info

    def execute_stage(self, attack_id, stage, is_last_stage, context) -> StageOutcome:
        if stage.name == self._fail_on_stage:
            raise DeviceConnectionError("socket closed by peer")
        return StageOutcome.SUCCESS

    def read_file(self, path: str) -> bytes:
        raise AssertionError("should not be reachable without a completed chain")


def test_dropped_connection_is_reported_distinctly_from_a_failed_stage():
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0), Stage("s2", 1.0)))
    device = _DropsConnectionDevice(make_info(), fail_on_stage="s2")
    orchestrator = Orchestrator(BestOddsSelector())

    result = orchestrator.run(device, [attack])

    assert result.success is False
    assert result.session is None
    assert "connection lost" in result.failure_reason
    assert len(result.stage_records) == 1  # s1 succeeded and was recorded; s2 never got that far
