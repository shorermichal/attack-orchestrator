from pathlib import Path

from attack_orchestrator import (
    Attack,
    BestOddsSelector,
    DeviceInfo,
    Extractor,
    InMemoryDevice,
    Orchestrator,
    Stage,
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


def _completed_session(filesystem: dict[str, bytes]):
    attack = Attack("a1", "A1", stages=(Stage("s1", 1.0),))
    device = InMemoryDevice(make_info(), filesystem=filesystem)
    result = Orchestrator(BestOddsSelector()).run(device, [attack])
    assert result.success
    return result.session


def test_extract_file_writes_bytes_to_disk(tmp_path: Path):
    session = _completed_session({"/etc/hosts": b"127.0.0.1 localhost"})
    extractor = Extractor(session)

    dest = extractor.extract_file("/etc/hosts", tmp_path)

    assert dest.exists()
    assert dest.read_bytes() == b"127.0.0.1 localhost"


def test_extract_all_reports_successes_and_errors(tmp_path: Path):
    session = _completed_session({"/a": b"aaa", "/b": b"bbb"})
    extractor = Extractor(session)

    report = extractor.extract_all(tmp_path, paths=["/a", "/b", "/missing"])

    assert report.success_count == 2
    assert report.error_count == 1
    assert "/missing" in report.errors
    assert report.extracted["/a"].read_bytes() == b"aaa"
    assert report.extracted["/b"].read_bytes() == b"bbb"


def test_extract_all_defaults_to_the_builtin_manifest(tmp_path: Path):
    session = _completed_session({})  # nothing present -> every default path errors, none crash
    extractor = Extractor(session)

    report = extractor.extract_all(tmp_path)

    assert report.success_count == 0
    assert report.error_count > 0
