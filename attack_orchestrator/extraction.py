from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .device import DeviceSession

# There is no directory-listing primitive in the device interface (the
# spec only grants "read a file at a given path" on chain completion), so
# "extract everything" means "everything in a known-paths manifest" - the
# same approach real mobile-forensics tooling takes: target well-known file
# locations rather than assume an arbitrary filesystem walk is available.
DEFAULT_MANIFEST: tuple[str, ...] = (
    "/private/var/mobile/Library/SMS/sms.db",
    "/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb",
    "/private/var/mobile/Library/CallHistoryDB/CallHistory.storedata",
    "/private/var/mobile/Library/Safari/History.db",
    "/private/var/mobile/Library/Preferences/com.apple.mobile.installation.plist",
)


@dataclass
class ExtractionReport:
    extracted: dict[str, Path] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def success_count(self) -> int:
        return len(self.extracted)

    @property
    def error_count(self) -> int:
        return len(self.errors)


class Extractor:
    """Pulls files off a device through a completed attack's session.

    Takes a `DeviceSession` rather than a `Device` so it's structurally
    impossible to extract data without having gone through a successful
    `Orchestrator.run()` first.
    """

    def __init__(self, session: DeviceSession) -> None:
        self._session = session

    def extract_file(self, path: str, dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        data = self._session.read_file(path)
        dest = dest_dir / path.lstrip("/").replace("/", "_")
        dest.write_bytes(data)
        return dest

    def extract_all(self, dest_dir: Path, paths: Iterable[str] | None = None) -> ExtractionReport:
        report = ExtractionReport()
        for path in (paths if paths is not None else DEFAULT_MANIFEST):
            try:
                report.extracted[path] = self.extract_file(path, dest_dir)
            except Exception as exc:  # noqa: BLE001 - one bad path shouldn't abort the rest
                report.errors[path] = str(exc)
        return report
