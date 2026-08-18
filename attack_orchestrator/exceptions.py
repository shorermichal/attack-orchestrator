class AttackOrchestratorError(Exception):
    """Base class for all errors raised by this package."""


class NoViableAttackError(AttackOrchestratorError):
    """Raised when no registered attack's requirements match the target device."""


class DeviceConnectionError(AttackOrchestratorError):
    """Raised when the connection to a device is lost or unusable.

    Distinct from a stage failing: a stage failure is an expected outcome the
    framework models (bad odds), while a connection error is an infrastructure
    fault (e.g. a dropped TCP connection to the device simulator).
    """