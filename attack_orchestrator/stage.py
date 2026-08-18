from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    """A single step of an attack chain.

    A stage carries no exploit logic itself. What it means to "run" a stage
    is decided by whichever `Device` executes it (an in-memory fake for
    tests, or a real device over TCP) - the stage just declares its name and
    how likely it is to succeed.
    """

    name: str
    success_probability: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.success_probability <= 1.0:
            raise ValueError(
                f"success_probability must be within [0.0, 1.0], got {self.success_probability!r}"
            )
