"""A handful of illustrative attacks, used by examples and tests.

None of this models a real exploit technique - stage names and odds are
flavor text for a simulated framework, not implementations of anything.
"""

from __future__ import annotations

from .attack import Attack, Requirements
from .stage import Stage

LEGACY_BOOTROM_ATTACK = Attack(
    attack_id="legacy-bootrom",
    name="Legacy bootrom-level attack",
    stages=(
        Stage("connect_dfu_mode", 0.95),
        Stage("bootrom_exploit", 0.9),
        Stage("load_payload", 0.85),
    ),
    requirements=Requirements(
        models=frozenset({"iPhone8,1", "iPhone8,2", "iPhone8,4"}),
        max_ios="14.8.1",
        min_battery=20,
    ),
    priority=10,
)

USERLAND_JAILBREAK_ATTACK = Attack(
    attack_id="userland-jailbreak",
    name="Userland jailbreak chain",
    stages=(
        Stage("exploit_sandbox_escape", 0.7),
        Stage("escalate_privileges", 0.6),
        Stage("install_implant", 0.8),
    ),
    requirements=Requirements(
        min_ios="14.0",
        max_ios="16.6",
        min_battery=10,
    ),
    priority=5,
)

TRUSTCACHE_BYPASS_ATTACK = Attack(
    attack_id="trustcache-bypass",
    name="Trust cache bypass",
    stages=(
        Stage("inject_signed_stub", 0.5),
        Stage("bypass_trustcache", 0.4),
    ),
    requirements=Requirements(
        min_ios="15.0",
        min_battery=30,
    ),
    priority=1,
)

DEFAULT_CATALOG: tuple[Attack, ...] = (
    LEGACY_BOOTROM_ATTACK,
    USERLAND_JAILBREAK_ATTACK,
    TRUSTCACHE_BYPASS_ATTACK,
)
