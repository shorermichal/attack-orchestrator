from attack_orchestrator import Attack, BestOddsSelector, DeviceInfo, Requirements, Stage


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


def test_selects_only_matching_attack():
    matching = Attack(
        "a1", "A1", stages=(Stage("s1", 0.5),), requirements=Requirements(min_ios="16.0")
    )
    non_matching = Attack(
        "a2", "A2", stages=(Stage("s1", 0.9),), requirements=Requirements(max_ios="10.0")
    )
    selector = BestOddsSelector()

    chosen = selector.select([matching, non_matching], make_info(ios_version="16.1"))

    assert chosen is matching


def test_returns_none_when_nothing_matches():
    attack = Attack("a1", "A1", stages=(Stage("s1", 0.5),), requirements=Requirements(min_ios="17.0"))
    selector = BestOddsSelector()

    assert selector.select([attack], make_info(ios_version="16.1")) is None


def test_prefers_higher_estimated_success_probability():
    low_odds = Attack("low", "Low", stages=(Stage("s1", 0.2), Stage("s2", 0.2)))
    high_odds = Attack("high", "High", stages=(Stage("s1", 0.9), Stage("s2", 0.9)))
    selector = BestOddsSelector()

    chosen = selector.select([low_odds, high_odds], make_info())

    assert chosen is high_odds


def test_ties_broken_by_priority():
    low_priority = Attack("low", "Low", stages=(Stage("s1", 0.5),), priority=0)
    high_priority = Attack("high", "High", stages=(Stage("s1", 0.5),), priority=10)
    selector = BestOddsSelector()

    chosen = selector.select([low_priority, high_priority], make_info())

    assert chosen is high_priority


def test_requirements_check_battery_and_model():
    reqs = Requirements(models=frozenset({"iPhone14,5"}), min_battery=40)

    assert reqs.matches(make_info(model="iPhone14,5", battery_percent=50))
    assert not reqs.matches(make_info(model="iPhone14,5", battery_percent=10))
    assert not reqs.matches(make_info(model="iPhone13,1", battery_percent=50))


def test_requirements_check_jailbroken_flag():
    reqs = Requirements(requires_jailbroken=True)

    assert not reqs.matches(make_info(jailbroken=False))
    assert reqs.matches(make_info(jailbroken=True))
