import time
import sys
from pathlib import Path

# make the package importable
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from nosp.stability import retry, register_component, set_component_status, get_health


def test_retry_succeeds_after_retries():
    calls = {"n": 0}

    @retry(max_attempts=4, initial_delay=0.01, backoff=1.5, exceptions=(ValueError,))
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("transient")
        return "ok"

    assert flaky() == "ok"
    assert calls["n"] == 3


def test_health_registry_and_status():
    register_component('test-comp', 'ok', {'info': 'initial'})
    set_component_status('test-comp', 'degraded', {'reason': 'unit-test'})
    health = get_health()
    assert 'test-comp' in health['components']
    assert health['components']['test-comp']['status'] == 'degraded'
