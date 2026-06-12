from main import max_severity_reached


RESULTS = {
    "host": [{"severity": "medium"}],
    "containers": [{"severity": "high"}],
    "images": [{"severity": "info"}],
    "binaries": [],
    "vulnerabilities": [{"severity": "critical"}]
}


def test_fail_on_none_never_fails():
    assert max_severity_reached(RESULTS, "none") is False


def test_fail_on_threshold_met():
    assert max_severity_reached(RESULTS, "high") is True
    assert max_severity_reached(RESULTS, "critical") is True


def test_fail_on_threshold_not_met():
    results = {"host": [{"severity": "low"}], "vulnerabilities": []}
    assert max_severity_reached(results, "high") is False


def test_fail_on_handles_missing_sections():
    assert max_severity_reached({}, "low") is False
