"""Tests for the local-only web assessment scanner."""

from __future__ import annotations

import threading
import time
import urllib.request
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from soclab.vapt import SafetyError, check_target, is_loopback, review_tls, scan

APP_PATH = Path(__file__).resolve().parent.parent / "lab" / "insecure_demo" / "app.py"


def _wait_until_ready(url: str, timeout: float = 20.0) -> bool:
    """Block until the server actually accepts connections.

    A fixed sleep is flaky on a loaded CI runner - the server can still be
    binding when the test fires its first request, which looks like a real
    failure. Poll instead.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except Exception:
            time.sleep(0.25)
    return False


@pytest.fixture(scope="module")
def demo_server():
    """Run the intentionally vulnerable demo app on 127.0.0.1:5099."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("insecure_demo", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Bind to port 0 so the OS picks a free port - a fixed port is a flaky
    # test on shared CI runners.
    server = make_server("127.0.0.1", 0, module.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{server.port}"
    if not _wait_until_ready(base):
        server.shutdown()
        pytest.fail("demo server did not become ready in time")
    yield base
    server.shutdown()


# --- safety guard -----------------------------------------------------------

def test_loopback_detection():
    assert is_loopback("127.0.0.1")
    assert is_loopback("localhost")
    assert not is_loopback("example.com")
    assert not is_loopback("8.8.8.8")


def test_scanner_refuses_remote_targets():
    with pytest.raises(SafetyError):
        check_target("https://example.com")
    with pytest.raises(SafetyError):
        check_target("http://192.168.1.10")


def test_scanner_allows_loopback():
    assert check_target("http://127.0.0.1:5001") == "http://127.0.0.1:5001"


def test_scanner_rejects_unsupported_scheme():
    with pytest.raises(SafetyError):
        check_target("ftp://127.0.0.1")


# --- findings ---------------------------------------------------------------

def test_scan_finds_real_issues(demo_server):
    result = scan(demo_server, timeout=5.0)
    ids = {f.id for f in result.findings}
    assert "HDR-strict-transport-security" in ids
    assert "COOK-001" in ids
    assert "CFG-002" in ids
    assert "CFG-003" in ids
    assert any(i.startswith("EXP-") for i in ids), "exposed .env should be found"
    assert result.status == 200


def test_findings_are_severity_ordered(demo_server):
    result = scan(demo_server, timeout=5.0)
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    severities = [order[f.severity] for f in result.findings]
    assert severities == sorted(severities, reverse=True)


def test_report_rendering(demo_server):
    result = scan(demo_server, timeout=5.0)
    markdown = result.to_markdown()
    assert "# Web security assessment" in markdown
    assert "OWASP" in markdown
    assert result.to_dict()["findings"]


def test_tls_review_handles_unreachable_host():
    info = review_tls("127.0.0.1", port=59999, timeout=1.0)
    assert "error" in info
