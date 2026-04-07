"""ComplyGuard integration tests."""

from __future__ import annotations

from substrate_guard.comply.comply_guard import ComplyGuard


class _DummyGuard:
    pass


def test_load_protected_content():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    r = g.load_protected_content(["p1", "p2"])
    assert r["num_documents"] == 2
    assert g._committed


def test_check_clean_output():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    g.load_protected_content(["only-secret"])
    cert = g.check_compliance("something-completely-different-12345")
    assert cert["result"]["verified"] is True


def test_check_infringing_output():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    secret = "copyrighted-block-xyz"
    g.load_protected_content([secret])
    cert = g.check_compliance(secret)
    assert cert["result"]["verified"] is False


def test_process_event_adds_compliance():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    g.load_protected_content(["hidden"])
    out = g.process_event({"output": "hidden"})
    assert "compliance" in out
    assert out["compliance"]["verified"] is False


def test_status_shows_commitment():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    g.load_protected_content(["a"])
    s = g.status()
    assert s["committed"] is True
    assert s["commitment_root"] is not None


def test_no_check_without_commitment():
    g = ComplyGuard(_DummyGuard(), {"use_z3": False})
    r = g.check_compliance("x")
    assert r["checked"] is False
