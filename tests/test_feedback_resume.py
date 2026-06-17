"""Tests for the WAF feedback loop, checkpointing, and session re-auth."""
from wafpierce.database import WAFPierceDB
from wafpierce import checkpoint
from wafpierce.pierce import CloudFrontBypasser


# -- WAF feedback loop ---------------------------------------------------- #
def test_feedback_records_and_prioritizes(tmp_path):
    db = WAFPierceDB(db_path=str(tmp_path / "fb.db"))
    # technique A bypasses cloudflare twice; B never does.
    db.record_technique_outcome('cloudflare', '_test_a', True)
    db.record_technique_outcome('cloudflare', '_test_a', True)
    db.record_technique_outcome('cloudflare', '_test_b', False)
    db.record_technique_outcome('cloudflare', '_test_b', False)

    prio = db.get_prioritized_techniques('cloudflare')
    assert prio[0] == '_test_a'        # higher success rate ranks first
    assert '_test_b' not in prio       # zero successes excluded


def test_feedback_isolated_per_waf(tmp_path):
    db = WAFPierceDB(db_path=str(tmp_path / "fb.db"))
    db.record_technique_outcome('akamai', '_test_x', True)
    assert db.get_prioritized_techniques('akamai') == ['_test_x']
    assert db.get_prioritized_techniques('cloudflare') == []


# -- checkpoint / resume -------------------------------------------------- #
def test_checkpoint_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(checkpoint, 'ensure_config_dir', lambda: str(tmp_path),
                        raising=False)
    # Force the path into tmp by patching the resolver.
    monkeypatch.setattr(checkpoint, '_checkpoint_path',
                        lambda target: str(tmp_path / "cp.json"))
    target = 'https://t.example'
    checkpoint.save(target, ['_test_a', '_test_b'], [{'technique': 'x'}])
    loaded = checkpoint.load(target)
    assert loaded['completed'] == ['_test_a', '_test_b']
    assert loaded['results'][0]['technique'] == 'x'
    checkpoint.clear(target)
    assert checkpoint.load(target) is None


# -- session expiry heuristic --------------------------------------------- #
def test_session_expiry_detection():
    assert CloudFrontBypasser.looks_like_session_expiry(401, '') is True
    assert CloudFrontBypasser.looks_like_session_expiry(200, '<input name="password">') is True
    assert CloudFrontBypasser.looks_like_session_expiry(200, 'welcome back, user') is False


def test_feedback_db_attached_by_create_scanner(tmp_path, monkeypatch, mock_waf):
    # create_scanner should attach a feedback DB when db-extras are enabled.
    import wafpierce.pierce as p
    monkeypatch.setattr(p, 'load_custom_payloads', lambda db: {})
    monkeypatch.setattr(p, 'load_plugins', lambda: [])
    monkeypatch.setattr(p, 'load_evasion_profile', lambda db, waf=None: {})
    db = WAFPierceDB(db_path=str(tmp_path / "fb.db"))
    scanner = p.create_scanner(mock_waf, db=db, use_db_extras=True,
                               threads=2, delay=0, timeout=3)
    assert scanner.feedback_db is db
