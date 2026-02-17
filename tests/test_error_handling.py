import os
import sys
import tempfile
from pathlib import Path

# make local python package importable (same approach as existing tests)
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from nosp.native_bindings import PacketCapture, PacketInjector
from nosp.rules_engine import RulesEngine
from nosp.session_manager import SessionManager
from nosp.errors import report_exception
from nosp.ai_engine import NOSPAIEngine


def test_packetcapture_library_missing():
    pc = PacketCapture()
    # library not present in native/c in test env -> start should be False
    assert pc.start() is False

    # safe wrapper returns Result
    res = pc.start_safe()
    assert hasattr(res, 'success')
    assert isinstance(res.success, bool)
    assert isinstance(res.value, bool)


def test_packetinjector_library_missing():
    inj = PacketInjector()
    # injector not initialized -> inject should return False
    assert inj.inject_rst("127.0.0.1", "127.0.0.1", 1234, 80) is False

    # safe wrapper returns Result
    r = inj.inject_rst_safe("127.0.0.1", "127.0.0.1", 1234, 80)
    assert hasattr(r, 'success')
    assert isinstance(r.value, bool)


def test_rules_engine_invalid_yaml(tmp_path):
    rules_file = tmp_path / "bad_rules.yaml"
    rules_file.write_text("::::not_yaml::::")

    engine = RulesEngine(str(rules_file))
    # load_rules should detect invalid YAML and return False
    assert engine.load_rules() is False

    # safe wrapper returns Result wrapping the boolean
    res = engine.load_rules_safe()
    assert isinstance(res.success, bool)
    assert res.value is False


def test_session_load_malformed_json(tmp_path):
    sf = tmp_path / "session.json"
    sf.write_text("{ this is not: valid json }")

    sm = SessionManager(str(sf))
    assert sm.load_session() is None

    res = sm.load_session_safe()
    assert res.success is True
    assert res.value is None

def test_report_exception_writes_log(tmp_path):
    log_path = tmp_path / "nosp_error.log"
    # temporarily monkeypatch default location by setting environment variable/working dir
    # report_exception writes to nosp_error.log in cwd, so change cwd
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        report_exception(Exception("unit-test-error"), context="unit_test")
        assert log_path.exists()
        content = log_path.read_text()
        assert "unit-test-error" in content
    finally:
        os.chdir(cwd)


def test_ai_engine_model_unavailable():
    ai = NOSPAIEngine()
    # If Ollama not installed this should gracefully indicate model not ready
    res = ai.analyze_process({})
    assert isinstance(res, str)
    assert res.startswith("⚠")

    # safe wrapper
    r = ai.analyze_process_safe({})
    assert hasattr(r, 'success')
    assert isinstance(r.value, str)


def test_database_insert_event_safe():
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, 'test.db')
        from nosp.database import NOSPDatabase
        db = NOSPDatabase(db_path)

        event = {
            'event_id': 1,
            'timestamp': '2026-02-08T12:00:00',
            'computer': 'TEST-PC',
            'process_guid': '{12345}',
            'process_id': 1234,
            'image': 'C:\\test.exe',
            'command_line': 'test.exe',
            'user': 'TestUser',
            'parent_image': 'C:\\parent.exe',
            'hashes': {}
        }

        res = db.insert_event_safe(event, 10, [])
        assert res.success is True
        assert isinstance(res.value, int)
        db.close()


def test_cage_detonate_file_safe():
    from nosp.cage import Cage
    cage = Cage()

    r = cage.detonate_file_safe('nonexistent_file_xyz.bin')
    assert r.success is False
    assert 'File not found' in (r.message or '')
    assert r.suggestion and 'Verify the file path' in r.suggestion
