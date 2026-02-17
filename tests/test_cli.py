import os
import sys
import tempfile
from pathlib import Path

# make local python package importable
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from nosp.cli import init_db, scan, analyze


def test_init_db_creates_file(tmp_path):
    db_path = tmp_path / 'nosp_test.db'
    assert not db_path.exists()
    res = init_db(str(db_path))
    assert res is True
    assert db_path.exists()


def test_scan_returns_list():
    rows = scan(top=5)
    assert isinstance(rows, list)
    if rows:
        r = rows[0]
        assert 'pid' in r and 'risk' in r and 'name' in r


def test_analyze_invalid_pid_returns_error():
    res = analyze(99999999)
    assert res.get('ok') is False
    assert 'error' in res
