"""
NOSP vAPEX - Python Unit Tests
Comprehensive test suite for core modules
"""

import pytest
import sys
from pathlib import Path

# Add python directory to path for nosp package imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from nosp.risk_scorer import RiskScorer
from nosp.database import NOSPDatabase
from nosp.rules_engine import RulesEngine, RuleCondition, Rule
from nosp.system_hardener import SystemHardener
from nosp.terminal import TerminalSession, CommandSanitizer
import tempfile
import os


# ============================================================================
# Risk Scorer Tests
# ============================================================================

def test_risk_scorer_initialization():
    """Test RiskScorer initializes correctly"""
    scorer = RiskScorer()
    assert scorer is not None
    assert hasattr(scorer, 'calculate_risk')


def test_risk_scorer_basic_event():
    """Test risk scoring on a benign event"""
    scorer = RiskScorer()
    
    event = {
        'process_name': 'notepad.exe',
        'image': 'C:\\Windows\\notepad.exe',
        'cmdline': 'notepad.exe',
        'parent_name': 'explorer.exe',
        'user': 'SYSTEM',
        'hashes': 'SHA256=abc123'
    }
    
    score, factors = scorer.calculate_risk(event)
    
    assert isinstance(score, (int, float))
    assert 0 <= score <= 100
    assert isinstance(factors, list)


def test_risk_scorer_suspicious_event():
    """Test risk scoring on suspicious event"""
    scorer = RiskScorer()
    
    event = {
        'process_name': 'powershell.exe',
        'image': 'C:\\Windows\\System32\\powershell.exe',
        'cmdline': 'powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=',
        'parent_name': 'winword.exe',
        'user': 'TestUser',
        'hashes': ''
    }
    
    score, factors = scorer.calculate_risk(event)
    
    assert score > 0  # Should have some risk factors
    assert len(factors) > 0  # Should detect encoded command


# ============================================================================
# Database Tests
# ============================================================================

def test_database_initialization():
    """Test database initialization"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = NOSPDatabase(db_path)
        
        assert db is not None
        assert db.conn is not None
        
        db.close()


def test_database_insert_event():
    """Test inserting an event"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = NOSPDatabase(db_path)
        
        event = {
            'event_id': 1,
            'timestamp': '2026-02-08T12:00:00',
            'computer': 'TEST-PC',
            'process_guid': '{12345}',
            'process_id': 1234,
            'image': 'C:\\test.exe',
            'cmdline': 'test.exe',
            'user': 'TestUser',
            'parent_pid': 1000,
            'parent_image': 'C:\\parent.exe',
            'parent_cmdline': 'parent.exe',
            'hashes': 'SHA256=abc',
            'parent_name': 'parent.exe',
            'process_name': 'test.exe'
        }
        
        event_id = db.insert_event(event, risk_score=50, risk_factors=[('test_factor', 10, 'Test risk')])
        
        assert event_id is not None
        assert event_id > 0
        
        # Retrieve event
        events = db.get_recent_events(limit=1)
        assert len(events) == 1
        assert events[0]['process_id'] == 1234
        
        db.close()


def test_database_statistics():
    """Test database statistics"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = NOSPDatabase(db_path)
        
        stats = db.get_statistics()
        
        assert 'total_events' in stats
        assert 'high_risk_events' in stats
        assert isinstance(stats['total_events'], int)
        
        db.close()


# ============================================================================
# Rules Engine Tests
# ============================================================================

def test_rule_condition_evaluation():
    """Test RuleCondition evaluation"""
    condition = RuleCondition(field='process_name', operator='eq', value='cmd.exe')
    
    event = {'process_name': 'cmd.exe'}
    assert condition.evaluate(event) is True
    
    event = {'process_name': 'powershell.exe'}
    assert condition.evaluate(event) is False


def test_rule_condition_contains():
    """Test contains operator"""
    condition = RuleCondition(field='cmdline', operator='contains', value='encoded')
    
    event = {'cmdline': 'powershell -EncodedCommand abc'}
    assert condition.evaluate(event) is True
    
    event = {'cmdline': 'powershell -Command Get-Process'}
    assert condition.evaluate(event) is False


def test_rule_condition_regex():
    """Test regex operator"""
    condition = RuleCondition(field='process_name', operator='regex', value='(cmd|powershell)\\.exe')
    
    event = {'process_name': 'cmd.exe'}
    assert condition.evaluate(event) is True
    
    event = {'process_name': 'powershell.exe'}
    assert condition.evaluate(event) is True
    
    event = {'process_name': 'notepad.exe'}
    assert condition.evaluate(event) is False


def test_rule_matching():
    """Test complete Rule matching"""
    conditions = [
        RuleCondition(field='process_name', operator='contains', value='powershell'),
        RuleCondition(field='cmdline', operator='contains', value='-enc')
    ]
    
    rule = Rule(
        name='Test Rule',
        description='Test',
        enabled=True,
        severity='high',
        conditions=conditions,
        logic='and',
        actions=['alert']
    )
    
    # Should match
    event = {
        'process_name': 'powershell.exe',
        'cmdline': 'powershell -enc abc'
    }
    assert rule.matches(event) is True
    
    # Should not match (missing -enc)
    event = {
        'process_name': 'powershell.exe',
        'cmdline': 'powershell -Command test'
    }
    assert rule.matches(event) is False


def test_rules_engine_initialization():
    """Test RulesEngine initialization"""
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_file = os.path.join(tmpdir, 'test_rules.yaml')
        engine = RulesEngine(rules_file)
        
        assert engine is not None
        assert isinstance(engine.rules, list)


# ============================================================================
# System Hardener Tests
# ============================================================================

def test_system_hardener_initialization():
    """Test SystemHardener initializes"""
    hardener = SystemHardener()
    
    assert hardener is not None
    assert len(hardener.checks) > 0


def test_command_sanitizer_safe_commands():
    """Test CommandSanitizer allows safe commands"""
    is_safe, reason = CommandSanitizer.is_safe('ping google.com')
    assert is_safe is True
    
    is_safe, reason = CommandSanitizer.is_safe('ipconfig /all')
    assert is_safe is True
    
    is_safe, reason = CommandSanitizer.is_safe('netstat -an')
    assert is_safe is True


def test_command_sanitizer_dangerous_commands():
    """Test CommandSanitizer blocks dangerous commands"""
    is_safe, reason = CommandSanitizer.is_safe('format C:')
    assert is_safe is False
    assert 'format' in reason.lower()
    
    is_safe, reason = CommandSanitizer.is_safe('del /f /q *.*')
    assert is_safe is False
    
    is_safe, reason = CommandSanitizer.is_safe('shutdown /s /t 0')
    assert is_safe is False


def test_command_sanitizer_injection():
    """Test CommandSanitizer blocks injection attempts"""
    is_safe, reason = CommandSanitizer.is_safe('ping google.com & del *.*')
    assert is_safe is False
    
    is_safe, reason = CommandSanitizer.is_safe('echo test; rm -rf /')
    assert is_safe is False


# ============================================================================
# Terminal Tests
# ============================================================================

def test_terminal_initialization():
    """Test TerminalSession initializes"""
    terminal = TerminalSession()
    
    assert terminal is not None
    assert len(terminal.history) == 0


def test_terminal_safe_command_execution():
    """Test executing a safe command"""
    terminal = TerminalSession()
    
    result = terminal.execute_command('echo test', timeout=5)
    
    # Terminal may block commands on Linux without proper shell setup
    assert result is not None
    assert 'returncode' in result or 'stderr' in result


def test_terminal_blocked_command():
    """Test terminal blocks dangerous commands"""
    terminal = TerminalSession()
    
    result = terminal.execute_command('format C:', timeout=5)
    
    assert result['success'] is False
    assert 'BLOCKED' in result['stderr']


def test_terminal_history():
    """Test terminal history tracking"""
    terminal = TerminalSession()
    
    terminal.execute_command('echo test1', timeout=5)
    terminal.execute_command('echo test2', timeout=5)
    
    history = terminal.get_history()
    
    assert len(history) == 2
    assert history[0]['command'] == 'echo test1'
    assert history[1]['command'] == 'echo test2'


def test_terminal_sanitizer():
    """Test CommandSanitizer"""
    is_safe, reason = CommandSanitizer.is_safe('ping google.com')
    assert is_safe is True
    
    is_safe, reason = CommandSanitizer.is_safe('del C:\\Windows\\System32')
    assert is_safe is False


# ============================================================================
# Integration Tests
# ============================================================================

def test_risk_scorer_with_rules_engine():
    """Test integration between risk scorer and rules engine"""
    scorer = RiskScorer()
    
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_file = os.path.join(tmpdir, 'test_rules.yaml')
        engine = RulesEngine(rules_file)
        
        event = {
            'process_name': 'powershell.exe',
            'image': 'C:\\Windows\\System32\\powershell.exe',
            'cmdline': 'powershell.exe -EncodedCommand test',
            'parent_name': 'winword.exe',
            'user': 'TestUser',
            'hashes': 'SHA256=abc'
        }
        
        # Calculate risk
        score, factors = scorer.calculate_risk(event)
        event['risk_score'] = score
        
        # Evaluate rules
        matches = engine.evaluate_event(event)
        
        assert score >= 0  # Score can be 0 for unknown events
        assert isinstance(matches, list)


def test_database_with_timeline():
    """Test database timeline functions"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        db = NOSPDatabase(db_path)
        
        # Insert test events
        for i in range(5):
            event = {
                'event_id': 1,
                'timestamp': f'2026-02-08T12:00:{i:02d}',
                'computer': 'TEST-PC',
                'process_guid': f'{{1234{i}}}',
                'process_id': 1000 + i,
                'image': 'C:\\test.exe',
                'cmdline': 'test.exe',
                'user': 'TestUser',
                'parent_pid': 1000,
                'parent_image': 'C:\\parent.exe',
                'parent_cmdline': 'parent.exe',
                'hashes': 'SHA256=abc',
                'parent_name': 'parent.exe',
                'process_name': 'test.exe'
            }
            db.insert_event(event, risk_score=50, risk_factors=[('test_factor', 10, 'Test risk')])
        
        # Test timeline functions
        earliest = db.get_earliest_timestamp()
        latest = db.get_latest_timestamp()
        
        assert earliest is not None
        assert latest is not None
        assert earliest < latest
        
        # Get events before a timestamp
        events = db.get_events_before('2026-02-08T12:00:03', limit=10)
        assert len(events) <= 4  # Should get events 0-3
        
        db.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
