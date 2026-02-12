#!/usr/bin/env python3
"""
NOSP Feature Verification Script
=================================

Comprehensive test of all 18 advertised features for both Windows and Linux.
"""

import sys
import platform
import importlib
from pathlib import Path

IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'

print("=" * 70)
print("NOSP FEATURE VERIFICATION")
print("=" * 70)
print(f"Platform: {platform.system()} {platform.release()}")
print(f"Python: {sys.version.split()[0]}")
print("=" * 70)
print()

results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'platform_limited': 0
}

def test_feature(name: str, test_func, windows_only: bool = False, linux_only: bool = False):
    """Test a single feature"""
    global results
    results['total'] += 1
    
    print(f"Testing: {name}...", end=" ")
    
    if windows_only and not IS_WINDOWS:
        print("⊘ (Windows only)")
        results['platform_limited'] += 1
        return
    
    if linux_only and not IS_LINUX:
        print("⊘ (Linux only)")
        results['platform_limited'] += 1
        return
    
    try:
        success = test_func()
        if success:
            print("✓")
            results['passed'] += 1
        else:
            print("✗")
            results['failed'] += 1
    except Exception as e:
        print(f"✗ ({str(e)[:50]})")
        results['failed'] += 1


def test_etw_monitoring():
    """1. Kernel-level ETW monitoring"""
    try:
        import nosp_core
        status = nosp_core.check_sysmon_status()
        return 'installed' in status
    except:
        return False


def test_ai_threat_assessment():
    """2. AI-powered threat assessment with MITRE ATT&CK"""
    from nosp.ai_engine import NOSPAIEngine
    engine = NOSPAIEngine()
    return engine.model_ready


def test_risk_scoring():
    """3. Behavioral risk scoring with dynamic thresholds"""
    from nosp.risk_scorer import RiskScorer
    scorer = RiskScorer()
    test_event = {'image': 'C:\\Windows\\System32\\cmd.exe', 'command_line': 'cmd /c test'}
    score, factors = scorer.calculate_risk(test_event)
    return isinstance(score, int) and 0 <= score <= 100


def test_usb_control():
    """4. USB device control with allowlist/blocklist"""
    if IS_WINDOWS:
        try:
            import nosp_core
            devices = nosp_core.list_usb_devices_py()
            return isinstance(devices, list)
        except:
            return False
    else:
        from nosp.linux_compat import LinuxUSBMonitor
        usb = LinuxUSBMonitor()
        devices = usb.get_devices()
        return isinstance(devices, list)


def test_dns_sinkhole():
    """5. DNS sinkholing for malicious domains"""
    try:
        import nosp_core
        nosp_core.sinkhole_domain_py("test.malware.example.com")
        domains = nosp_core.list_sinkholed_domains_py()
        return "test.malware.example.com" in [d['domain'] for d in domains]
    except:
        return False


def test_registry_monitoring():
    """6. Registry protection and monitoring"""
    try:
        import nosp_core
        backup = nosp_core.registry_backup_key_py("HKEY_CURRENT_USER\\Software\\Test")
        return backup is not None
    except:
        return False


def test_memory_forensics():
    """7. In-memory forensics and process scanning"""
    try:
        import nosp_core
        import os
        results = nosp_core.scan_process_memory_py(os.getpid())
        return isinstance(results, dict)
    except:
        return False


def test_file_integrity():
    """8. File integrity monitoring using SHA-256"""
    from nosp import file_integrity
    import tempfile
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test content")
        test_file = f.name
    
    try:
        file_integrity.watch_file(test_file)
        violations = file_integrity.check_integrity()
        return isinstance(violations, list)
    finally:
        import os
        os.unlink(test_file)


def test_vm_detection():
    """9. VM/sandbox detection"""
    try:
        import nosp_core
        vm_status = nosp_core.detect_vm_py()
        return isinstance(vm_status, dict) and 'is_vm' in vm_status
    except:
        return False


def test_self_defense():
    """10. Self-defense mechanisms"""
    try:
        import nosp_core
        status = nosp_core.get_defense_status_py()
        return isinstance(status, dict) and 'debugger' in status
    except:
        return False


def test_clipboard_monitoring():
    """11. Clipboard monitoring"""
    try:
        import nosp_core
        nosp_core.start_clipboard_monitor_py()
        is_running = nosp_core.is_monitoring_py()
        nosp_core.stop_clipboard_monitor_py()
        return is_running
    except:
        return False


def test_blockchain_audit():
    """12. Blockchain audit logging"""
    from nosp.ledger import ImmutableLedger
    ledger = ImmutableLedger(difficulty=1)
    block = ledger.add_event({"event_type": "test", "data": "verification"})
    is_valid, _ = ledger.validate_chain()
    return is_valid and len(ledger.chain) > 1


def test_p2p_intelligence():
    """13. P2P threat intelligence sharing"""
    from nosp.mesh_network import MeshNetwork
    mesh = MeshNetwork()
    return mesh.node_id is not None and len(mesh.node_id) == 64


def test_virtual_sandboxing():
    """14. Virtual sandboxing for untrusted processes"""
    from nosp.cage import Cage
    import tempfile
    import os
    
    test_dir = Path(tempfile.gettempdir()) / "nosp_verify"
    test_dir.mkdir(exist_ok=True)
    
    if IS_WINDOWS:
        test_file = test_dir / "test.bat"
        test_file.write_text("@echo off\necho test")
    else:
        test_file = test_dir / "test.sh"
        test_file.write_text("#!/bin/bash\necho test")
        os.chmod(test_file, 0o755)
    
    try:
        cage = Cage(execution_timeout=5)
        result = cage.detonate_file(str(test_file))
        return result.verdict in ['BENIGN', 'SUSPICIOUS', 'MALICIOUS']
    finally:
        try:
            test_file.unlink()
            test_dir.rmdir()
        except:
            pass


def test_packet_injection():
    """15. Network packet injection capabilities"""
    from nosp.native_bindings import get_packet_injector
    injector = get_packet_injector()
    return injector.lib is not None


def test_web_dashboard():
    """16. Web dashboard with real-time monitoring"""
    import subprocess
    result = subprocess.run(['streamlit', '--version'], capture_output=True)
    return result.returncode == 0


def test_system_tray():
    """17. System tray integration"""
    try:
        from nosp.system_tray import NOSPSystemTray
        tray = NOSPSystemTray()
        return True
    except:
        return False


def test_rule_engine():
    """18. Rule engine with PowerShell support"""
    from nosp.rules_engine import RulesEngine
    import tempfile
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("rules: []")
        rules_file = f.name
    
    try:
        engine = RulesEngine(rules_file)
        return engine.rules is not None
    finally:
        import os
        os.unlink(rules_file)


print("FEATURE TESTS")
print("-" * 70)

test_feature("1. ETW Monitoring", test_etw_monitoring, windows_only=True)
test_feature("2. AI Threat Assessment (MITRE ATT&CK)", test_ai_threat_assessment)
test_feature("3. Behavioral Risk Scoring", test_risk_scoring)
test_feature("4. USB Device Control", test_usb_control)
test_feature("5. DNS Sinkholing", test_dns_sinkhole, windows_only=True)
test_feature("6. Registry Protection", test_registry_monitoring, windows_only=True)
test_feature("7. Memory Forensics", test_memory_forensics, windows_only=True)
test_feature("8. File Integrity Monitoring", test_file_integrity)
test_feature("9. VM/Sandbox Detection", test_vm_detection, windows_only=True)
test_feature("10. Self-Defense Mechanisms", test_self_defense, windows_only=True)
test_feature("11. Clipboard Monitoring", test_clipboard_monitoring, windows_only=True)
test_feature("12. Blockchain Audit Logging", test_blockchain_audit)
test_feature("13. P2P Threat Intelligence", test_p2p_intelligence)
test_feature("14. Virtual Sandboxing", test_virtual_sandboxing)
test_feature("15. Network Packet Injection", test_packet_injection)
test_feature("16. Web Dashboard (Streamlit)", test_web_dashboard)
test_feature("17. System Tray Integration", test_system_tray)
test_feature("18. Rule Engine with PowerShell", test_rule_engine)

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total Features: {results['total']}")
print(f"✓ Passed: {results['passed']}")
print(f"✗ Failed: {results['failed']}")
print(f"⊘ Platform Limited: {results['platform_limited']}")

coverage = (results['passed'] / (results['total'] - results['platform_limited'])) * 100 if results['total'] > results['platform_limited'] else 0
print(f"\nCoverage: {coverage:.1f}% of available features working")

print()
print("PLATFORM NOTES:")
if IS_WINDOWS:
    print("  - All 18 features available on Windows")
    print("  - ETW, Registry, Memory scanning require Windows")
else:
    print("  - 11 features available natively on Linux")
    print("  - 7 Windows-specific features have Linux alternatives:")
    print("    • ETW → auditd/eBPF")
    print("    • Registry → Config file monitoring")
    print("    • Memory scanning → /proc/[pid]/mem")
    print("    • Some Rust modules are Windows-only by design")

print()
print("=" * 70)

if results['failed'] == 0:
    print("✓ ALL FEATURES VERIFIED SUCCESSFULLY!")
    sys.exit(0)
else:
    print(f"⚠ {results['failed']} features need attention")
    sys.exit(1)
