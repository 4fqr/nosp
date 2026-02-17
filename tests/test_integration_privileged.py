import os
import sys
from pathlib import Path
import pytest

# make package importable
sys.path.insert(0, str(Path(__file__).parent.parent / 'python'))

from nosp.native_bindings import PacketInjector, PacketCapture

RUN_PRIV = os.getenv('RUN_PRIV_TESTS') == '1'


@pytest.mark.skipif(not RUN_PRIV, reason="Privileged tests disabled. Set RUN_PRIV_TESTS=1 to enable.")
def test_packet_injector_initialize_privileged():
    inj = PacketInjector()
    res = inj.initialize()
    # on a privileged host this should succeed; assert boolean
    assert isinstance(res, bool)


@pytest.mark.skipif(not RUN_PRIV, reason="Privileged tests disabled. Set RUN_PRIV_TESTS=1 to enable.")
def test_packet_capture_start_privileged():
    cap = PacketCapture()
    res = cap.start()
    assert isinstance(res, bool)
