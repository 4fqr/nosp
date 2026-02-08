"""
NOSP vAPEX - Session Persistence Manager
Auto-save and restore Streamlit session state across refreshes
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
import threading
import time

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages Streamlit session state persistence
    
    Features:
    - Auto-save session state every N seconds
    - Restore session on startup
    - Exclude non-serializable objects
    - Thread-safe background saving
    """
    
    def __init__(self, session_file: str = "session.json", auto_save_interval: int = 10):
        self.session_file = Path(session_file)
        self.auto_save_interval = auto_save_interval
        self.auto_save_enabled = False
        self._save_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Keys to exclude from serialization
        self.exclude_keys = {
            'db',  # Database connection
            'ai_engine',  # AI engine with model
            'alert_system',  # Audio system
            'system_tray',  # System tray icon
            'process_tree',  # NetworkX graph
            'forensic_reporter',  # Reporter with file handles
            'rules_engine',  # Rules engine
            'ml_detector',  # ML model
            'plugin_manager',  # Plugin manager
            'alert_manager',  # Alert manager
            '_is_running',  # Runtime flags
        }
    
    def save_session(self, session_state: Dict[str, Any]) -> bool:
        """
        Save session state to JSON file
        
        Args:
            session_state: Streamlit session_state dict
        
        Returns:
            True if saved successfully
        """
        try:
            # Filter out non-serializable objects
            serializable_state = self._make_serializable(session_state)
            
            # Add metadata
            serializable_state['_saved_at'] = datetime.now().isoformat()
            serializable_state['_version'] = 'vAPEX'
            
            # Write to file
            with open(self.session_file, 'w') as f:
                json.dump(serializable_state, f, indent=2)
            
            logger.debug(f"Session saved to {self.session_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False
    
    def load_session(self) -> Optional[Dict[str, Any]]:
        """
        Load session state from JSON file
        
        Returns:
            Dictionary of restored state, or None if not found
        """
        if not self.session_file.exists():
            logger.info("No saved session found")
            return None
        
        try:
            with open(self.session_file, 'r') as f:
                state = json.load(f)
            
            # Remove metadata
            saved_at = state.pop('_saved_at', None)
            version = state.pop('_version', None)
            
            logger.info(f"Session restored from {saved_at} (version: {version})")
            return state
            
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return None
    
    def _make_serializable(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Filter out non-serializable objects from state
        
        Args:
            state: Raw session state
        
        Returns:
            Filtered dictionary with only JSON-serializable values
        """
        serializable = {}
        
        for key, value in state.items():
            # Skip excluded keys
            if key in self.exclude_keys:
                continue
            
            # Skip private keys (start with _)
            if key.startswith('_'):
                continue
            
            # Try to serialize
            try:
                json.dumps(value)  # Test if serializable
                serializable[key] = value
            except (TypeError, ValueError):
                logger.debug(f"Skipping non-serializable key: {key}")
                continue
        
        return serializable
    
    def start_auto_save(self, session_state: Dict[str, Any]):
        """
        Start background auto-save thread
        
        Args:
            session_state: Streamlit session_state to monitor
        """
        if self.auto_save_enabled:
            logger.warning("Auto-save already running")
            return
        
        self.auto_save_enabled = True
        self._stop_event.clear()
        
        def auto_save_worker():
            logger.info(f"Auto-save started (interval: {self.auto_save_interval}s)")
            
            while not self._stop_event.is_set():
                # Wait for interval or stop signal
                if self._stop_event.wait(self.auto_save_interval):
                    break  # Stop signal received
                
                # Save session
                self.save_session(session_state)
        
        self._save_thread = threading.Thread(target=auto_save_worker, daemon=True)
        self._save_thread.start()
    
    def stop_auto_save(self):
        """Stop background auto-save thread"""
        if not self.auto_save_enabled:
            return
        
        logger.info("Stopping auto-save...")
        self.auto_save_enabled = False
        self._stop_event.set()
        
        if self._save_thread:
            self._save_thread.join(timeout=2)
        
        logger.info("Auto-save stopped")
    
    def restore_to_session_state(self, target_state: Any) -> bool:
        """
        Restore saved session to Streamlit session_state
        
        Args:
            target_state: Streamlit st.session_state object
        
        Returns:
            True if restored successfully
        """
        saved_state = self.load_session()
        
        if saved_state is None:
            return False
        
        try:
            # Restore each key
            for key, value in saved_state.items():
                target_state[key] = value
            
            logger.info(f"Restored {len(saved_state)} session keys")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore session: {e}")
            return False
    
    def clear_session(self) -> bool:
        """Delete saved session file"""
        try:
            if self.session_file.exists():
                self.session_file.unlink()
                logger.info("Session file deleted")
            return True
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get information about saved session"""
        if not self.session_file.exists():
            return {
                'exists': False,
                'path': str(self.session_file)
            }
        
        try:
            with open(self.session_file, 'r') as f:
                state = json.load(f)
            
            return {
                'exists': True,
                'path': str(self.session_file),
                'saved_at': state.get('_saved_at', 'Unknown'),
                'version': state.get('_version', 'Unknown'),
                'keys_count': len([k for k in state.keys() if not k.startswith('_')]),
                'file_size': self.session_file.stat().st_size
            }
        except Exception as e:
            return {
                'exists': True,
                'path': str(self.session_file),
                'error': str(e)
            }


def create_session_manager(session_file: str = "session.json", auto_save_interval: int = 10) -> SessionManager:
    """Create and initialize a session manager"""
    return SessionManager(session_file, auto_save_interval)
