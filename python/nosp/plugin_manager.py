"""
NOSP vOMEGA - Plugin System
Extensible architecture for custom event processors and analyzers
"""

import importlib.util
import inspect
import logging
from typing import Dict, List, Any, Callable, Optional
from pathlib import Path
from dataclasses import dataclass
import traceback

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Metadata about a loaded plugin"""
    name: str
    version: str
    author: str
    description: str
    file_path: str
    enabled: bool = True


class PluginBase:
    """
    Base class for NOSP plugins
    
    Plugins can override these methods:
    - on_event(event): Process each security event
    - on_init(): Called when plugin is loaded
    - on_shutdown(): Called when plugin is unloaded
    - get_info(): Return plugin metadata
    """
    
    def get_info(self) -> Dict[str, str]:
        """Return plugin metadata"""
        return {
            'name': self.__class__.__name__,
            'version': '1.0',
            'author': 'Unknown',
            'description': 'No description'
        }
    
    def on_init(self):
        """Called when plugin is loaded"""
        pass
    
    def on_shutdown(self):
        """Called when plugin is unloaded"""
        pass
    
    def on_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a security event
        
        Args:
            event: Security event dictionary
        
        Returns:
            Modified event dictionary, or None to filter event out
        """
        return event


class PluginManager:
    """
    Plugin system manager
    
    Features:
    - Hot-reload plugins from directory
    - Event pipeline with multiple plugins
    - Plugin enable/disable
    - Error isolation (failed plugins don't crash system)
    - Plugin statistics
    """
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        
        self.plugins: Dict[str, PluginBase] = {}
        self.plugin_info: Dict[str, PluginInfo] = {}
        
        self.stats = {
            'loaded': 0,
            'enabled': 0,
            'disabled': 0,
            'failed': 0,
            'events_processed': 0
        }
        
        # Create example plugin if none exist
        self._create_example_plugins()
        
        # Load all plugins
        self.load_all_plugins()
    
    def load_plugin(self, plugin_path: Path) -> bool:
        """
        Load a single plugin from file
        
        Args:
            plugin_path: Path to plugin .py file
        
        Returns:
            True if loaded successfully
        """
        try:
            # Load module
            spec = importlib.util.spec_from_file_location(
                plugin_path.stem,
                plugin_path
            )
            
            if spec is None or spec.loader is None:
                logger.error(f"Failed to load plugin spec: {plugin_path}")
                return False
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes (subclasses of PluginBase)
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, PluginBase) and obj != PluginBase:
                    plugin_classes.append(obj)
            
            if not plugin_classes:
                logger.warning(f"No plugin classes found in {plugin_path}")
                return False
            
            # Instantiate first plugin class found
            plugin_class = plugin_classes[0]
            plugin = plugin_class()
            
            # Get plugin info
            info = plugin.get_info()
            plugin_name = info['name']
            
            # Store plugin
            self.plugins[plugin_name] = plugin
            self.plugin_info[plugin_name] = PluginInfo(
                name=plugin_name,
                version=info.get('version', '1.0'),
                author=info.get('author', 'Unknown'),
                description=info.get('description', 'No description'),
                file_path=str(plugin_path),
                enabled=True
            )
            
            # Initialize plugin
            plugin.on_init()
            
            logger.info(f"✓ Loaded plugin: {plugin_name} v{info.get('version', '1.0')}")
            self.stats['loaded'] += 1
            self.stats['enabled'] += 1
            return True
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_path}: {e}")
            logger.debug(traceback.format_exc())
            self.stats['failed'] += 1
            return False
    
    def load_all_plugins(self) -> int:
        """
        Load all plugins from plugins directory
        
        Returns:
            Number of plugins loaded
        """
        loaded = 0
        
        # Find all .py files
        plugin_files = list(self.plugins_dir.glob("*.py"))
        
        if not plugin_files:
            logger.info("No plugins found in plugins directory")
            return 0
        
        logger.info(f"Loading plugins from {self.plugins_dir}...")
        
        for plugin_file in plugin_files:
            # Skip __init__.py and private files
            if plugin_file.name.startswith('_'):
                continue
            
            if self.load_plugin(plugin_file):
                loaded += 1
        
        logger.info(f"Loaded {loaded}/{len(plugin_files)} plugins")
        return loaded
    
    def reload_plugins(self) -> int:
        """
        Reload all plugins (hot-reload)
        
        Returns:
            Number of plugins loaded
        """
        logger.info("Hot-reloading plugins...")
        
        # Shutdown existing plugins
        for plugin_name, plugin in self.plugins.items():
            try:
                plugin.on_shutdown()
            except:
                pass
        
        # Clear plugins
        self.plugins.clear()
        self.plugin_info.clear()
        self.stats = {
            'loaded': 0,
            'enabled': 0,
            'disabled': 0,
            'failed': 0,
            'events_processed': self.stats['events_processed']
        }
        
        # Reload
        return self.load_all_plugins()
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        if plugin_name not in self.plugin_info:
            return False
        
        if not self.plugin_info[plugin_name].enabled:
            self.plugin_info[plugin_name].enabled = True
            self.stats['enabled'] += 1
            self.stats['disabled'] -= 1
            logger.info(f"Enabled plugin: {plugin_name}")
        
        return True
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        if plugin_name not in self.plugin_info:
            return False
        
        if self.plugin_info[plugin_name].enabled:
            self.plugin_info[plugin_name].enabled = False
            self.stats['enabled'] -= 1
            self.stats['disabled'] += 1
            logger.info(f"Disabled plugin: {plugin_name}")
        
        return True
    
    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Pass event through plugin pipeline
        
        Args:
            event: Security event dictionary
        
        Returns:
            Modified event, or None if filtered out
        """
        self.stats['events_processed'] += 1
        
        current_event = event
        
        # Process through each enabled plugin
        for plugin_name, plugin in self.plugins.items():
            # Skip disabled plugins
            if not self.plugin_info[plugin_name].enabled:
                continue
            
            try:
                # Process event
                current_event = plugin.on_event(current_event)
                
                # If plugin filters out event (returns None), stop pipeline
                if current_event is None:
                    logger.debug(f"Event filtered by plugin: {plugin_name}")
                    return None
                    
            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}")
                logger.debug(traceback.format_exc())
                # Continue with other plugins
                continue
        
        return current_event
    
    def get_plugins_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded plugins"""
        return [
            {
                'name': info.name,
                'version': info.version,
                'author': info.author,
                'description': info.description,
                'enabled': info.enabled,
                'file_path': info.file_path
            }
            for info in self.plugin_info.values()
        ]
    
    def get_stats(self) -> Dict[str, int]:
        """Get plugin system statistics"""
        return self.stats.copy()
    
    def _create_example_plugins(self):
        """Create example plugins if none exist"""
        example1 = self.plugins_dir / "example_logger.py"
        example2 = self.plugins_dir / "example_filter.py"
        
        if not example1.exists():
            with open(example1, 'w') as f:
                f.write('''"""
Example NOSP Plugin: Event Logger
Logs all events to a separate file
"""

from pathlib import Path
import json
from datetime import datetime
import sys

# Add NOSP to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from python.nosp.plugin_manager import PluginBase


class EventLoggerPlugin(PluginBase):
    """Logs all events to events.log"""
    
    def get_info(self):
        return {
            'name': 'EventLogger',
            'version': '1.0',
            'author': 'NOSP Team',
            'description': 'Logs all events to a file'
        }
    
    def on_init(self):
        self.log_file = Path("events.log")
        print(f"[EventLogger] Initialized, logging to {self.log_file}")
    
    def on_event(self, event):
        """Log event to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(event) + "\\n")
        except:
            pass
        
        return event  # Pass through unchanged
    
    def on_shutdown(self):
        print("[EventLogger] Shutting down")
''')
        
        if not example2.exists():
            with open(example2, 'w') as f:
                f.write('''"""
Example NOSP Plugin: High Risk Filter
Only passes through events with risk score > 50
"""

from pathlib import Path
import sys

# Add NOSP to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from python.nosp.plugin_manager import PluginBase


class HighRiskFilterPlugin(PluginBase):
    """Filters out low-risk events"""
    
    def get_info(self):
        return {
            'name': 'HighRiskFilter',
            'version': '1.0',
            'author': 'NOSP Team',
            'description': 'Only shows events with risk score > 50'
        }
    
    def on_init(self):
        self.threshold = 50
        self.filtered_count = 0
        print(f"[HighRiskFilter] Initialized, threshold={self.threshold}")
    
    def on_event(self, event):
        """Filter by risk score"""
        risk_score = event.get('risk_score', 0)
        
        if risk_score <= self.threshold:
            self.filtered_count += 1
            return None  # Filter out
        
        return event  # Pass through
    
    def on_shutdown(self):
        print(f"[HighRiskFilter] Filtered {self.filtered_count} events")
''')
        
        logger.info("Created example plugins")


def create_plugin_manager(plugins_dir: str = "plugins") -> PluginManager:
    """Create and initialize plugin manager"""
    return PluginManager(plugins_dir)
