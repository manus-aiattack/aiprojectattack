import importlib
import os
import sys
from typing import Dict, Any, List, TYPE_CHECKING
from core.logger import log

if TYPE_CHECKING:
    from core.agent_registry import AgentRegistry


class PluginManager:
    def __init__(self, agent_registry: 'AgentRegistry', plugin_dir: str = "plugins"):
        self.agent_registry = agent_registry
        self.plugin_dir = plugin_dir
        if self.plugin_dir not in sys.path:
            sys.path.insert(0, self.plugin_dir)

    def discover_and_load_plugins(self):
        """Discovers and loads agents from the plugin directory."""
        if not os.path.exists(self.plugin_dir):
            log.warning(
                f"Plugin directory '{self.plugin_dir}' not found. Skipping plugin loading.")
            return

        log.info(f"Discovering plugins from '{self.plugin_dir}'...")
        for item in os.listdir(self.plugin_dir):
            item_path = os.path.join(self.plugin_dir, item)
            if os.path.isdir(item_path):
                # Assuming each plugin is a directory containing its modules
                self._load_plugin_from_directory(item)

    def _load_plugin_from_directory(self, plugin_name: str):
        """Loads a single plugin from its directory."""
        try:
            # Assuming the main plugin file is named after the plugin directory
            module = importlib.import_module(f"{plugin_name}.{plugin_name}")
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                # Heuristic to find agent classes: ends with 'Agent' and has a 'run' method
                if isinstance(attr, type) and attr_name.endswith('Agent') and hasattr(attr, 'run'):
                    log.info(
                        f"Found plugin agent: {attr_name} in {plugin_name}")
                    # Here you would ideally run the plugin in a sandbox
                    # For now, we register it directly.
                    self.agent_registry.register_agent(attr_name, attr)
                    log.success(
                        f"Successfully loaded and registered plugin agent: {attr_name}")
        except ImportError as e:
            log.error(
                f"Failed to load plugin '{plugin_name}'. Could not import: {e}")
        except Exception as e:
            log.error(
                f"An unexpected error occurred while loading plugin '{plugin_name}': {e}")
