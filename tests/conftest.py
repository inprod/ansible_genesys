"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

# Add the plugins directory to path for imports
plugins_path = Path(__file__).parent.parent.parent / "plugins" / "modules"
sys.path.insert(0, str(plugins_path))
