"""Root wrapper for app.py"""

import sys
from pathlib import Path

# Add log_agent to path
root = Path(__file__).resolve().parent
log_agent_dir = root / "log_agent"
sys.path.insert(0, str(log_agent_dir))

# Execute log_agent/app.py
with open(log_agent_dir / "app.py", "r", encoding="utf-8") as f:
    code = f.read()
exec(code, {"__name__": "__main__", "__file__": str(log_agent_dir / "app.py")})

