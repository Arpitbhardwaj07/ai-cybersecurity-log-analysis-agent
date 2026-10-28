"""Root wrapper for evaluate.py"""

import sys
from pathlib import Path

# Add log_agent to path
root = Path(__file__).resolve().parent
log_agent_dir = root / "log_agent"
sys.path.insert(0, str(log_agent_dir))

from evaluate import evaluate

if __name__ == "__main__":
    csv_file = log_agent_dir / "data" / "logs.csv"
    gt_file = log_agent_dir / "data" / "ground_truth.json"
    evaluate(str(csv_file), str(gt_file))

