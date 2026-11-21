import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("SECOPS_API_KEYS", "test-key")
os.environ.setdefault("RATE_LIMIT_PER_MIN", "1000")
os.environ.setdefault("SERVICE_NAME", "xdr-triage-bridge")
