import os
import sys
from pathlib import Path

# Make ``src.*`` importable from tests without requiring an install.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Point secrets at a throwaway data dir so tests do not mutate the real one.
os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
