"""Rend importables les modules du projet (emby_proxy, emby_quota) et le faux
serveur Emby des tests de quotas (mock_emby)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "tests"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
