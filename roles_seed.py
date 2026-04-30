"""Bootstrap roles seed — closes the audit-window gap.

The audit trail records every "Update User Global Roles" event going forward,
but it can't recover roles that were assigned before audit retention started.
A SysAdmin role granted at deployment time will be missing from the projection.

This module loads `roles_seed.json` (if present) — a simple
{userName: [role,...]} or {userId: [role,...]} mapping — and merges it into
the snapshot as a fourth source of truth, behind:
  1. /v4/auth/principal.isAdmin (calling identity)
  2. /v4/organizations.members[].role
  3. Audit-trail projection (Update User Global Roles events)
  4. Bootstrap roles_seed.json  ← this file

The seed should be populated once from the customer's admin export, then the
audit trail keeps it current automatically.

Format (roles_seed.json — adjacent to app.py or in /domino/datasets/local/):
  {
    "_capturedAt": "2026-04-30",
    "_source": "Initial admin export from life-sciences-demo Edit User screens",
    "users": {
      "matt_tendler_domino": ["Practitioner", "SysAdmin"],
      "ross_domino":         ["Practitioner", "GovernanceAdmin"]
    }
  }
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

_LOCATIONS = [
    Path("/domino/datasets/local/access_review/roles_seed.json"),
    Path(__file__).parent / "roles_seed.json",
]


def _log(msg: str) -> None:
    print(f"[roles_seed] {msg}", file=sys.stdout, flush=True)


def load() -> Dict:
    for p in _LOCATIONS:
        if p.exists():
            try:
                with open(p) as f:
                    data = json.load(f)
                _log(f"loaded {p} ({len(data.get('users') or {})} entries)")
                return data
            except Exception as e:
                _log(f"could not parse {p}: {e}")
    return {}


def roles_for(seed: Dict, user_name: Optional[str], user_id: Optional[str]) -> List[str]:
    users = (seed or {}).get("users") or {}
    if user_name and user_name in users:
        return list(users[user_name] or [])
    if user_id and user_id in users:
        return list(users[user_id] or [])
    return []


def metadata(seed: Dict) -> Dict:
    return {
        "loaded": bool(seed),
        "capturedAt": seed.get("_capturedAt"),
        "source": seed.get("_source"),
        "userCount": len(seed.get("users") or {}),
    }
