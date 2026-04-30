"""Reconciliation test: take a Ground Truth Pack and verify the snapshot matches.

Run:
  DOMINO_API_HOST=... API_KEY_OVERRIDE=... \
  python test_reconciliation.py ground_truth/matt.json

Ground Truth JSON shape:
  {
    "userName": "matt_tendler_domino",
    "expectedProjects": [{"projectName": "supply_risk_radar", "role": "Owner"}, ...],
    "expectedRoles": ["SysAdmin", "Practitioner"],
    "expectedVolumes": ["NetApp_App", "skill-test-volume"]
  }

Exit code:
  0  - all expectations matched
  1  - one or more failures (details printed)
  2  - setup error (couldn't reach Domino, ground truth invalid, etc.)
"""
from __future__ import annotations

import json
import os
import sys
from typing import Dict


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_reconciliation.py <ground_truth.json>", file=sys.stderr)
        return 2

    gt_path = sys.argv[1]
    try:
        with open(gt_path) as f:
            gt = json.load(f)
    except Exception as e:
        print(f"could not read {gt_path}: {e}", file=sys.stderr)
        return 2

    user_name = gt.get("userName")
    if not user_name:
        print("ground truth must include 'userName'", file=sys.stderr)
        return 2

    sys.path.insert(0, os.path.dirname(__file__))
    import snapshot as snapmod

    print(f"taking live snapshot for reconciliation against {user_name}…")
    snap = snapmod.take_snapshot(taken_by=f"reconciliation:{user_name}")

    user = next((u for u in snap.get("users", []) if u.get("userName") == user_name), None)
    if not user:
        print(f"FAIL: user {user_name} not found in snapshot")
        return 1
    uid = user.get("id")

    actual_projects: Dict[str, str] = {}
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if c.get("userId") == uid:
                actual_projects[p.get("name")] = c.get("role")
                break
    actual_roles = set(user.get("roles") or [])
    actual_volumes = set(
        v.get("name") for v in snap.get("volumes", [])
        if uid in (v.get("userIds") or [])
    )

    failures = []

    print()
    print(f"=== {user_name} ===")
    print(f"  global roles: {sorted(actual_roles) or '(none surfaced)'}")
    print(f"  privileged?   {user.get('isPrivileged')}")
    print(f"  projects:     {len(actual_projects)}")
    print(f"  volumes:      {len(actual_volumes)}")
    print()

    print("--- Projects ---")
    for exp in gt.get("expectedProjects") or []:
        name = exp.get("projectName")
        want = exp.get("role")
        got = actual_projects.get(name)
        ok = got is not None and (want is None or got == want)
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {name}: expected={want or '(any)'} actual={got or '(missing)'}")
        if not ok:
            failures.append(("project", name, want, got))

    print()
    print("--- Global roles ---")
    for r in gt.get("expectedRoles") or []:
        ok = r in actual_roles
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {r}")
        if not ok:
            failures.append(("role", r, "present", "absent"))

    print()
    print("--- Volumes ---")
    for v in gt.get("expectedVolumes") or []:
        ok = v in actual_volumes
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {v}")
        if not ok:
            failures.append(("volume", v, "accessible", "not accessible"))

    print()
    if not failures:
        print("All expectations matched.")
        return 0
    print(f"{len(failures)} failure(s).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
