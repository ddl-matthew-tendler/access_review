"""Report builders. Each takes a snapshot dict and returns rows ready for a table."""
from __future__ import annotations
from datetime import datetime, timezone
from dateutil import parser as dtparser
from typing import Dict, List, Optional


def _user_index(snap: Dict) -> Dict[str, Dict]:
    return {u["id"]: u for u in snap.get("users", []) if u.get("id")}


def _project_index(snap: Dict) -> Dict[str, Dict]:
    return {p["id"]: p for p in snap.get("projects", []) if p.get("id")}


def _days_since(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        dt = dtparser.parse(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def access_listing(snap: Dict) -> List[Dict]:
    """User x Project x Role — the workhorse table."""
    users = _user_index(snap)
    rows: List[Dict] = []
    for proj in snap.get("projects", []):
        for c in proj.get("collaborators", []):
            uid = c.get("userId")
            u = users.get(uid, {})
            rows.append({
                "userId": uid,
                "userName": c.get("userName") or u.get("userName"),
                "fullName": u.get("fullName"),
                "email": u.get("email"),
                "status": u.get("status"),
                "licenseType": u.get("licenseType"),
                "projectId": proj.get("id"),
                "projectName": proj.get("name"),
                "role": c.get("role"),
                "grantedAt": c.get("grantedAt"),
                "grantedBy": c.get("grantedBy"),
                "lastLogin": u.get("lastLogin"),
                "daysSinceLogin": _days_since(u.get("lastLogin")),
            })
    return rows


def project_role_matrix(snap: Dict, project_id: str) -> Dict:
    """All users for a single project, plus that project's datasets and volumes."""
    proj = _project_index(snap).get(project_id)
    if not proj:
        return {}
    users = _user_index(snap)
    user_rows = []
    for c in proj.get("collaborators", []):
        u = users.get(c.get("userId"), {})
        user_rows.append({
            "userId": c.get("userId"),
            "userName": c.get("userName") or u.get("userName"),
            "email": u.get("email"),
            "role": c.get("role"),
            "status": u.get("status"),
            "lastLogin": u.get("lastLogin"),
        })
    project_datasets = [d for d in snap.get("datasets", []) if d.get("projectId") == project_id]
    project_volumes = [
        {**v, "accessKind": "project-mount"}
        for v in snap.get("volumes", []) if project_id in (v.get("projectIds") or [])
    ]
    return {
        "project": {"id": proj.get("id"), "name": proj.get("name"), "owner": proj.get("owner")},
        "users": user_rows,
        "datasets": project_datasets,
        "volumes": project_volumes,
    }


def privileged_users(snap: Dict) -> List[Dict]:
    rows = []
    for u in snap.get("users", []):
        if not u.get("isPrivileged"):
            continue
        rows.append({
            "userId": u.get("id"),
            "userName": u.get("userName"),
            "fullName": u.get("fullName"),
            "email": u.get("email"),
            "roles": u.get("roles") or [],
            "status": u.get("status"),
            "mfaEnabled": u.get("mfaEnabled"),
            "lastLogin": u.get("lastLogin"),
            "daysSinceLogin": _days_since(u.get("lastLogin")),
        })
    return rows


def dormant_users(snap: Dict, threshold_days: int = 90) -> List[Dict]:
    rows = []
    for u in snap.get("users", []):
        days = _days_since(u.get("lastLogin"))
        if u.get("status") == "Disabled":
            recommendation = "Disabled — confirm offboarded"
        elif days is None:
            recommendation = "No login record — investigate"
        elif days >= 180:
            recommendation = "Disable account (>180d inactive)"
        elif days >= threshold_days:
            recommendation = f"Review (>{threshold_days}d inactive)"
        else:
            continue
        rows.append({
            "userId": u.get("id"),
            "userName": u.get("userName"),
            "fullName": u.get("fullName"),
            "email": u.get("email"),
            "status": u.get("status"),
            "lastLogin": u.get("lastLogin"),
            "daysSinceLogin": days,
            "recommendation": recommendation,
        })
    rows.sort(key=lambda r: r.get("daysSinceLogin") or 9999, reverse=True)
    return rows


def volume_access(snap: Dict) -> List[Dict]:
    """Per-(volume, principal) row covering NetApp/NFS/SMB/EFS external volumes.

    Permission column carries the audit-projected `userGrants[uid]` role
    (Owner / Editor / Reader) when available; falls back to read/read-write
    inferred from `readOnly` for project-mount and public-mount rows.
    """
    users = _user_index(snap)
    projects = _project_index(snap)
    rows: List[Dict] = []
    for v in snap.get("volumes", []):
        user_grants = v.get("userGrants") or {}
        fallback = "read" if v.get("readOnly") else "read/write"
        if v.get("isPublic"):
            rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "mountPath": v.get("mountPath"),
                "readOnly": v.get("readOnly"),
                "principalType": "Public",
                "principalName": "All Users",
                "permission": fallback,
                "via": "isPublic",
                "discoveredVia": v.get("discoveredVia"),
            })
        for uid in v.get("userIds") or []:
            u = users.get(uid, {})
            rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "mountPath": v.get("mountPath"),
                "readOnly": v.get("readOnly"),
                "principalType": "User",
                "principalId": uid,
                "principalName": u.get("userName") or uid,
                "permission": user_grants.get(uid) or fallback,
                "via": "direct user grant",
                "discoveredVia": v.get("discoveredVia"),
            })
        for pid in v.get("projectIds") or []:
            p = projects.get(pid, {})
            rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "mountPath": v.get("mountPath"),
                "readOnly": v.get("readOnly"),
                "principalType": "Project",
                "principalId": pid,
                "principalName": p.get("name") or pid,
                "permission": fallback,
                "via": "project mount",
                "discoveredVia": v.get("discoveredVia"),
            })
    return rows
