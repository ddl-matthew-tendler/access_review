"""Snapshot capture, persistence, and diffing.

A snapshot is an immutable, point-in-time JSON record of who-has-access-to-what
across users, projects, datasets, and external data volumes (NetApp/NFS/SMB/EFS).
Snapshots are written to /domino/datasets/local/access_review/snapshots/ when
that path is available, otherwise to a local ./snapshots dir for dev.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import domino_client as dc
import audit_projection
import roles_seed


DOMINO_DATASET_DIR = Path("/domino/datasets/local/access_review/snapshots")
LOCAL_FALLBACK_DIR = Path(__file__).parent / "snapshots"

PRIVILEGED_ROLES = {
    "SysAdmin", "SystemAdministrator", "Admin",
    "OrgOwner", "EnvAdmin", "DataSourceAdmin",
}


def _log(msg: str) -> None:
    print(f"[snapshot] {msg}", file=sys.stdout, flush=True)


def snapshot_dir() -> Path:
    if DOMINO_DATASET_DIR.parent.exists():
        DOMINO_DATASET_DIR.mkdir(parents=True, exist_ok=True)
        return DOMINO_DATASET_DIR
    LOCAL_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
    return LOCAL_FALLBACK_DIR


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


PRIVILEGED_ROLE_NAMES = {
    "SysAdmin", "GovernanceAdmin", "LimitedAdmin", "SupportStaff",
    "ProjectManager", "Librarian", "ReadOnlySupportStaff",
}


def _last_login_map(users: List[Dict], lookback_days: int = 180) -> Dict[str, str]:
    """Derive last-login per user from audit events. Many Domino releases do
    not expose /auditevents publicly — this returns an empty map silently in
    that case, and dormant detection falls back to "no login record" guidance.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    events = dc.list_audit_events(
        start_iso=start.isoformat(),
        end_iso=end.isoformat(),
        event_type="UserLogin",
    )
    if not events:
        return {}
    out: Dict[str, str] = {}
    for ev in events:
        uid = ev.get("userId") or ev.get("actor") or ev.get("subjectId")
        ts = ev.get("timestamp") or ev.get("eventTime")
        if not uid or not ts:
            continue
        prev = out.get(uid)
        if prev is None or ts > prev:
            out[uid] = ts
    return out


def _user_role_flags(user: Dict) -> List[str]:
    """Flatten role fields. /v4/users does NOT include roles per user — only
    /v4/users/self does, which means we can only mark roles for users that the
    calling identity is. For everyone else we leave roles empty unless an
    org-membership 'Admin' role is present.
    """
    roles: List[str] = []
    for key in ("roles", "systemRoles", "organizationRoles", "permissionsLevel"):
        v = user.get(key)
        if isinstance(v, list):
            roles.extend([str(x) for x in v if x])
        elif isinstance(v, str):
            roles.append(v)
    if user.get("isAdmin"):
        roles.append("SysAdmin")
    return sorted(set(roles))


def take_snapshot(taken_by: str = "system") -> Dict:
    """Capture full who-has-access-to-what across the deployment."""
    snap_id = f"snap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}"
    _log(f"taking snapshot {snap_id}")

    users_raw = dc.list_users()
    orgs = dc.list_organizations()
    projects_raw = dc.list_projects()
    datasets_raw = dc.list_datasets()
    volumes_raw = dc.list_data_mounts()
    principal = dc.get_principal()

    # Audit-trail-driven projection: replays every event so we can recover
    # state the resource APIs hide (per-user roles, all NetApp grants/mounts,
    # last login). See audit_projection.py.
    _log("fetching audit events for projection")
    events = dc.list_audit_events()
    projection = audit_projection.project(events)
    _log(f"projected from {projection.get('totalEvents')} events: "
         f"{len(projection.get('userGlobalRoles', {}))} user-role records, "
         f"{len(projection.get('volumeGrants', {}))} volume-grant records, "
         f"{len(projection.get('discoveredVolumes', {}))} volumes seen")

    last_login = projection.get("lastLogin") or {}

    # /v4/users in current Domino releases does NOT expose per-user roles or
    # last-login. We can flag only the calling identity's privilege from
    # /v4/auth/principal.isAdmin. Roles for other users surface only via
    # org-Admin membership (read below) — this is a known limitation.
    org_admin_user_ids = set()
    for org in orgs:
        for m in (org.get("members") or []):
            if (m.get("role") == "Admin") and m.get("id"):
                org_admin_user_ids.add(m["id"])

    self_id = principal.get("canonicalId")
    self_is_admin = bool(principal.get("isAdmin"))

    projected_user_roles = projection.get("userGlobalRoles") or {}
    seed = roles_seed.load()

    users: List[Dict] = []
    for u in users_raw:
        uid = u.get("id") or u.get("userId") or u.get("_id")
        uname = u.get("userName") or u.get("loginName") or u.get("name")
        first = (u.get("firstName") or "").strip()
        last = (u.get("lastName") or "").strip()
        roles: Set[str] = set(_user_role_flags(u))
        role_sources: List[str] = []
        if uid == self_id and self_is_admin:
            roles.add("SysAdmin"); role_sources.append("auth/principal")
        if uid in org_admin_user_ids:
            roles.add("OrgAdmin"); role_sources.append("organizations")
        ar = projected_user_roles.get(uid, {}).get("roles") or []
        if ar:
            for r in ar:
                roles.add(r)
            role_sources.append("audit-projection")
        seeded = roles_seed.roles_for(seed, uname, uid)
        if seeded:
            for r in seeded:
                roles.add(r)
            role_sources.append("seed")
        role_list = sorted(roles)
        users.append({
            "id": uid,
            "userName": u.get("userName") or u.get("loginName") or u.get("name"),
            "fullName": u.get("fullName") or (first + " " + last).strip(),
            "email": u.get("email") or u.get("emailAddress"),
            "status": "Active",
            "licenseType": u.get("licenseType") or u.get("licenseTier") or "Standard",
            "mfaEnabled": bool(u.get("mfaEnabled")),
            "roles": role_list,
            "roleSources": role_sources,
            "isPrivileged": any(
                r in PRIVILEGED_ROLES or r in PRIVILEGED_ROLE_NAMES or r == "OrgAdmin"
                for r in role_list
            ),
            "lastLogin": last_login.get(uid),
            "createdAt": u.get("createdAt") or u.get("created"),
        })

    user_index = {u["id"]: u for u in users if u.get("id")}

    projects: List[Dict] = []
    for p in projects_raw:
        pid = p.get("id") or p.get("projectId")
        owner = p.get("ownerUsername") or (p.get("owner") or {}).get("userName")
        owner_id = (p.get("owner") or {}).get("id") or p.get("ownerId")
        # /v4/projects already embeds collaborators inline.
        inline_collabs = p.get("collaborators") or []
        collaborators = []
        if owner_id:
            collaborators.append({
                "userId": owner_id,
                "userName": owner,
                "role": "Owner",
                "grantedAt": p.get("createdAt"),
                "grantedBy": "system",
            })
        for c in inline_collabs:
            cid = c.get("collaboratorId") or c.get("id") or (c.get("collaborator") or {}).get("id")
            cname = c.get("userName") or (c.get("collaborator") or {}).get("userName")
            if not cname and cid:
                u = next((x for x in users_raw if x.get("id") == cid), {})
                cname = u.get("userName")
            collaborators.append({
                "userId": cid,
                "userName": cname,
                "role": c.get("projectRole") or c.get("role") or "Contributor",
                "grantedAt": c.get("createdAt"),
                "grantedBy": c.get("grantedBy"),
            })
        projects.append({
            "id": pid,
            "name": p.get("name"),
            "owner": owner,
            "ownerId": owner_id,
            "visibility": p.get("visibility"),
            "collaborators": collaborators,
        })

    projected_ds_grants = projection.get("datasetGrants") or {}
    user_id_to_name = {u["id"]: u.get("userName") for u in users if u.get("id")}

    datasets: List[Dict] = []
    seen_ds_ids = set()
    for d in datasets_raw:
        did = d.get("id") or d.get("datasetId")
        seen_ds_ids.add(did)
        # Try direct API; fall back to audit-projected grants.
        grants_raw = dc.list_dataset_grants(did) if did else []
        grants_out: List[Dict] = []
        if grants_raw:
            for g in grants_raw:
                grants_out.append({
                    "principalType": g.get("principalType") or g.get("targetType") or "User",
                    "principalId": g.get("principalId") or g.get("targetId"),
                    "principalName": g.get("principalName"),
                    "permission": audit_projection.normalize_grant_role(
                        g.get("permission") or g.get("grantType")),
                    "source": "datasetrw-api",
                })
        else:
            for uid, role in (projected_ds_grants.get(did, {}).get("grants") or {}).items():
                grants_out.append({
                    "principalType": "User",
                    "principalId": uid,
                    "principalName": user_id_to_name.get(uid),
                    "permission": audit_projection.normalize_grant_role(role),
                    "source": "audit-projection",
                })
        datasets.append({
            "id": did,
            "name": d.get("name") or d.get("datasetName"),
            "projectId": d.get("projectId"),
            "grants": grants_out,
        })

    # Append datasets we discovered ONLY via audit projection (where the
    # datasetrw API has hidden them from us).
    for did, ds in projected_ds_grants.items():
        if did in seen_ds_ids:
            continue
        datasets.append({
            "id": did,
            "name": ds.get("name"),
            "projectId": None,
            "discoveredVia": "audit-only",
            "grants": [
                {
                    "principalType": "User",
                    "principalId": uid,
                    "principalName": user_id_to_name.get(uid),
                    "permission": audit_projection.normalize_grant_role(role),
                    "source": "audit-projection",
                }
                for uid, role in (ds.get("grants") or {}).items()
            ],
        })

    projected_vol_grants = projection.get("volumeGrants") or {}
    projected_vol_projects = projection.get("volumeProjects") or {}
    discovered_vols = projection.get("discoveredVolumes") or {}

    volumes: List[Dict] = []
    seen_vol_ids = set()
    for v in volumes_raw:
        vid = v.get("id")
        seen_vol_ids.add(vid)
        ag = projected_vol_grants.get(vid) or {}
        ap = projected_vol_projects.get(vid) or []
        # Always merge projected user grants (audit-trail view is authoritative
        # because /v4/datamount/all filters by accessibility).
        merged_users = list(set((v.get("users") or []) + list((ag.get("grants") or {}).keys())))
        merged_projects = list(set((v.get("projects") or []) + list(ap)))
        volumes.append({
            "id": vid,
            "name": v.get("name") or ag.get("name"),
            "volumeType": v.get("volumeType") or "Nfs",  # NetApp volumes are NFS-backed
            "mountPath": v.get("mountPath"),
            "readOnly": bool(v.get("readOnly")),
            "isPublic": bool(v.get("isPublic")),
            "userIds": merged_users,
            "projectIds": merged_projects,
            "status": v.get("status"),
            "userGrants": {uid: audit_projection.normalize_grant_role(role)
                            for uid, role in (ag.get("grants") or {}).items()},
            "discoveredVia": "datamount-api",
        })

    # Volumes discovered ONLY via audit trail (the datamount API hid them).
    for vid, ag in projected_vol_grants.items():
        if vid in seen_vol_ids:
            continue
        meta = discovered_vols.get(vid, {})
        if meta.get("deleted"):
            continue
        volumes.append({
            "id": vid,
            "name": ag.get("name") or meta.get("name"),
            "volumeType": "Nfs",
            "mountPath": None,
            "readOnly": False,
            "isPublic": False,
            "userIds": list((ag.get("grants") or {}).keys()),
            "projectIds": list(projected_vol_projects.get(vid) or []),
            "status": meta.get("deleted") and "Deleted" or "Active",
            "userGrants": {uid: audit_projection.normalize_grant_role(role)
                            for uid, role in (ag.get("grants") or {}).items()},
            "discoveredVia": "audit-only",
            "createdAt": meta.get("createdAt"),
            "createdBy": meta.get("createdBy"),
        })

    snapshot = {
        "id": snap_id,
        "takenAt": _now(),
        "takenBy": taken_by,
        "scope": "deployment",
        "counts": {
            "users": len(users),
            "projects": len(projects),
            "datasets": len(datasets),
            "volumes": len(volumes),
            "privilegedUsers": sum(1 for u in users if u.get("isPrivileged")),
        },
        "users": users,
        "organizations": [
            {"id": o.get("id"), "name": o.get("name"), "memberIds": o.get("members") or o.get("memberIds") or []}
            for o in orgs
        ],
        "projects": projects,
        "datasets": datasets,
        "volumes": volumes,
        "projectionSummary": {
            "totalEvents": projection.get("totalEvents"),
            "eventCounts": projection.get("eventCounts"),
            "discoveredVolumeCount": len(projection.get("discoveredVolumes") or {}),
            "userRoleProjectionCount": len(projection.get("userGlobalRoles") or {}),
        },
        "principal": {
            "id": principal.get("canonicalId"),
            "name": principal.get("canonicalName"),
            "isAdmin": principal.get("isAdmin"),
        },
        "rolesSeed": roles_seed.metadata(seed),
    }

    path = snapshot_dir() / f"{snap_id}.json"
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)
    _log(f"wrote {path}")
    return snapshot


def list_snapshots() -> List[Dict]:
    out: List[Dict] = []
    for p in sorted(snapshot_dir().glob("snap_*.json"), reverse=True):
        try:
            with open(p) as f:
                s = json.load(f)
            out.append({
                "id": s["id"],
                "takenAt": s["takenAt"],
                "takenBy": s.get("takenBy"),
                "counts": s.get("counts", {}),
                "signed": (snapshot_dir() / f"{s['id']}.signature.json").exists(),
            })
        except Exception as e:
            _log(f"skip {p}: {e}")
    return out


def load_snapshot(snap_id: str) -> Optional[Dict]:
    path = snapshot_dir() / f"{snap_id}.json"
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def diff_snapshots(a_id: str, b_id: str) -> Dict:
    a = load_snapshot(a_id) or {}
    b = load_snapshot(b_id) or {}

    def project_role_set(snap: Dict) -> set:
        out = set()
        for p in snap.get("projects", []):
            for c in p.get("collaborators", []):
                out.add((c.get("userId"), p.get("id"), c.get("role")))
        return out

    def volume_access_set(snap: Dict) -> set:
        out = set()
        for v in snap.get("volumes", []):
            for uid in v.get("userIds", []):
                out.add((uid, v.get("id"), "user"))
            for pid in v.get("projectIds", []):
                out.add((pid, v.get("id"), "project"))
        return out

    a_pr, b_pr = project_role_set(a), project_role_set(b)
    a_vol, b_vol = volume_access_set(a), volume_access_set(b)

    return {
        "fromSnapshot": a_id,
        "toSnapshot": b_id,
        "projectRolesGranted": list(b_pr - a_pr),
        "projectRolesRevoked": list(a_pr - b_pr),
        "volumeAccessGranted": list(b_vol - a_vol),
        "volumeAccessRevoked": list(a_vol - b_vol),
    }
