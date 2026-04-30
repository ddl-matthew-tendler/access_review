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


DOMINO_DATASET_DIR = Path("/domino/datasets/local/access_review/snapshots")
LOCAL_FALLBACK_DIR = Path(__file__).parent / "snapshots"

# Canonical privileged role names from /admin/users "Roles" column.
PRIVILEGED_ROLES = {
    "SysAdmin", "SystemAdministrator", "Admin",
    "OrgAdmin", "OrgOwner",
    "GovernanceAdmin", "EnvironmentAdmin", "EnvAdmin",
    "LimitedAdmin", "SupportStaff", "DataSourceAdmin",
    "Librarian", "ProjectManager",
}


def _build_grant_history_index() -> Dict:
    """Replay grant-related audit events into an index keyed by
    (target_id, affecting_id) -> {timestamp, actor}, so we can stamp
    grantedAt + grantedBy on every project / volume / dataset grant."""
    out = {"project": {}, "volume": {}, "dataset": {}}
    for ev in dc.audit_grant_history():
        action = (ev.get("action") or {}).get("eventName") or ""
        ts = ev.get("timestamp")
        actor_name = (ev.get("actor") or {}).get("name")
        targets = ev.get("targets") or []
        affecting = ev.get("affecting") or []
        target_id = (targets[0].get("entity") or {}).get("id") if targets else None
        # Pick the affecting entity that matches the action's resource type
        for a in affecting:
            etype = a.get("entityType")
            aid = a.get("id")
            if not (target_id and aid):
                continue
            bucket = None
            if action in ("Add Collaborator", "Change User Role In Project") and etype == "project":
                bucket = "project"
            elif action == "Add Grant for NetApp-backed Volume" and etype == "netAppVolume":
                bucket = "volume"
            elif action == "Add Grant For Dataset" and etype == "dataset":
                bucket = "dataset"
            if bucket:
                key = (target_id, aid)
                # Latest event wins (events are oldest-first in input)
                out[bucket][key] = {"grantedAt": ts, "grantedBy": actor_name}
    return out


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




def take_snapshot(taken_by: str = "system") -> Dict:
    """Capture full who-has-access-to-what across the deployment."""
    snap_id = f"snap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}"
    _log(f"taking snapshot {snap_id}")

    users_raw = dc.list_users()
    orgs = dc.list_organizations()
    projects_raw = dc.list_projects()
    datasets_raw = dc.list_datasets()
    volumes_raw = dc.list_data_mounts()
    data_sources_raw = dc.list_data_sources()
    principal = dc.get_principal()

    # Canonical user attributes come from the /admin/users page (HTML scrape).
    # /v4/users on this Domino release returns only basic fields; the admin
    # page is the only source of roles, lastWorkload, active, serviceAccount,
    # dominoEmployee. Indexed by username (the primary key on that page).
    admin_users = dc.scrape_admin_users()
    admin_index = {row["username"]: row for row in admin_users}

    # Orgs come back from /v4/users as user-records (organizationUserId).
    # We use that to flag them and exclude from default human-user views.
    org_user_ids = {o.get("organizationUserId") for o in orgs if o.get("organizationUserId")}
    org_admin_user_ids = set()
    for org in orgs:
        for m in (org.get("members") or []):
            if (m.get("role") == "Admin") and m.get("id"):
                org_admin_user_ids.add(m["id"])

    # Audit-driven projection (still useful for volume/dataset grant discovery
    # and for granted-at/by enrichment; per-user role projection is now
    # superseded by the admin scrape).
    _log("fetching audit events for projection")
    events = dc.list_audit_events()
    projection = audit_projection.project(events)
    _log(f"projected from {projection.get('totalEvents')} events")
    grant_history = _build_grant_history_index()

    self_id = principal.get("canonicalId")

    users: List[Dict] = []
    for u in users_raw:
        uid = u.get("id") or u.get("userId") or u.get("_id")
        uname = u.get("userName") or u.get("loginName") or u.get("name")
        first = (u.get("firstName") or "").strip()
        last = (u.get("lastName") or "").strip()
        admin = admin_index.get(uname) or {}

        # Determine user type (used for filtering humans-only views)
        if uid in org_user_ids:
            user_type = "organization"
        elif admin.get("serviceAccount"):
            user_type = "service_account"
        elif admin.get("dominoEmployee"):
            user_type = "domino_employee"
        else:
            user_type = "human"

        # Roles: admin scrape is canonical. Layer in OrgAdmin from /v4/organizations.
        roles: Set[str] = set(admin.get("roles") or [])
        if uid in org_admin_user_ids:
            roles.add("OrgAdmin")
        if uid == self_id and principal.get("isAdmin") and not roles:
            roles.add("SysAdmin")
        role_list = sorted(roles)

        users.append({
            "id": uid,
            "userName": uname,
            "fullName": admin.get("name") or u.get("fullName") or (first + " " + last).strip(),
            "email": u.get("email") or u.get("emailAddress"),
            "status": "Active" if (admin.get("active") if admin else True) else "Disabled",
            "userType": user_type,
            "isOrganization": user_type == "organization",
            "isServiceAccount": user_type == "service_account",
            "isDominoEmployee": user_type == "domino_employee",
            "licenseType": u.get("licenseType") or u.get("licenseTier") or "Standard",
            "roles": role_list,
            "isPrivileged": user_type == "human"
                            and any(r in PRIVILEGED_ROLES for r in role_list),
            "lastWorkload": admin.get("lastWorkload"),
            "signedUp": admin.get("signedUp"),
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
            hist = grant_history["project"].get((cid, pid)) or {}
            collaborators.append({
                "userId": cid,
                "userName": cname,
                "role": c.get("projectRole") or c.get("role") or "Contributor",
                "grantedAt": hist.get("grantedAt") or c.get("createdAt"),
                "grantedBy": hist.get("grantedBy") or c.get("grantedBy"),
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
                tid = g.get("targetId") or g.get("principalId")
                hist = grant_history["dataset"].get((tid, did)) or {}
                grants_out.append({
                    "principalType": "Organization" if g.get("isOrganization") else "User",
                    "principalId": tid,
                    "principalName": g.get("targetName") or g.get("principalName"),
                    "role": g.get("targetRole") or g.get("permission"),
                    "grantedAt": hist.get("grantedAt"),
                    "grantedBy": hist.get("grantedBy"),
                    "source": "datasetrw-api",
                })
        else:
            for uid, role in (projected_ds_grants.get(did, {}).get("grants") or {}).items():
                grants_out.append({
                    "principalType": "User",
                    "principalId": uid,
                    "principalName": user_id_to_name.get(uid),
                    "role": role,
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
                    "role": role,
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
        merged_users = list(set((v.get("userIds") or []) + list((ag.get("grants") or {}).keys())))
        merged_projects = list(set([p.get("id") if isinstance(p, dict) else p
                                     for p in (v.get("projects") or [])] + list(ap)))
        # Per-grant detail: role + grantedAt/By from audit history
        raw_grants = v.get("rawGrants") or []
        grant_records = []
        for g in raw_grants:
            tid = g.get("targetId")
            hist = grant_history["volume"].get((tid, vid)) or {}
            grant_records.append({
                "principalId": tid,
                "principalName": g.get("targetName"),
                "principalType": "Organization" if g.get("isOrganization") else "User",
                "role": g.get("targetRole"),
                "grantedAt": hist.get("grantedAt"),
                "grantedBy": hist.get("grantedBy"),
            })
        volumes.append({
            "id": vid,
            "name": v.get("name") or ag.get("name"),
            "volumeType": v.get("volumeType") or "Nfs",
            "mountPath": v.get("mountPath"),
            "filesystemName": v.get("filesystemName"),
            "readOnly": bool(v.get("readOnly")),
            "isPublic": bool(v.get("isPublic")),
            "userIds": merged_users,
            "projectIds": merged_projects,
            "status": v.get("status"),
            "userGrants": {uid: audit_projection.normalize_grant_role(role)
                            for uid, role in (ag.get("grants") or {}).items()},
            "grants": grant_records,
            "discoveredVia": "remotefs-api",
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

    # ---- Data Sources (Snowflake / Redshift / S3 / etc.) -------------------
    # /datasource/dataSources/all (per fulldominoswagger) returns DataSourceDto
    # with embedded dataSourcePermissions: {isEveryone, userIds[], credentialType}.
    # Project users grants is a flat list — Domino's data-source authz is a
    # binary "is the user allowed to use this connection" rather than the
    # graded Owner/Editor/Reader of volumes/datasets. Owner is separate.
    data_sources: List[Dict] = []
    for ds in data_sources_raw:
        perms = ds.get("dataSourcePermissions") or {}
        owner_id = ds.get("ownerId")
        owner_info = ds.get("ownerInfo") or {}
        grants_out: List[Dict] = []
        if owner_id:
            grants_out.append({
                "principalType": "User",
                "principalId": owner_id,
                "principalName": owner_info.get("userName") or user_id_to_name.get(owner_id),
                "role": "DataSourceOwner",
            })
        if perms.get("isEveryone"):
            grants_out.append({
                "principalType": "Public",
                "principalName": "All Users",
                "role": "DataSourceUser",
            })
        for uid in (perms.get("userIds") or []):
            if uid == owner_id:
                continue  # already represented as Owner
            grants_out.append({
                "principalType": "User",
                "principalId": uid,
                "principalName": user_id_to_name.get(uid),
                "role": "DataSourceUser",
            })
        data_sources.append({
            "id": ds.get("id"),
            "name": ds.get("name"),
            "displayName": ds.get("displayName"),
            "dataSourceType": ds.get("dataSourceType"),
            "authType": ds.get("authType"),
            "credentialType": perms.get("credentialType"),
            "status": ds.get("status"),
            "ownerId": owner_id,
            "ownerName": owner_info.get("userName"),
            "projectIds": ds.get("projectIds") or [],
            "lastAccessed": ds.get("lastAccessed"),
            "lastUpdated": ds.get("lastUpdated"),
            "grants": grants_out,
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
            "dataSources": len(data_sources),
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
        "dataSources": data_sources,
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
