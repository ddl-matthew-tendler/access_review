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
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import domino_client as dc
import audit_projection


# ---- Progress tracker ------------------------------------------------------
#
# Snapshots take 10-30s on a busy install. The frontend polls /api/snapshot/progress
# while take_snapshot() runs to render a step list. State is process-global —
# only one snapshot at a time (enforced by _SNAPSHOT_LOCK below), so no races.

_PROGRESS: Dict[str, Any] = {
    "running": False,
    "stage": "idle",
    "stages": [],
    "startedAt": None,
    "finishedAt": None,
    "snapshotId": None,
    "error": None,
}
_PROGRESS_LOCK = threading.Lock()
_SNAPSHOT_LOCK = threading.Lock()


def _progress(stage: str, **extra: Any) -> None:
    with _PROGRESS_LOCK:
        _PROGRESS["stage"] = stage
        # Append to stages history with elapsed-since-start
        started = _PROGRESS.get("startedAt")
        elapsed_ms = None
        if started:
            elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        _PROGRESS["stages"].append({"stage": stage, "elapsedMs": elapsed_ms, **extra})


def get_progress() -> Dict[str, Any]:
    with _PROGRESS_LOCK:
        out = dict(_PROGRESS)
        # Datetime → ISO for JSON
        if isinstance(out.get("startedAt"), datetime):
            out["startedAt"] = out["startedAt"].isoformat()
        if isinstance(out.get("finishedAt"), datetime):
            out["finishedAt"] = out["finishedAt"].isoformat()
        out["stages"] = list(out.get("stages") or [])
    return out


def _parallel(tasks: Dict[str, Callable[[], Any]], max_workers: int = 8) -> Dict[str, Any]:
    """Run {name: zero-arg-callable} in parallel. Returns {name: result-or-Exception}.

    Uses as_completed so progress events fire in real completion order — not
    dict insertion order. Without this, progress would show fast tasks as
    "completed late" simply because we hadn't gotten around to calling
    .result() on them yet."""
    out: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                out[name] = fut.result()
                count = len(out[name]) if hasattr(out[name], "__len__") else None
                _progress(f"fetch:{name}:done", count=count)
            except Exception as e:
                _log(f"parallel task {name} failed: {e}")
                out[name] = e
                _progress(f"fetch:{name}:failed", error=str(e))
    return out


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


def _organizations_with_history(orgs: List[Dict], proj_members: Dict) -> List[Dict]:
    """Merge live org membership (`/v4/organizations`) with audit-projected
    join/leave history. Each member dict carries `addedAt` / `addedBy` (when
    known from the audit trail) plus a `current: bool` flag. Members that are
    in the audit trail but no longer in the live response stay with a
    `removedAt` / `removedBy` stamp."""
    out: List[Dict] = []
    for o in orgs:
        oid = o.get("id")
        oname = o.get("name")
        live_members_raw = o.get("members") or o.get("memberIds") or []
        # /v4/organizations returns either a list of {id, name, role} dicts or
        # a flat list of user IDs depending on Domino release.
        live_by_id: Dict[str, Dict] = {}
        for m in live_members_raw:
            if isinstance(m, dict) and m.get("id"):
                live_by_id[m["id"]] = m
            elif isinstance(m, str):
                live_by_id[m] = {"id": m}
        proj = proj_members.get(oid) or {}
        proj_member_dict = proj.get("members") or {}
        members_out: List[Dict] = []
        seen_ids: set = set()
        # First pass: live members, enriched with audit timestamps where we have them.
        for uid, live in live_by_id.items():
            audit = None
            for mkey, m in proj_member_dict.items():
                if m.get("userId") == uid or mkey == uid:
                    audit = m
                    break
            members_out.append({
                "userId": uid,
                "userName": (live.get("name") if isinstance(live, dict) else None)
                            or (audit.get("userName") if audit else None),
                "role": live.get("role") if isinstance(live, dict) else None,
                "addedAt": (audit or {}).get("addedAt"),
                "addedBy": (audit or {}).get("addedBy"),
                "removedAt": None,
                "removedBy": None,
                "current": True,
            })
            seen_ids.add(uid)
        # Second pass: audit-only members (joined then left before snapshot).
        for mkey, m in proj_member_dict.items():
            uid = m.get("userId") or mkey
            if uid in seen_ids:
                continue
            members_out.append({
                "userId": m.get("userId"),
                "userName": m.get("userName"),
                "role": None,
                "addedAt": m.get("addedAt"),
                "addedBy": m.get("addedBy"),
                "removedAt": m.get("removedAt"),
                "removedBy": m.get("removedBy"),
                "current": False,
            })
        out.append({
            "id": oid,
            "name": oname,
            "createdAt": proj.get("createdAt"),
            "createdBy": proj.get("createdBy"),
            "memberIds": list(live_by_id.keys()),
            "members": members_out,
        })
    return out


def _audit_grant_row(uid: str, role: str, did: str, user_id_to_name: Dict, grant_history: Dict) -> Dict:
    hist = grant_history["dataset"].get((uid, did)) or {}
    return {
        "principalType": "User",
        "principalId": uid,
        "principalName": user_id_to_name.get(uid),
        "role": role,
        "grantedAt": hist.get("grantedAt"),
        "grantedBy": hist.get("grantedBy"),
        "source": "audit-projection",
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




def take_snapshot(taken_by: str = "system") -> Dict:
    """Capture full who-has-access-to-what across the deployment.

    Single-flight: if a snapshot is already in progress, this call BLOCKS
    on the lock (so callers see the same fresh result), but never resets
    the in-flight progress tracker. Stage order on the wire reflects real
    completion order (see _parallel using as_completed)."""
    # Acquire SNAPSHOT_LOCK first. If another snapshot is in flight, we wait
    # — and we DO NOT reset the progress tracker mid-flight (that was the
    # bug producing duplicate/out-of-order stage entries in the UI).
    with _SNAPSHOT_LOCK:
        snap_id = f"snap_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:6]}"
        _log(f"taking snapshot {snap_id}")
        with _PROGRESS_LOCK:
            _PROGRESS["running"] = True
            _PROGRESS["stage"] = "starting"
            _PROGRESS["stages"] = []
            _PROGRESS["startedAt"] = datetime.now(timezone.utc)
            _PROGRESS["finishedAt"] = None
            _PROGRESS["snapshotId"] = snap_id
            _PROGRESS["error"] = None
        try:
            return _take_snapshot_inner(snap_id, taken_by)
        except Exception as e:
            with _PROGRESS_LOCK:
                _PROGRESS["error"] = str(e)
            raise
        finally:
            # `running=False` only after persist completes. The frontend
            # uses this to know it's safe to fetch the new snapshot.
            with _PROGRESS_LOCK:
                _PROGRESS["running"] = False
                _PROGRESS["stage"] = "done"
                _PROGRESS["finishedAt"] = datetime.now(timezone.utc)


def _take_snapshot_inner(snap_id: str, taken_by: str) -> Dict:
    _progress("fetch:start")
    # Pull all the top-level resources in parallel — most of these are
    # independent /v4/* calls and the slowest (audit events) takes ~5s. Doing
    # them serially adds ~10-15s of wall-clock; in parallel it's bounded by
    # the slowest call.
    fetches = _parallel({
        "users": dc.list_users,
        "organizations": dc.list_organizations,
        "projects": dc.list_projects,
        "datasets": dc.list_datasets,
        "volumes": dc.list_data_mounts,
        "dataSources": dc.list_data_sources,
        "apps": dc.list_apps,
        "principal": dc.get_principal,
        "adminUsers": dc.scrape_admin_users,
        "auditEvents": dc.list_audit_events,
    })

    def _val(name: str, default: Any) -> Any:
        v = fetches.get(name)
        return default if isinstance(v, Exception) or v is None else v

    users_raw = _val("users", [])
    orgs = _val("organizations", [])
    projects_raw = _val("projects", [])
    datasets_raw = _val("datasets", [])
    volumes_raw = _val("volumes", [])
    data_sources_raw = _val("dataSources", [])
    apps_raw = _val("apps", [])
    principal = _val("principal", {})
    admin_users = _val("adminUsers", [])
    events = _val("auditEvents", [])

    _log(f"api fetch: datasets={len(datasets_raw)} volumes={len(volumes_raw)}")

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
    # superseded by the admin scrape). Events were fetched in the parallel
    # block above so this is now CPU-only replay.
    _progress("project:audit", events=len(events))
    projection = audit_projection.project(events)
    _log(f"projected from {projection.get('totalEvents')} events")
    grant_history = _build_grant_history_index()

    self_id = principal.get("canonicalId")

    _progress("build:users", total=len(users_raw))
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

    _progress("build:projects", total=len(projects_raw))
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
    user_name_to_id = {u.get("userName"): u["id"] for u in users if u.get("id") and u.get("userName")}

    # Backfill ownerId from username for datasets where the summary endpoint
    # only returns the username (it does for owner — see DatasetRwSummaryDto).
    for d in datasets_raw:
        if not d.get("ownerId") and d.get("ownerUsername"):
            d["ownerId"] = user_name_to_id.get(d["ownerUsername"])

    # Fan out per-dataset grants in parallel — 111 sequential HTTP calls
    # at ~100ms each costs 11s of wall-clock; with 16 workers this drops to
    # ~1s. The /grants endpoint is the dominant cost in dataset enrichment.
    _progress("fetch:datasetGrants", total=len(datasets_raw))
    ds_ids = [d.get("id") or d.get("datasetId") for d in datasets_raw]
    grants_by_id: Dict[str, List[Dict]] = {}
    with ThreadPoolExecutor(max_workers=16) as ex:
        future_to_id = {
            ex.submit(dc.list_dataset_grants, did): did
            for did in ds_ids if did
        }
        for fut in future_to_id:
            did = future_to_id[fut]
            try:
                grants_by_id[did] = fut.result() or []
            except Exception as e:
                _log(f"list_dataset_grants({did}) failed: {e}")
                grants_by_id[did] = []

    _progress("build:datasets", total=len(datasets_raw))
    datasets: List[Dict] = []
    seen_ds_ids = set()
    for d in datasets_raw:
        did = d.get("id") or d.get("datasetId")
        seen_ds_ids.add(did)
        grants_raw = grants_by_id.get(did, [])
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
                hist = grant_history["dataset"].get((uid, did)) or {}
                grants_out.append({
                    "principalType": "User",
                    "principalId": uid,
                    "principalName": user_id_to_name.get(uid),
                    "role": role,
                    "grantedAt": hist.get("grantedAt"),
                    "grantedBy": hist.get("grantedBy"),
                    "source": "audit-projection",
                })

        # The /grants endpoint omits the dataset owner on this Domino release —
        # owner-only datasets come back with []. Reconstruct the owner grant from
        # the dataset listing's owner fields so owners show up as grantees in
        # user-detail views and per-dataset access reports.
        owner_id = d.get("ownerId") or d.get("author")
        owner_names = d.get("ownerUsernames") or []
        owner_name = d.get("ownerUsername") or (owner_names[0] if owner_names else None)
        if owner_name and not owner_id:
            owner_id = user_name_to_id.get(owner_name)
        if (owner_id or owner_name) and not any(
            (owner_id and g.get("principalId") == owner_id)
            or (owner_name and g.get("principalName") == owner_name)
            for g in grants_out
        ):
            grants_out.insert(0, {
                "principalType": "User",
                "principalId": owner_id,
                "principalName": owner_name or (user_id_to_name.get(owner_id) if owner_id else None),
                "role": "DatasetRwOwner",
                "source": "dataset-owner",
            })

        datasets.append({
            "id": did,
            "name": d.get("name") or d.get("datasetName"),
            "projectId": d.get("projectId"),
            "ownerId": owner_id,
            "ownerName": owner_name,
            "grants": grants_out,
        })

    # Datasets discovered ONLY via audit (referenced in events but not in
    # the live /api/datasetrw response — usually deleted). Counted
    # separately so the dashboard reflects "currently exists" not "ever
    # existed in the audit log". Kept in the snapshot for completeness.
    audit_only_datasets: List[Dict] = []
    for did, ds in projected_ds_grants.items():
        if did in seen_ds_ids:
            continue
        audit_only_datasets.append({
            "id": did,
            "name": ds.get("name"),
            "projectId": None,
            "discoveredVia": "audit-only",
            "grants": [
                _audit_grant_row(uid, role, did, user_id_to_name, grant_history)
                for uid, role in (ds.get("grants") or {}).items()
            ],
        })

    projected_vol_grants = projection.get("volumeGrants") or {}
    projected_vol_projects = projection.get("volumeProjects") or {}
    discovered_vols = projection.get("discoveredVolumes") or {}

    _progress("build:volumes", total=len(volumes_raw))
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
    _progress("build:dataSources", total=len(data_sources_raw))
    data_sources: List[Dict] = []
    projected_ds_perms = projection.get("dataSourceGrants") or {}
    for ds in data_sources_raw:
        # /api/datasource/v1/datasources returns `permissions`, not
        # `dataSourcePermissions` (swagger is stale on this release).
        perms = ds.get("permissions") or ds.get("dataSourcePermissions") or {}
        owner_id = ds.get("ownerId")
        owner_username = ds.get("ownerUsername") or (ds.get("ownerInfo") or {}).get("userName")
        # `credentialType` is on the data source root in the live API; older
        # spec puts it on `permissions`. Read either.
        credential_type = ds.get("credentialType") or perms.get("credentialType")
        # Audit-driven provenance for THIS data source. Keyed by principal id.
        ds_audit = projected_ds_perms.get(ds.get("id")) or {}
        ds_audit_grants = ds_audit.get("grants") or {}
        grants_out: List[Dict] = []
        if owner_id:
            owner_audit = ds_audit_grants.get(owner_id) or {}
            grants_out.append({
                "principalType": "User",
                "principalId": owner_id,
                "principalName": owner_username or user_id_to_name.get(owner_id),
                "role": "DataSourceOwner",
                "grantedAt": ds_audit.get("createdAt") or owner_audit.get("grantedAt"),
                "grantedBy": ds_audit.get("createdBy") or owner_audit.get("grantedBy"),
            })
        if perms.get("isEveryone"):
            grants_out.append({
                "principalType": "Public",
                "principalName": "All Users",
                "role": "DataSourceUser",
            })
        # Live API uses userAndOrganizationIds; older spec was userIds.
        principal_ids = perms.get("userAndOrganizationIds") or perms.get("userIds") or []
        for pid in principal_ids:
            if pid == owner_id:
                continue
            audit_g = ds_audit_grants.get(pid) or {}
            grants_out.append({
                "principalType": "Organization" if pid in org_user_ids else "User",
                "principalId": pid,
                "principalName": user_id_to_name.get(pid) or audit_g.get("principalName"),
                "role": "DataSourceUser",
                "grantedAt": audit_g.get("grantedAt"),
                "grantedBy": audit_g.get("grantedBy"),
            })
        data_sources.append({
            "id": ds.get("id"),
            "name": ds.get("name"),
            "displayName": ds.get("displayName") or ds.get("name"),
            "description": ds.get("description"),
            "dataSourceType": ds.get("dataSourceType"),
            "authType": ds.get("authType"),
            "credentialType": credential_type,
            "status": ds.get("status") or "Active",
            "ownerId": owner_id,
            "ownerName": owner_username,
            "projectIds": ds.get("projectIds") or [],
            "lastAccessed": ds.get("lastAccessed"),
            "lastUpdated": ds.get("lastUpdated"),
            "createdAt": ds_audit.get("createdAt"),
            "createdBy": ds_audit.get("createdBy"),
            "grants": grants_out,
        })

    # ---- Domino Apps -------------------------------------------------------
    # Listing endpoint returns publisher + visibility for free; for GRANT_BASED
    # apps the per-user accessStatuses needs the detail call. AUTHENTICATED
    # apps don't get a per-user list (everyone has access).
    _progress("build:apps", total=len(apps_raw))
    grant_based_ids = [a.get("id") for a in apps_raw
                       if a.get("visibility") == "GRANT_BASED" and a.get("id")]
    app_details: Dict[str, Dict] = {}
    if grant_based_ids:
        with ThreadPoolExecutor(max_workers=16) as ex:
            future_to_id = {ex.submit(dc.get_app_detail, aid): aid for aid in grant_based_ids}
            for fut in future_to_id:
                aid = future_to_id[fut]
                try:
                    app_details[aid] = fut.result() or {}
                except Exception as e:
                    _log(f"get_app_detail({aid}) failed: {e}")
                    app_details[aid] = {}

    apps: List[Dict] = []
    for a in apps_raw:
        aid = a.get("id")
        if not aid:
            continue
        publisher = a.get("publisher") or {}
        proj = a.get("project") or {}
        visibility = a.get("visibility")
        # The detail call (only for GRANT_BASED) carries the populated list.
        detail = app_details.get(aid, a)
        access_statuses = detail.get("accessStatuses") or []
        grants_out: List[Dict] = []
        # Publisher always has access.
        if publisher.get("id"):
            grants_out.append({
                "principalType": "User",
                "principalId": publisher.get("id"),
                "principalName": publisher.get("name"),
                "role": "Publisher",
                "source": "app-publisher",
            })
        if visibility == "AUTHENTICATED":
            grants_out.append({
                "principalType": "Public",
                "principalName": "All authenticated users",
                "role": "Authenticated",
                "source": "app-visibility",
            })
        else:  # GRANT_BASED — explicit per-user list
            for st in access_statuses:
                uid = st.get("userId")
                if not uid or uid == publisher.get("id"):
                    continue
                if (st.get("status") or "ALLOWED") != "ALLOWED":
                    continue
                grants_out.append({
                    "principalType": "User",
                    "principalId": uid,
                    "principalName": user_id_to_name.get(uid),
                    "role": "Granted",
                    "source": "app-grant",
                })
        apps.append({
            "id": aid,
            "name": a.get("name"),
            "description": a.get("description"),
            "url": a.get("url"),
            "vanityUrl": a.get("vanityUrl"),
            "visibility": visibility,
            "discoverable": a.get("discoverable"),
            "projectId": proj.get("id"),
            "projectName": proj.get("name"),
            "projectOwner": proj.get("ownerUsername"),
            "publisherId": publisher.get("id"),
            "publisherName": publisher.get("name"),
            "updatedAt": a.get("updatedAt"),
            "views": a.get("views"),
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
            "apps": len(apps),
            "privilegedUsers": sum(1 for u in users if u.get("isPrivileged")),
        },
        "users": users,
        "organizations": _organizations_with_history(orgs, projection.get("organizationMembers") or {}),
        "projects": projects,
        "datasets": datasets,
        "volumes": volumes,
        "dataSources": data_sources,
        "apps": apps,
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

    _progress("persist", path=str(snapshot_dir()))
    path = snapshot_dir() / f"{snap_id}.json"
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)
    _log(f"wrote {path}")
    _progress("persist:done", users=len(users), datasets=len(datasets), volumes=len(volumes))
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
