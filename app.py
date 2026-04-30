"""FastAPI backend for the Domino Permissions Audit app."""
from __future__ import annotations

import csv
import io
import os
import sys
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

import chat
import domino_client as dc
import reports
import snapshot as snapmod


app = FastAPI(title="Domino Access Review")


@app.middleware("http")
async def capture_public_host(request, call_next):
    """No env var names the install's public URL, but every browser request
    arrives with the right Host header. Cache it for /api/audittrail calls."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    if host:
        dc.set_public_host(f"{proto}://{host}")
    return await call_next(request)


def _log(msg: str) -> None:
    print(f"[app] {msg}", file=sys.stdout, flush=True)


@app.on_event("startup")
def _log_identity() -> None:
    """One line per boot showing which Domino identity is in use. The runtime
    token from /access-token (always present in a Domino-hosted app) already
    authenticates as the app's publisher; if the publisher is SysAdmin, that
    token is enough to scrape /admin/* pages. API_KEY_OVERRIDE is only used
    as a local-dev fallback when there's no /access-token reachable."""
    try:
        principal = dc.get_principal()
        canonical = principal.get("canonicalName") or principal.get("userName")
        is_admin = principal.get("isAdmin")
    except Exception as e:
        canonical = f"<error: {e}>"
        is_admin = None
    _log(
        f"identity: canonicalName={canonical} isAdmin={is_admin} "
        f"host={os.environ.get('DOMINO_API_HOST', 'unset')}"
    )


# ---- Health / connectivity -------------------------------------------------

@app.get("/api/health")
def health() -> Dict:
    """Probe whether we can reach Domino + summarize endpoint coverage so the
    UI can warn the user about expected vs missing data sources."""
    users = dc.list_users()
    principal = dc.get_principal()
    volumes = dc.list_data_mounts()
    audit = dc.list_audit_events()
    return {
        "ok": bool(users),
        "userCount": len(users),
        "host": os.environ.get("DOMINO_API_HOST", "unset"),
        "hasApiKey": bool(os.environ.get("API_KEY_OVERRIDE")),
        "principal": {
            "userName": principal.get("canonicalName"),
            "isAdmin": principal.get("isAdmin"),
        },
        "endpoints": {
            "users": bool(users),
            "datamount": len(volumes) > 0,
            "auditevents": len(audit) > 0,
        },
    }


@app.get("/api/users-lookup")
def users_lookup() -> List[Dict]:
    """Lightweight user list for the Verify-a-user autocomplete: just the
    fields needed to render the dropdown (no roles / projects / volumes)."""
    snaps = snapmod.list_snapshots()
    snap = snapmod.load_snapshot(snaps[0]["id"]) if snaps else snapmod.take_snapshot(taken_by="lookup")
    out = []
    for u in snap.get("users", []):
        out.append({
            "userName": u.get("userName"),
            "fullName": u.get("fullName"),
            "email": u.get("email"),
            "userType": u.get("userType"),
        })
    out.sort(key=lambda r: (r.get("userType") != "human", (r.get("userName") or "").lower()))
    return out


@app.get("/api/whitelabel")
def whitelabel() -> Dict:
    return dc.get_whitelabel()


# ---- Snapshots -------------------------------------------------------------

@app.post("/api/snapshots")
def create_snapshot() -> Dict:
    snap = snapmod.take_snapshot(taken_by=os.environ.get("DOMINO_STARTING_USERNAME", "system"))
    return {"id": snap["id"], "takenAt": snap["takenAt"], "counts": snap["counts"]}


@app.get("/api/snapshot/progress")
def snapshot_progress() -> Dict:
    """Polled by the frontend while a snapshot is in flight. Returns
    {running, stage, stages: [{stage, elapsedMs, ...}], snapshotId, error}."""
    return snapmod.get_progress()


import threading


def _kick_off_snapshot_async() -> None:
    """Fire-and-forget: kick off a snapshot in a background thread so the
    HTTP response (e.g. dashboard's first GET) returns immediately. The
    frontend polls /api/snapshot/progress to render the progress bar.
    Single-flight is enforced inside take_snapshot."""
    def _runner():
        try:
            snapmod.take_snapshot(taken_by=os.environ.get("DOMINO_STARTING_USERNAME", "system"))
        except Exception as e:
            _log(f"async snapshot failed: {e}")
    threading.Thread(target=_runner, daemon=True).start()


@app.post("/api/snapshots/refresh")
def refresh_snapshot() -> Dict:
    """Kick off a fresh snapshot in the background and return immediately.
    Frontend polls /api/snapshot/progress + /api/snapshots for completion."""
    progress = snapmod.get_progress()
    if progress.get("running"):
        return {"alreadyRunning": True, "progress": progress}
    _kick_off_snapshot_async()
    return {"alreadyRunning": False, "progress": snapmod.get_progress()}


@app.get("/api/snapshots")
def get_snapshots() -> List[Dict]:
    return snapmod.list_snapshots()


@app.get("/api/snapshots/{snap_id}")
def get_snapshot(snap_id: str) -> Dict:
    snap = snapmod.load_snapshot(snap_id)
    if not snap:
        raise HTTPException(404, f"snapshot {snap_id} not found")
    return snap


@app.get("/api/snapshots/{a_id}/diff/{b_id}")
def diff(a_id: str, b_id: str) -> Dict:
    return snapmod.diff_snapshots(a_id, b_id)


# ---- Debug -----------------------------------------------------------------

@app.get("/api/debug-env")
def debug_env() -> Dict:
    """Dump non-secret DOMINO_* env vars so we can find the right host
    for /remotefs and /api/audittrail."""
    keep = {}
    for k, v in os.environ.items():
        if not k.startswith(("DOMINO_", "DCH_", "NUCLEUS_", "REMOTEFS_", "AUDIT")):
            continue
        if any(s in k.upper() for s in ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASS")):
            keep[k] = "***redacted***"
        else:
            keep[k] = v
    return {"env": keep}


@app.get("/api/debug-probe")
def debug_probe() -> Dict:
    """Probe each endpoint across candidate internal hosts so we can find
    where /remotefs and /api/audittrail are reachable from inside the cluster."""
    import requests as _r
    headers = dc.get_bearer_headers()
    hosts = [
        dc.API_HOST,
        "http://nucleus-dispatcher.domino-platform:80",
        "http://nucleus-frontend.domino-platform",
        "http://remotefs.domino-platform",
        "http://remotefs.domino-platform:80",
        "http://audit-trail.domino-platform",
        "http://audit-trail.domino-platform:80",
        "http://localhost:8899",
    ]
    paths = [
        ("GET", "/remotefs/v1/volumes?limit=1&filter_strictly_by_volume_roles=false&status=Active"),
        ("POST", "/api/audittrail/v1/search"),
    ]
    out = []
    for host in hosts:
        for method, path in paths:
            url = f"{host}{path}"
            try:
                if method == "GET":
                    r = _r.get(url, headers=headers, timeout=8)
                else:
                    r = _r.post(url, headers={**headers, "Content-Type": "application/json"},
                                json={"offset": 0, "limit": 1}, timeout=8)
                out.append({"host": host, "path": path.split("?")[0], "method": method,
                            "status": r.status_code, "len": len(r.text)})
            except Exception as e:
                out.append({"host": host, "path": path.split("?")[0], "method": method,
                            "error": str(e)[:120]})
    return {"probes": out}


@app.get("/api/debug")
def debug() -> Dict:
    """Diagnostic: which endpoints work, what the projection found, and the
    last snapshot's principal + counts. Surfaced in the UI's Debug panel."""
    users = dc.list_users()
    principal = dc.get_principal()
    self_user = dc.get_user_self()
    volumes_raw = dc.list_data_mounts()
    audit_sample = dc.list_audit_events(limit=200)
    snaps = snapmod.list_snapshots()
    last = snapmod.load_snapshot(snaps[0]["id"]) if snaps else None
    return {
        "principal": {
            "id": principal.get("canonicalId"),
            "name": principal.get("canonicalName"),
            "isAdmin": principal.get("isAdmin"),
            "selfRoles": self_user.get("roles") or [],
        },
        "endpoints": {
            "users": {"ok": bool(users), "count": len(users), "path": "/v4/users"},
            "projects": {"ok": True, "path": "/v4/projects"},
            "datamount": {
                "ok": True, "count": len(volumes_raw),
                "path": "/v4/datamount/all",
                "note": "Filters by accessibility — empty for service accounts without explicit grants. Audit-trail post-processing fills the gap.",
            },
            "audit": {
                "ok": bool(audit_sample), "sampleCount": len(audit_sample),
                "path": "/api/audittrail/v1/auditevents",
            },
            "datasetGrants": {"path": "/api/datasetrw/v1/datasets/{id}/grants"},
        },
        "lastSnapshot": last and {
            "id": last["id"], "takenAt": last["takenAt"],
            "counts": last.get("counts"),
            "projectionSummary": last.get("projectionSummary"),
        },
        "host": os.environ.get("DOMINO_API_HOST", "unset"),
        "hasApiKey": bool(os.environ.get("API_KEY_OVERRIDE")),
    }


# ---- Role verification (per-user spot-check) -------------------------------

@app.get("/api/verify/user/{user_name}")
def verify_user(user_name: str, snapshot: Optional[str] = Query(None)) -> Dict:
    """Return everything we know about one user: their global roles, the
    project memberships + role at each, dataset grants, and volume grants —
    in one payload so a compliance officer can spot-check at a glance.

    Drives the AC-9 "end-to-end one user" test and the UI's Verify-User card.
    """
    snap = _resolve_snapshot(snapshot)
    user = next((u for u in snap.get("users", []) if u.get("userName") == user_name), None)
    if not user:
        raise HTTPException(404, f"user {user_name} not found in snapshot")

    uid = user.get("id")
    project_memberships = []
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if c.get("userId") == uid or c.get("userName") == user_name:
                project_memberships.append({
                    "projectId": p.get("id"),
                    "projectName": p.get("name"),
                    "projectOwner": p.get("owner"),
                    "role": c.get("role"),
                    "grantedAt": c.get("grantedAt"),
                    "grantedBy": c.get("grantedBy"),
                })
                break

    # Datasets this user can access (they're the grantee).
    dataset_grants = []
    # Datasets where this user issued a grant to someone else (they're the grantor).
    dataset_grants_issued = []
    for d in snap.get("datasets", []):
        ds_owner = d.get("ownerName") or d.get("ownerUsername")
        for g in d.get("grants", []):
            if g.get("principalId") == uid or g.get("principalName") == user_name:
                dataset_grants.append({
                    "datasetId": d.get("id"),
                    "datasetName": d.get("name"),
                    "datasetOwner": ds_owner,
                    "projectId": d.get("projectId"),
                    "permission": g.get("permission"),
                    "source": g.get("source"),
                    "grantedAt": g.get("grantedAt"),
                    "grantedBy": g.get("grantedBy"),
                })
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name:
                dataset_grants_issued.append({
                    "datasetId": d.get("id"),
                    "datasetName": d.get("name"),
                    "datasetOwner": ds_owner,
                    "projectId": d.get("projectId"),
                    "principalType": g.get("principalType"),
                    "principalName": g.get("principalName"),
                    "permission": g.get("permission"),
                    "grantedAt": g.get("grantedAt"),
                })

    # Volumes this user can access (they're the grantee).
    volume_access_rows = []
    # Volumes where this user issued a grant to someone else (they're the grantor).
    volume_grants_issued = []
    for v in snap.get("volumes", []):
        # Match against the rich grants[] array first to pick up grantedAt /
        # grantedBy. Fall back to legacy userIds projection for older snapshots.
        own_grant = next(
            (g for g in (v.get("grants") or [])
             if g.get("principalId") == uid or g.get("principalName") == user_name),
            None,
        )
        if own_grant:
            volume_access_rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "permission": own_grant.get("role"),
                "via": "direct grant",
                "grantedAt": own_grant.get("grantedAt"),
                "grantedBy": own_grant.get("grantedBy"),
            })
        elif uid in (v.get("userIds") or []):
            volume_access_rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "permission": (v.get("userGrants") or {}).get(uid) or ("read" if v.get("readOnly") else "read/write"),
                "via": "direct user grant",
            })
        for g in v.get("grants") or []:
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name:
                volume_grants_issued.append({
                    "volumeId": v.get("id"),
                    "volumeName": v.get("name"),
                    "volumeType": v.get("volumeType"),
                    "principalType": g.get("principalType"),
                    "principalName": g.get("principalName"),
                    "permission": g.get("role"),
                    "grantedAt": g.get("grantedAt"),
                })

    # Data sources this user can access (owner or grantee).
    data_source_grants = []
    data_source_grants_issued = []
    for ds in snap.get("dataSources", []):
        for g in ds.get("grants") or []:
            if g.get("principalId") == uid or g.get("principalName") == user_name:
                data_source_grants.append({
                    "dataSourceId": ds.get("id"),
                    "dataSourceName": ds.get("displayName") or ds.get("name"),
                    "dataSourceType": ds.get("dataSourceType"),
                    "permission": g.get("role"),
                    "grantedAt": g.get("grantedAt"),
                    "grantedBy": g.get("grantedBy"),
                })
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name:
                data_source_grants_issued.append({
                    "dataSourceId": ds.get("id"),
                    "dataSourceName": ds.get("displayName") or ds.get("name"),
                    "principalType": g.get("principalType"),
                    "principalName": g.get("principalName"),
                    "permission": g.get("role"),
                    "grantedAt": g.get("grantedAt"),
                })

    # Organization memberships (current + historical from audit trail).
    organization_memberships = []
    for o in snap.get("organizations", []):
        for m in o.get("members") or []:
            match = (
                (m.get("userId") and m.get("userId") == uid)
                or (m.get("userName") and m.get("userName") == user_name)
            )
            if not match:
                continue
            organization_memberships.append({
                "organizationId": o.get("id"),
                "organizationName": o.get("name"),
                "role": m.get("role"),
                "addedAt": m.get("addedAt"),
                "addedBy": m.get("addedBy"),
                "removedAt": m.get("removedAt"),
                "removedBy": m.get("removedBy"),
                "current": m.get("current"),
            })

    return {
        "snapshot": _meta(snap),
        "user": user,
        "globalRoles": user.get("roles") or [],
        "isPrivileged": user.get("isPrivileged"),
        "projectMemberships": project_memberships,
        "datasetGrants": dataset_grants,
        "datasetGrantsIssued": dataset_grants_issued,
        "volumeAccess": volume_access_rows,
        "volumeGrantsIssued": volume_grants_issued,
        "dataSourceGrants": data_source_grants,
        "dataSourceGrantsIssued": data_source_grants_issued,
        "organizationMemberships": organization_memberships,
        "summary": {
            "projectCount": len(project_memberships),
            "datasetCount": len(dataset_grants),
            "datasetGrantsIssuedCount": len(dataset_grants_issued),
            "volumeCount": len(volume_access_rows),
            "volumeGrantsIssuedCount": len(volume_grants_issued),
            "dataSourceCount": len(data_source_grants),
            "dataSourceGrantsIssuedCount": len(data_source_grants_issued),
            "organizationCount": sum(1 for m in organization_memberships if m.get("current")),
        },
    }


# ---- Reconciliation against ground truth -----------------------------------

class ReconcileRequest:
    pass  # FastAPI will infer from kwargs


@app.post("/api/verify/reconcile")
def reconcile(payload: Dict, snapshot: Optional[str] = Query(None)) -> Dict:
    """Compare a Ground Truth Pack to the current snapshot, return per-AC
    pass/fail. Payload shape:
      {
        "userName": "matt_tendler_domino",
        "expectedProjects": [
           {"projectName": "supply_risk_radar", "role": "Owner"}, ...
        ],
        "expectedRoles": ["SysAdmin", "Practitioner"],
        "expectedVolumes": ["NetApp_App", "skill-test-volume"]
      }
    """
    snap = _resolve_snapshot(snapshot)
    user_name = payload.get("userName")
    if not user_name:
        raise HTTPException(400, "userName required")
    user = next((u for u in snap.get("users", []) if u.get("userName") == user_name), None)
    if not user:
        raise HTTPException(404, f"user {user_name} not found in snapshot")
    uid = user.get("id")

    actual_projects = {}
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if c.get("userId") == uid:
                actual_projects[p.get("name")] = c.get("role")
                break
    actual_roles = set(user.get("roles") or [])
    actual_volumes = set()
    for v in snap.get("volumes", []):
        if uid in (v.get("userIds") or []):
            actual_volumes.add(v.get("name"))

    findings = {"projects": [], "roles": [], "volumes": []}

    for exp in payload.get("expectedProjects", []) or []:
        name = exp.get("projectName")
        want = exp.get("role")
        got = actual_projects.get(name)
        findings["projects"].append({
            "projectName": name,
            "expectedRole": want,
            "actualRole": got,
            "pass": got is not None and (want is None or got == want),
        })

    for r in payload.get("expectedRoles", []) or []:
        findings["roles"].append({
            "role": r, "pass": r in actual_roles,
        })

    for v in payload.get("expectedVolumes", []) or []:
        findings["volumes"].append({
            "volumeName": v, "pass": v in actual_volumes,
        })

    summary = {
        "projectsPass": sum(1 for f in findings["projects"] if f["pass"]),
        "projectsTotal": len(findings["projects"]),
        "rolesPass": sum(1 for f in findings["roles"] if f["pass"]),
        "rolesTotal": len(findings["roles"]),
        "volumesPass": sum(1 for f in findings["volumes"] if f["pass"]),
        "volumesTotal": len(findings["volumes"]),
    }
    summary["allPass"] = (
        summary["projectsPass"] == summary["projectsTotal"]
        and summary["rolesPass"] == summary["rolesTotal"]
        and summary["volumesPass"] == summary["volumesTotal"]
    )
    return {
        "snapshot": _meta(snap),
        "userName": user_name,
        "actual": {
            "projects": actual_projects,
            "roles": sorted(actual_roles),
            "volumes": sorted(actual_volumes),
        },
        "findings": findings,
        "summary": summary,
    }


# ---- Live snapshot helper --------------------------------------------------

def _resolve_snapshot(snap_id: Optional[str]) -> Dict:
    """If snap_id is None, take a fresh in-memory snapshot for live mode."""
    if snap_id and snap_id != "live":
        snap = snapmod.load_snapshot(snap_id)
        if not snap:
            raise HTTPException(404, f"snapshot {snap_id} not found")
        return snap
    return snapmod.take_snapshot(taken_by="live-view")


# ---- Reports ---------------------------------------------------------------

@app.get("/api/reports/access-listing")
def report_access_listing(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.access_listing(snap)}


@app.get("/api/reports/project-matrix/{project_id}")
def report_project_matrix(project_id: str, snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "data": reports.project_role_matrix(snap, project_id)}


@app.get("/api/reports/privileged")
def report_privileged(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.privileged_users(snap)}


@app.get("/api/reports/volumes")
def report_volumes(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.volume_access(snap)}


@app.get("/api/reports/datasets")
def report_datasets(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.dataset_access(snap)}


@app.get("/api/reports/data-sources")
def report_data_sources(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.data_source_access(snap)}


def _meta(snap: Dict) -> Dict:
    return {
        "id": snap.get("id"),
        "takenAt": snap.get("takenAt"),
        "takenBy": snap.get("takenBy"),
        "principal": snap.get("principal") or {},
        "counts": snap.get("counts", {}),
    }


# ---- Exports ---------------------------------------------------------------

_REPORT_COLUMNS = {
    "access-listing": [
        {"key": "userName", "label": "User"},
        {"key": "email", "label": "Email"},
        {"key": "projectName", "label": "Project"},
        {"key": "role", "label": "Role"},
        {"key": "status", "label": "Status"},
        {"key": "userType", "label": "User Type"},
        {"key": "grantedAt", "label": "Granted At"},
        {"key": "grantedBy", "label": "Granted By"},
        {"key": "lastWorkload", "label": "Last Workload"},
    ],
    "privileged": [
        {"key": "userName", "label": "User"},
        {"key": "email", "label": "Email"},
        {"key": "roles", "label": "Roles"},
        {"key": "status", "label": "Status"},
        {"key": "lastWorkload", "label": "Last Workload"},
    ],
    "volumes": [
        {"key": "volumeName", "label": "Volume"},
        {"key": "volumeType", "label": "Type"},
        {"key": "principalType", "label": "Principal"},
        {"key": "principalName", "label": "Name"},
        {"key": "permission", "label": "Role"},
        {"key": "via", "label": "Granted Via"},
        {"key": "grantedAt", "label": "Granted At"},
        {"key": "grantedBy", "label": "Granted By"},
    ],
    "datasets": [
        {"key": "datasetName", "label": "Dataset"},
        {"key": "projectName", "label": "Project"},
        {"key": "principalType", "label": "Principal"},
        {"key": "principalName", "label": "Name"},
        {"key": "permission", "label": "Access"},
        {"key": "grantedAt", "label": "Granted At"},
        {"key": "grantedBy", "label": "Granted By"},
    ],
    "data-sources": [
        {"key": "dataSourceName", "label": "Data Source"},
        {"key": "dataSourceType", "label": "Type"},
        {"key": "credentialType", "label": "Credential"},
        {"key": "principalType", "label": "Principal"},
        {"key": "principalName", "label": "Name"},
        {"key": "permission", "label": "Access"},
        {"key": "status", "label": "Status"},
    ],
}


def _rows_for(report_key: str, snap: Dict) -> List[Dict]:
    if report_key == "access-listing":
        return reports.access_listing(snap)
    if report_key == "privileged":
        return reports.privileged_users(snap)
    if report_key == "volumes":
        return reports.volume_access(snap)
    if report_key == "datasets":
        return reports.dataset_access(snap)
    if report_key == "data-sources":
        return reports.data_source_access(snap)
    raise HTTPException(404, f"unknown report {report_key}")


@app.get("/api/exports/{report_key}.csv")
def export_csv(report_key: str, snapshot: Optional[str] = Query(None)) -> Response:
    if report_key not in _REPORT_COLUMNS:
        raise HTTPException(404, f"unknown report {report_key}")
    snap = _resolve_snapshot(snapshot)
    rows = _rows_for(report_key, snap)
    cols = _REPORT_COLUMNS[report_key]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([c["label"] for c in cols])
    for r in rows:
        w.writerow([r.get(c["key"], "") for c in cols])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{report_key}-{snap["id"]}.csv"'},
    )


@app.get("/api/exports/{report_key}.pdf")
def export_pdf(report_key: str, snapshot: Optional[str] = Query(None)) -> Response:
    if report_key not in _REPORT_COLUMNS:
        raise HTTPException(404, f"unknown report {report_key}")
    snap = _resolve_snapshot(snapshot)
    rows = _rows_for(report_key, snap)
    cols = _REPORT_COLUMNS[report_key]
    titles = {
        "access-listing": "User Access Listing",
        "privileged": "Privileged User Report",
        "volumes": "External Data Volume Access (NetApp / NFS / SMB / EFS)",
        "datasets": "Dataset Access",
        "data-sources": "Data Source Access (Snowflake / Redshift / S3 / etc.)",
    }
    try:
        import pdf_export
        pdf = pdf_export.render_pdf(titles[report_key], _meta(snap), cols, rows)
    except Exception as e:
        _log(f"pdf render failed: {e}")
        raise HTTPException(500, f"PDF export unavailable: {e}")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_key}-{snap["id"]}.pdf"'},
    )


# ---- Compliance chat (locked-down, deterministic) --------------------------
#
# No external LLM, no model inference, no network beyond the Domino APIs the
# rest of the app already calls. chat.route() pattern-matches the question to
# one of 10 intents, runs a real query against the snapshot, and returns
# structured rows. Unknown questions return the supported-question list — we
# never generate prose. See chat.py for the rules.


@app.get("/api/ask/examples")
def ask_examples() -> Dict:
    return {"questions": chat.SUPPORTED_QUESTIONS}


@app.post("/api/ask")
def ask(payload: Dict, snapshot: Optional[str] = Query(None)) -> Dict:
    question = (payload or {}).get("question") or ""
    context = (payload or {}).get("context")  # last turn's resultContext
    snap = _resolve_snapshot(snapshot)
    answer = chat.answer(question, snap, context=context)
    answer["snapshot"] = _meta(snap)
    answer["sources"] = [
        f"snapshot {snap.get('id')} (taken {snap.get('takenAt')})",
        "Domino APIs: /v4/projects, /v4/datamount/all, /api/datasetrw/v1/datasets/*/grants, "
        "/api/datasource/v1/dataSources, /api/audittrail/v1/auditevents",
    ]
    answer["disclaimer"] = (
        "This answer was produced by deterministic queries against the snapshot above. "
        "No language model was used; no data was sent to any external service."
    )
    return answer


# ---- Static frontend -------------------------------------------------------

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))
