"""FastAPI backend for the Domino Permissions Audit app."""
from __future__ import annotations

import csv
import io
import os
import sys
from typing import Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Query
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


# ---- Bulk org member add ---------------------------------------------------
#
# Wraps Domino's changeOrganizationMembers (PUT /v4/organizations/{id}/members).
# That endpoint is a SET, not a delta - it replaces the entire member list -
# so to add we must: resolve usernames -> ids, GET current members, merge,
# then PUT the union. We then categorize each input username so the UI can
# render a per-user result.

def _normalize_tokens(tokens_raw: List[str]) -> List[str]:
    """Strip whitespace + dedup while preserving first-seen order."""
    seen = set()
    out: List[str] = []
    for t in tokens_raw or []:
        s = (t or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _build_user_resolvers(all_users: List[Dict]) -> Dict[str, Dict]:
    """Return {kind: dict} where kind is 'userName', 'email', 'fullName'.
    Each dict maps a case-folded lookup string to the user record. Lets
    bulk-add accept "matt_tendler" / "matt.tendler@domino.com" / "Matt
    Tendler" interchangeably - whichever the caller pasted from."""
    by_name: Dict[str, Dict] = {}
    by_email: Dict[str, Dict] = {}
    by_full: Dict[str, Dict] = {}
    for u in all_users or []:
        un = u.get("userName")
        em = u.get("email")
        fn = u.get("fullName") or (
            ((u.get("firstName") or "") + " " + (u.get("lastName") or "")).strip()
        )
        if un:
            by_name[un.lower()] = u
        if em:
            by_email[em.lower()] = u
        if fn:
            by_full[fn.lower()] = u
    return {"userName": by_name, "email": by_email, "fullName": by_full}


def _resolve_token(token: str, resolvers: Dict[str, Dict]) -> Optional[Dict]:
    """Try userName first (most specific), then email, then fullName."""
    key = (token or "").strip().lower()
    if not key:
        return None
    return (resolvers["userName"].get(key)
            or resolvers["email"].get(key)
            or resolvers["fullName"].get(key))


@app.post("/api/orgs/{org_user_id}/resolve-members")
def resolve_org_member_tokens(org_user_id: str, body: Dict = Body(...)) -> Dict:
    """Preview-only: given a list of tokens, report which would resolve to
    an existing user, which would be no-ops because they're already in the
    org, and which can't be resolved at all. Same matching logic as
    bulk-add but performs no writes - drives the frontend's live chip
    preview so callers see the outcome before they submit."""
    tokens = _normalize_tokens(body.get("tokens") or body.get("usernames") or [])
    if not tokens:
        return {"resolved": [], "notFound": []}

    all_users = dc.list_users() or []
    resolvers = _build_user_resolvers(all_users)

    org = dc.get_organization(org_user_id)
    existing_ids = set()
    if org:
        for m in (org.get("members") or []):
            if m.get("id"):
                existing_ids.add(m["id"])

    resolved_out: List[Dict] = []
    not_found: List[str] = []
    for token in tokens:
        u = _resolve_token(token, resolvers)
        if not u or not u.get("id"):
            not_found.append(token)
            continue
        resolved_out.append({
            "token": token,
            "id": u.get("id"),
            "userName": u.get("userName"),
            "fullName": u.get("fullName"),
            "email": u.get("email"),
            "alreadyMember": u.get("id") in existing_ids,
        })
    return {"resolved": resolved_out, "notFound": not_found}


@app.post("/api/orgs/{org_user_id}/bulk-add-members")
def bulk_add_org_members(org_user_id: str, body: Dict = Body(...)) -> Dict:
    """Add multiple users to a Domino org in one request.

    body = { "usernames": ["alice", "bob@x.com", "Carol Smith"],
             "role": "Member" | "Admin" }

    Each token is resolved via userName -> email -> fullName (case-insensitive).
    Returns { added, alreadyMember, notFound, failed, finalCount, error }.
    """
    tokens = _normalize_tokens(body.get("usernames") or body.get("tokens") or [])
    role = body.get("role") or "Member"
    if role not in ("Member", "Admin"):
        raise HTTPException(400, f"role must be 'Member' or 'Admin', got {role!r}")
    if not tokens:
        raise HTTPException(400, "no usernames provided")

    all_users = dc.list_users() or []
    resolvers = _build_user_resolvers(all_users)

    not_found: List[str] = []
    resolved: List[Dict] = []  # [{token, userName, id}]
    for token in tokens:
        u = _resolve_token(token, resolvers)
        if not u or not u.get("id"):
            not_found.append(token)
            continue
        resolved.append({
            "token": token,
            "userName": u.get("userName") or token,
            "id": u.get("id"),
        })

    # Read the authoritative current member list. We must include every
    # existing member with their existing role in the PUT body or we'll
    # accidentally remove them.
    org = dc.get_organization(org_user_id)
    if not org:
        raise HTTPException(404, f"org {org_user_id} not found")

    existing = org.get("members") or []
    existing_ids = {m.get("id"): (m.get("role") or "Member") for m in existing if m.get("id")}

    already_member: List[str] = []
    to_add: List[Dict] = []
    for r in resolved:
        if r["id"] in existing_ids:
            already_member.append(r["userName"])
        else:
            to_add.append({"id": r["id"], "role": role})

    if not to_add:
        return {
            "added": [],
            "alreadyMember": already_member,
            "notFound": not_found,
            "failed": [],
            "finalCount": len(existing_ids),
            "orgName": org.get("name"),
        }

    merged = ([{"id": mid, "role": mrole} for mid, mrole in existing_ids.items()]
              + to_add)

    res = dc.set_organization_members(org_user_id, merged)
    if not res.get("ok"):
        return {
            "added": [],
            "alreadyMember": already_member,
            "notFound": not_found,
            "failed": [{"userName": r["userName"], "reason": "API error"} for r in resolved if r["id"] not in existing_ids],
            "finalCount": len(existing_ids),
            "orgName": org.get("name"),
            "error": {"status": res.get("status"), "body": res.get("body")},
        }

    return {
        "added": [r["userName"] for r in resolved if r["id"] not in existing_ids],
        "alreadyMember": already_member,
        "notFound": not_found,
        "failed": [],
        "finalCount": len(existing_ids) + len(to_add),
        "orgName": org.get("name"),
    }


@app.post("/api/orgs/{org_user_id}/remove-member")
def remove_org_member(org_user_id: str, body: Dict = Body(...)) -> Dict:
    """Remove a single user from a Domino org in one call.

    body = { "userName": "matt_domino" }   (or { "userId": "<id>" })

    Mechanism: changeOrganizationMembers is a SET, so we GET the current
    members, filter out the target, and PUT the rest back.

    Returns { removed: bool, reason?, finalCount, orgName, alreadyRemoved? }.
    Refuses (without writing) if removing the user would leave the org
    with zero Admins - that's a footgun (no one left who can manage
    membership) so we surface a 'lastAdmin' reason and let the caller
    decide what to do.
    """
    target_name = (body.get("userName") or "").strip()
    target_id = (body.get("userId") or "").strip()
    if not target_name and not target_id:
        raise HTTPException(400, "must provide userName or userId")

    # Resolve to a user id if only the name was given. Use live /v4/users -
    # the snapshot may be stale.
    if not target_id:
        all_users = dc.list_users() or []
        match = next((u for u in all_users if (u.get("userName") or "").lower() == target_name.lower()), None)
        if not match or not match.get("id"):
            raise HTTPException(404, f"user {target_name!r} not found")
        target_id = match["id"]
        target_name = match.get("userName") or target_name

    # Read authoritative current members. Filter the target out and check
    # whether they were ever in the org in the first place.
    org = dc.get_organization(org_user_id)
    if not org:
        raise HTTPException(404, f"org {org_user_id} not found")
    members = org.get("members") or []
    keep: List[Dict] = []
    target_was_member = False
    target_role: Optional[str] = None
    for m in members:
        if m.get("id") == target_id:
            target_was_member = True
            target_role = m.get("role") or "Member"
            continue
        keep.append({"id": m.get("id"), "role": m.get("role") or "Member"})
    if not target_was_member:
        return {
            "removed": False,
            "alreadyRemoved": True,
            "finalCount": len(keep),
            "orgName": org.get("name"),
            "reason": "Already not a member",
        }

    # Last-admin guard: if the target is the only Admin, refuse. Prevents
    # the "I locked everyone out" scenario. (Members-only orgs are fine -
    # they can still be managed by Domino admins via /admin.)
    if (target_role or "").lower() == "admin":
        remaining_admins = [m for m in keep if (m.get("role") or "").lower() == "admin"]
        if len(remaining_admins) == 0:
            return {
                "removed": False,
                "finalCount": len(members),
                "orgName": org.get("name"),
                "reason": "lastAdmin",
                "reasonText": (f"{target_name} is the only Admin of {org.get('name')!r}. "
                                "Promote another member to Admin first, or use Domino's admin UI."),
            }

    res = dc.set_organization_members(org_user_id, keep)
    if not res.get("ok"):
        return {
            "removed": False,
            "finalCount": len(members),
            "orgName": org.get("name"),
            "reason": "apiError",
            "error": {"status": res.get("status"), "body": res.get("body")},
        }
    return {
        "removed": True,
        "finalCount": len(keep),
        "orgName": org.get("name"),
        "userName": target_name,
        "role": target_role,
    }


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
                "note": "Filters by accessibility - empty for service accounts without explicit grants. Audit-trail post-processing fills the gap.",
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
    project memberships + role at each, dataset grants, and volume grants -
    in one payload so a compliance officer can spot-check at a glance.

    Drives the AC-9 "end-to-end one user" test and the UI's Verify-User card.
    """
    snap = _resolve_snapshot(snapshot)
    user = next((u for u in snap.get("users", []) if u.get("userName") == user_name), None)
    if not user:
        raise HTTPException(404, f"user {user_name} not found in snapshot")

    uid = user.get("id")
    # In Domino, organizations are also user-shaped principals (they show up
    # in /v4/users with userType=organization). When the looked-up entity
    # is an org, the user-centric questions ("what orgs are they in?", "what
    # projects are they a member of?") flip: callers actually want the org's
    # *members* and the access granted *to the org*. We compute org members
    # here and let the existing grant loops handle access-to-org-as-principal
    # via id/name matching.
    is_organization = (user.get("userType") == "organization")
    organization_members = []
    # When the principal IS an org, capture both ids so the frontend can:
    #   - target the right PUT endpoint (organizationUserId)
    #   - look up viewer admin status against the canonical Organization.id
    #     (which is what viewer.orgAdminIds is keyed on).
    organization_user_id_for_principal = None
    organization_id_for_principal = None
    if is_organization:
        org_record = next(
            (o for o in snap.get("organizations", [])
             if o.get("id") == uid
             or o.get("organizationUserId") == uid
             or o.get("name") == user_name),
            None,
        )
        if org_record:
            organization_user_id_for_principal = org_record.get("organizationUserId") or org_record.get("id")
            organization_id_for_principal = org_record.get("id")
        if org_record:
            for m in org_record.get("members") or []:
                organization_members.append({
                    "userId": m.get("userId"),
                    "userName": m.get("userName"),
                    "role": m.get("role"),
                    "addedAt": m.get("addedAt"),
                    "addedBy": m.get("addedBy"),
                    "removedAt": m.get("removedAt"),
                    "removedBy": m.get("removedBy"),
                    "current": m.get("current"),
                })

    # Project lookup used to enrich dataset/app/volume rows with parent-project
    # owner + name so the frontend can build "Manage in Domino" deep links
    # (Domino UI URLs are scoped under /u/{owner}/{projectName}/...).
    project_by_id = {p.get("id"): p for p in snap.get("projects", []) if p.get("id")}
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
    # Iterate live datasets AND audit-only (deleted) datasets so revoke history
    # and grants on deleted datasets stay visible in user-detail access reviews.
    # Audit-only rows are tagged status="Deleted" so the UI can render them
    # distinctly from currently-active grants.
    for d in list(snap.get("datasets", [])) + list(snap.get("auditOnlyDatasets", [])):
        ds_owner = d.get("ownerName") or d.get("ownerUsername")
        ds_status = "Deleted" if d.get("discoveredVia") == "audit-only" else "Active"
        parent_proj = project_by_id.get(d.get("projectId")) or {}
        proj_owner = parent_proj.get("owner")
        proj_name = parent_proj.get("name")
        for g in d.get("grants", []):
            if g.get("principalId") == uid or g.get("principalName") == user_name:
                dataset_grants.append({
                    "datasetId": d.get("id"),
                    "datasetName": d.get("name"),
                    "datasetOwner": ds_owner,
                    "datasetStatus": ds_status,
                    "projectId": d.get("projectId"),
                    "projectName": proj_name,
                    "projectOwner": proj_owner,
                    "permission": g.get("role") or g.get("permission"),
                    "source": g.get("source"),
                    "grantedAt": g.get("grantedAt"),
                    "grantedBy": g.get("grantedBy"),
                })
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name:
                dataset_grants_issued.append({
                    "datasetId": d.get("id"),
                    "datasetName": d.get("name"),
                    "datasetOwner": ds_owner,
                    "datasetStatus": ds_status,
                    "projectId": d.get("projectId"),
                    "projectName": proj_name,
                    "projectOwner": proj_owner,
                    "principalType": g.get("principalType"),
                    "principalName": g.get("principalName"),
                    "permission": g.get("role") or g.get("permission"),
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
        vol_status = "Deleted" if v.get("discoveredVia") == "audit-only" else "Active"
        if own_grant:
            volume_access_rows.append({
                "volumeId": v.get("id"),
                "volumeName": v.get("name"),
                "volumeType": v.get("volumeType"),
                "volumeStatus": vol_status,
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
                "volumeStatus": vol_status,
                "permission": (v.get("userGrants") or {}).get(uid) or ("read" if v.get("readOnly") else "read/write"),
                "via": "direct user grant",
            })
        for g in v.get("grants") or []:
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name:
                volume_grants_issued.append({
                    "volumeId": v.get("id"),
                    "volumeName": v.get("name"),
                    "volumeType": v.get("volumeType"),
                    "volumeStatus": vol_status,
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

    # Domino Apps this user can access.
    # Three access types: Publisher (the user deployed it), Granted (explicit
    # accessStatuses entry), Authenticated (visibility=AUTHENTICATED - anyone
    # logged in). Per Mockup B we list every app one row each.
    app_access_rows = []
    apps_published = []
    app_grants_issued = []
    for a in snap.get("apps", []):
        access_type = None
        for g in a.get("grants") or []:
            if g.get("principalId") == uid or g.get("principalName") == user_name:
                access_type = g.get("role")
                break
        if access_type is None and a.get("visibility") == "AUTHENTICATED":
            access_type = "Authenticated"
        if access_type:
            app_access_rows.append({
                "appId": a.get("id"),
                "appName": a.get("name"),
                "projectId": a.get("projectId"),
                "projectName": a.get("projectName"),
                "projectOwner": a.get("projectOwner"),
                "publisherName": a.get("publisherName"),
                "visibility": a.get("visibility"),
                "permission": access_type,
                "url": a.get("url"),
            })
        if a.get("publisherId") == uid or a.get("publisherName") == user_name:
            apps_published.append({
                "appId": a.get("id"),
                "appName": a.get("name"),
                "projectId": a.get("projectId"),
                "projectName": a.get("projectName"),
                "projectOwner": a.get("projectOwner"),
                "visibility": a.get("visibility"),
                "url": a.get("url"),
            })
        for g in a.get("grants") or []:
            if g.get("grantedBy") == user_name and g.get("principalName") != user_name \
               and g.get("role") != "Publisher" \
               and (g.get("principalName") or "").lower() != "all authenticated users":
                app_grants_issued.append({
                    "appId": a.get("id"),
                    "appName": a.get("name"),
                    "projectId": a.get("projectId"),
                    "projectName": a.get("projectName"),
                    "projectOwner": a.get("projectOwner"),
                    "principalType": g.get("principalType"),
                    "principalName": g.get("principalName"),
                    "permission": g.get("role"),
                    "grantedAt": g.get("grantedAt"),
                    "grantedBy": g.get("grantedBy"),
                    "url": a.get("url"),
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
                # PUT /v4/organizations/{organizationUserId}/members keys
                # by the user-record id; surface it so the bulk-add modal
                # can target the right org from the user-lookup view too.
                "organizationUserId": o.get("organizationUserId") or o.get("id"),
                "organizationName": o.get("name"),
                "role": m.get("role"),
                "addedAt": m.get("addedAt"),
                "addedBy": m.get("addedBy"),
                "removedAt": m.get("removedAt"),
                "removedBy": m.get("removedBy"),
                "current": m.get("current"),
            })

    # Viewer scope: what the *current* viewer (not the looked-up user) can act on.
    # Frontend uses this to decide whether each "Manage in Domino" action is
    # enabled or disabled-with-tooltip. Computed from the same snapshot so
    # results are consistent with what the rest of the page shows.
    try:
        principal = dc.get_principal()
        viewer_name = principal.get("canonicalName") or principal.get("userName")
        viewer_is_admin = bool(principal.get("isAdmin"))
    except Exception:
        viewer_name = None
        viewer_is_admin = False
    owned_project_ids = []
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if c.get("userName") == viewer_name and (c.get("role") or "") == "Owner":
                owned_project_ids.append(p.get("id"))
                break
    org_admin_ids = []
    for o in snap.get("organizations", []):
        for m in o.get("members") or []:
            if m.get("userName") == viewer_name and (m.get("role") or "").lower() in ("admin", "owner"):
                org_admin_ids.append(o.get("id"))
                break
    # Volumes have per-resource Owners (separate from Domino admins): the
    # viewer can manage a volume's permissions if they're a grantee with
    # role=Owner on that volume. Compute this here so the frontend can
    # decide enable/disable consistently across resource types.
    owned_volume_ids = []
    for v in snap.get("volumes", []):
        for g in v.get("grants") or []:
            if g.get("principalName") == viewer_name and (g.get("role") or "").lower() == "owner":
                owned_volume_ids.append(v.get("id"))
                break
    # Dataset Owners similarly - first-class permissions, not inherited.
    owned_dataset_ids = []
    for d in snap.get("datasets", []):
        for g in d.get("grants") or []:
            role = (g.get("role") or "").lower()
            if g.get("principalName") == viewer_name and ("owner" in role):
                owned_dataset_ids.append(d.get("id"))
                break
    viewer = {
        "userName": viewer_name,
        "isAdmin": viewer_is_admin,
        "ownedProjectIds": owned_project_ids,
        "orgAdminIds": org_admin_ids,
        "ownedVolumeIds": owned_volume_ids,
        "ownedDatasetIds": owned_dataset_ids,
    }

    return {
        "snapshot": _meta(snap),
        "viewer": viewer,
        "dominoHost": os.environ.get("DOMINO_API_HOST", "").rstrip("/"),
        "user": user,
        "isOrganization": is_organization,
        "organizationMembers": organization_members,
        "organizationUserId": organization_user_id_for_principal,
        "organizationId": organization_id_for_principal,
        "globalRoles": user.get("roles") or [],
        "isPrivileged": user.get("isPrivileged"),
        "projectMemberships": project_memberships,
        "datasetGrants": dataset_grants,
        "datasetGrantsIssued": dataset_grants_issued,
        "volumeAccess": volume_access_rows,
        "volumeGrantsIssued": volume_grants_issued,
        "dataSourceGrants": data_source_grants,
        "dataSourceGrantsIssued": data_source_grants_issued,
        "appAccess": app_access_rows,
        "appsPublished": apps_published,
        "appGrantsIssued": app_grants_issued,
        "organizationMemberships": organization_memberships,
        "summary": {
            "projectCount": len(project_memberships),
            "datasetCount": len(dataset_grants),
            "datasetGrantsIssuedCount": len(dataset_grants_issued),
            "volumeCount": len(volume_access_rows),
            "volumeGrantsIssuedCount": len(volume_grants_issued),
            "dataSourceCount": len(data_source_grants),
            "dataSourceGrantsIssuedCount": len(data_source_grants_issued),
            "appCount": len(app_access_rows),
            "appsPublishedCount": len(apps_published),
            "appGrantsIssuedCount": len(app_grants_issued),
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


@app.get("/api/reports/apps")
def report_apps(snapshot: Optional[str] = Query(None)) -> Dict:
    snap = _resolve_snapshot(snapshot)
    return {"snapshot": _meta(snap), "rows": reports.app_access(snap)}


def _meta(snap: Dict) -> Dict:
    return {
        "id": snap.get("id"),
        "takenAt": snap.get("takenAt"),
        "takenBy": snap.get("takenBy"),
        "principal": snap.get("principal") or {},
        "counts": snap.get("counts", {}),
    }


@app.get("/api/dashboard-charts")
def dashboard_charts(snapshot: Optional[str] = Query(None)) -> Dict:
    """Pre-aggregated data for the dashboard's bar charts.

    The full snapshot can be tens of megabytes - serializing every
    project + volume just to compute the chart inputs on the client is
    wasteful. This endpoint returns only what the two charts need:
    top-10 projects by collaborator count, and volume-type histogram."""
    snap = _resolve_snapshot(snapshot)
    projects = snap.get("projects") or []
    top_projects = sorted(
        [{"name": p.get("name") or "-",
          "collaboratorCount": len(p.get("collaborators") or [])} for p in projects],
        key=lambda r: r["collaboratorCount"],
        reverse=True,
    )[:10]

    # Normalize volume type spellings so case variants merge into one bar.
    def _canon(t: str) -> str:
        s = (t or "Unknown")
        up = s.upper()
        if up == "NFS": return "NFS"
        if up == "SMB": return "SMB"
        if up == "EFS": return "EFS"
        if up == "NETAPP": return "NetApp"
        return s
    vol_counts: Dict[str, int] = {}
    for v in (snap.get("volumes") or []):
        t = _canon(v.get("volumeType"))
        vol_counts[t] = vol_counts.get(t, 0) + 1
    volume_types = sorted(
        [{"type": k, "count": v} for k, v in vol_counts.items()],
        key=lambda r: r["count"],
        reverse=True,
    )
    return {"topProjects": top_projects, "volumeTypes": volume_types}


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
    "apps": [
        {"key": "appName", "label": "App"},
        {"key": "projectName", "label": "Project"},
        {"key": "publisherName", "label": "Publisher"},
        {"key": "visibility", "label": "Visibility"},
        {"key": "granteeCount", "label": "Grantees"},
        {"key": "url", "label": "URL"},
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
    if report_key == "apps":
        return reports.app_access(snap)
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
        "apps": "Domino App Access",
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
# structured rows. Unknown questions return the supported-question list - we
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
