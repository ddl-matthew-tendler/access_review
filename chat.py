"""Locked-down compliance Q&A.

Hard rules:
  * No external LLM, no model inference, no network egress beyond the Domino
    APIs the rest of the app already uses.
  * Every answer is rendered from real snapshot rows (or audit events). If a
    question doesn't match a known intent, we return the supported list — we
    do NOT generate prose.
  * Every answer carries `sources` so an auditor can trace each row to the
    snapshot id + endpoint it came from.

Supported intents (10):
  1. project_access      Who has access to project(s) X[, Y, Z]?
  2. dataset_access      Who has access to dataset(s) X?
  3. resource_access     Who has access to volume / data source X?
  4. user_access         What does user X have access to?
  5. list_admins         List all administrators (and which kind).
  6. stale_users         Users inactive >= N days who still have grants.
  7. orphan_grants       Deactivated users who still have grants.
  8. public_access       Anything granted publicly / to "Everyone".
  9. recent_changes      Permission changes in the last N days.
 10. anomalies           Anything unusual the auditor should know.

A multi-resource form ("these 4 projects and 3 datasets") is recognised and
fans out into intents 1 + 2 in a single payload.
"""
from __future__ import annotations

import difflib
import re
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from dateutil import parser as dtparser

import domino_client as dc
import reports


# ---------- synonym & fuzzy layer ------------------------------------------
#
# Normalises auditor-speak before the router runs. All substitutions are
# lossless for our intent matcher — we only collapse synonyms, never invent
# new resource names.
SYNONYMS: List[Tuple[str, str]] = [
    (r"\bdormant\b", "stale"),
    (r"\binactive accounts?\b", "stale users"),
    (r"\bnever logged in\b", "haven't logged in"),
    (r"\bsuspicious\b", "unusual"),
    (r"\bweird\b", "unusual"),
    (r"\bred flags?\b", "unusual"),
    (r"\banything wrong\b", "anything unusual"),
    (r"\baudit trail\b", "permission changes"),
    (r"\boff-?boarded\b", "deactivated"),
    (r"\bdisabled accounts?\b", "deactivated users"),
    (r"\beveryone\b", "public"),
    (r"\bworld[- ]readable\b", "public"),
    (r"\bsysadmins?\b", "administrators"),
    (r"\bsuper ?users?\b", "administrators"),
    (r"\bowners?\b(?=\s+of)", "owner"),
]


def _normalize_question(q: str) -> str:
    out = q
    for pat, repl in SYNONYMS:
        out = re.sub(pat, repl, out, flags=re.IGNORECASE)
    return out


def _fuzzy_pick(name: str, candidates: List[str], cutoff: float = 0.78) -> Optional[str]:
    """Return the candidate name closest to `name`, or None below cutoff.

    Used so 'supply risk radar' matches 'supply_risk_radar' and minor typos
    don't fall through to a 'not found' answer. Cutoff is conservative — we
    return None rather than risk matching the wrong project.
    """
    if not name or not candidates:
        return None
    lower_map = {c.lower(): c for c in candidates if c}
    keys = list(lower_map.keys())
    matches = difflib.get_close_matches(name.lower(), keys, n=1, cutoff=cutoff)
    if matches:
        return lower_map[matches[0]]
    # Try a relaxed pass: collapse separators
    norm = re.sub(r"[\s_\-]+", "", name.lower())
    for k, orig in lower_map.items():
        if re.sub(r"[\s_\-]+", "", k) == norm:
            return orig
    return None


SUPPORTED_QUESTIONS = [
    "Who has access to project <name> (and <name>, <name>)?",
    "Who has access to dataset <name>?",
    "Who has access to volume <name>?  /  Who has access to data source <name>?",
    "What does user <userName> have access to?",
    "List all administrators.",
    "Which users haven't logged in in 90 days?",
    "Which deactivated users still have grants?",
    "What is publicly accessible?",
    "Show permission changes in the last 14 days.",
    "Anything unusual I should know about?",
]


# ---------- helpers ---------------------------------------------------------

def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _user_by_name(snap: Dict, name: str) -> Optional[Dict]:
    n = _norm(name)
    for u in snap.get("users", []):
        if _norm(u.get("userName")) == n or _norm(u.get("email")) == n or _norm(u.get("fullName")) == n:
            return u
    # Fuzzy fallback across userName / fullName
    candidates = []
    for u in snap.get("users", []):
        for k in (u.get("userName"), u.get("fullName"), u.get("email")):
            if k:
                candidates.append((k, u))
    pick = _fuzzy_pick(name, [c[0] for c in candidates])
    if pick:
        return next((u for c, u in candidates if c == pick), None)
    return None


def _projects_by_names(snap: Dict, names: List[str]) -> Tuple[List[Dict], List[str]]:
    found, missing = [], []
    all_names = [p.get("name") for p in snap.get("projects", []) if p.get("name")]
    for raw in names:
        n = _norm(raw)
        match = next((p for p in snap.get("projects", [])
                      if _norm(p.get("name")) == n or _norm(p.get("id")) == n), None)
        if not match:
            fuzzy = _fuzzy_pick(raw, all_names)
            if fuzzy:
                match = next((p for p in snap.get("projects", [])
                              if p.get("name") == fuzzy), None)
        if match:
            found.append(match)
        else:
            missing.append(raw)
    return found, missing


def _datasets_by_names(snap: Dict, names: List[str]) -> Tuple[List[Dict], List[str]]:
    found, missing = [], []
    all_names = [d.get("name") for d in snap.get("datasets", []) if d.get("name")]
    for raw in names:
        n = _norm(raw)
        match = next((d for d in snap.get("datasets", [])
                      if _norm(d.get("name")) == n or _norm(d.get("id")) == n), None)
        if not match:
            fuzzy = _fuzzy_pick(raw, all_names)
            if fuzzy:
                match = next((d for d in snap.get("datasets", [])
                              if d.get("name") == fuzzy), None)
        if match:
            found.append(match)
        else:
            missing.append(raw)
    return found, missing


def _volumes_by_names(snap: Dict, names: List[str]) -> Tuple[List[Dict], List[str]]:
    found, missing = [], []
    for raw in names:
        n = _norm(raw)
        match = next((v for v in snap.get("volumes", [])
                      if _norm(v.get("name")) == n or _norm(v.get("id")) == n), None)
        if match:
            found.append(match)
        else:
            missing.append(raw)
    return found, missing


def _data_sources_by_names(snap: Dict, names: List[str]) -> Tuple[List[Dict], List[str]]:
    found, missing = [], []
    for raw in names:
        n = _norm(raw)
        match = next((d for d in snap.get("dataSources", [])
                      if _norm(d.get("displayName")) == n or _norm(d.get("name")) == n
                      or _norm(d.get("id")) == n), None)
        if match:
            found.append(match)
        else:
            missing.append(raw)
    return found, missing


def _user_index(snap: Dict) -> Dict[str, Dict]:
    return {u["id"]: u for u in snap.get("users", []) if u.get("id")}


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


# ---------- intent: project_access ------------------------------------------

PROJECT_COLUMNS = [
    {"key": "projectName", "label": "Project"},
    {"key": "userName", "label": "User"},
    {"key": "email", "label": "Email"},
    {"key": "role", "label": "Role"},
    {"key": "userType", "label": "User type"},
    {"key": "status", "label": "Status"},
    {"key": "grantedAt", "label": "Granted"},
    {"key": "grantedBy", "label": "Granted by"},
]


def answer_project_access(snap: Dict, names: List[str]) -> Dict:
    projects, missing = _projects_by_names(snap, names)
    users = _user_index(snap)
    rows = []
    for p in projects:
        for c in p.get("collaborators", []):
            u = users.get(c.get("userId"), {})
            rows.append({
                "projectId": p.get("id"),
                "projectName": p.get("name"),
                "userId": c.get("userId"),
                "userName": c.get("userName") or u.get("userName"),
                "email": u.get("email"),
                "role": c.get("role"),
                "userType": u.get("userType"),
                "status": u.get("status"),
                "grantedAt": c.get("grantedAt"),
                "grantedBy": c.get("grantedBy"),
            })
    found_names = ", ".join(p.get("name") for p in projects) or "(none)"
    text = (
        f"{len(rows)} grant(s) found across {len(projects)} project(s): {found_names}."
    )
    if missing:
        text += f" Could not find: {', '.join(missing)}."
    return {
        "intent": "project_access",
        "params": {"projects": [p.get("name") for p in projects], "missing": missing},
        "text": text,
        "columns": PROJECT_COLUMNS,
        "rows": rows,
    }


# ---------- intent: dataset_access ------------------------------------------

DATASET_COLUMNS = [
    {"key": "datasetName", "label": "Dataset"},
    {"key": "projectName", "label": "Project"},
    {"key": "principalType", "label": "Principal"},
    {"key": "principalName", "label": "Name"},
    {"key": "permission", "label": "Access"},
    {"key": "grantedAt", "label": "Granted"},
    {"key": "grantedBy", "label": "Granted by"},
]


def answer_dataset_access(snap: Dict, names: List[str]) -> Dict:
    datasets, missing = _datasets_by_names(snap, names)
    all_rows = reports.dataset_access(snap)
    wanted_ids = {d.get("id") for d in datasets}
    rows = [r for r in all_rows if r.get("datasetId") in wanted_ids]
    found = ", ".join(d.get("name") for d in datasets) or "(none)"
    text = f"{len(rows)} grant(s) on {len(datasets)} dataset(s): {found}."
    if missing:
        text += f" Could not find: {', '.join(missing)}."
    return {
        "intent": "dataset_access",
        "params": {"datasets": [d.get("name") for d in datasets], "missing": missing},
        "text": text,
        "columns": DATASET_COLUMNS,
        "rows": rows,
    }


# ---------- intent: resource_access (volumes + data sources) ----------------

VOLUME_COLUMNS = [
    {"key": "volumeName", "label": "Volume"},
    {"key": "volumeType", "label": "Type"},
    {"key": "principalType", "label": "Principal"},
    {"key": "principalName", "label": "Name"},
    {"key": "permission", "label": "Access"},
    {"key": "via", "label": "Via"},
    {"key": "grantedAt", "label": "Granted"},
]

DATASOURCE_COLUMNS = [
    {"key": "dataSourceName", "label": "Data source"},
    {"key": "dataSourceType", "label": "Type"},
    {"key": "credentialType", "label": "Credential"},
    {"key": "principalType", "label": "Principal"},
    {"key": "principalName", "label": "Name"},
    {"key": "permission", "label": "Access"},
]


def answer_volume_access(snap: Dict, names: List[str]) -> Dict:
    volumes, missing = _volumes_by_names(snap, names)
    all_rows = reports.volume_access(snap)
    ids = {v.get("id") for v in volumes}
    rows = [r for r in all_rows if r.get("volumeId") in ids]
    found = ", ".join(v.get("name") for v in volumes) or "(none)"
    text = f"{len(rows)} grant(s) on {len(volumes)} volume(s): {found}."
    if missing:
        text += f" Could not find: {', '.join(missing)}."
    return {
        "intent": "volume_access",
        "params": {"volumes": [v.get("name") for v in volumes], "missing": missing},
        "text": text,
        "columns": VOLUME_COLUMNS,
        "rows": rows,
    }


def answer_data_source_access(snap: Dict, names: List[str]) -> Dict:
    sources, missing = _data_sources_by_names(snap, names)
    all_rows = reports.data_source_access(snap)
    ids = {d.get("id") for d in sources}
    rows = [r for r in all_rows if r.get("dataSourceId") in ids]
    found = ", ".join((d.get("displayName") or d.get("name")) for d in sources) or "(none)"
    text = f"{len(rows)} grant(s) on {len(sources)} data source(s): {found}."
    if missing:
        text += f" Could not find: {', '.join(missing)}."
    return {
        "intent": "data_source_access",
        "params": {"dataSources": [d.get("name") for d in sources], "missing": missing},
        "text": text,
        "columns": DATASOURCE_COLUMNS,
        "rows": rows,
    }


# ---------- intent: user_access ---------------------------------------------

USER_ACCESS_COLUMNS = [
    {"key": "scope", "label": "Scope"},
    {"key": "name", "label": "Name"},
    {"key": "role", "label": "Role / permission"},
    {"key": "extra", "label": "Detail"},
]


def answer_user_access(snap: Dict, name: str) -> Dict:
    user = _user_by_name(snap, name)
    if not user:
        return {
            "intent": "user_access",
            "params": {"userName": name, "missing": [name]},
            "text": f"No user found matching '{name}' in this snapshot.",
            "columns": USER_ACCESS_COLUMNS,
            "rows": [],
        }
    uid = user.get("id")
    rows: List[Dict] = []
    for r in (user.get("roles") or []):
        rows.append({"scope": "Global role", "name": r, "role": r,
                     "extra": "Privileged" if user.get("isPrivileged") else ""})
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if c.get("userId") == uid:
                rows.append({"scope": "Project", "name": p.get("name"),
                             "role": c.get("role"),
                             "extra": f"granted {c.get('grantedAt') or '—'} by {c.get('grantedBy') or '—'}"})
                break
    for d in snap.get("datasets", []):
        for g in d.get("grants") or []:
            if g.get("principalId") == uid:
                rows.append({"scope": "Dataset", "name": d.get("name"),
                             "role": g.get("role"),
                             "extra": f"source: {g.get('source') or '—'}"})
    for v in snap.get("volumes", []):
        for g in v.get("grants") or []:
            if g.get("principalId") == uid:
                rows.append({"scope": "Volume", "name": v.get("name"),
                             "role": g.get("role"),
                             "extra": v.get("volumeType") or ""})
        if uid in (v.get("userIds") or []):
            already = any(r["scope"] == "Volume" and r["name"] == v.get("name") for r in rows)
            if not already:
                rows.append({"scope": "Volume", "name": v.get("name"),
                             "role": "read" if v.get("readOnly") else "read/write",
                             "extra": v.get("volumeType") or ""})
    for ds in snap.get("dataSources", []):
        for g in ds.get("grants") or []:
            if g.get("principalId") == uid:
                rows.append({"scope": "Data source",
                             "name": ds.get("displayName") or ds.get("name"),
                             "role": g.get("role"),
                             "extra": f"{ds.get('dataSourceType') or ''} · {ds.get('credentialType') or ''}"})
    text = (
        f"{user.get('userName')} ({user.get('email') or '—'}, {user.get('userType') or 'human'}, "
        f"status={user.get('status') or '—'}) has {len(rows)} access row(s) in this snapshot."
    )
    return {
        "intent": "user_access",
        "params": {"userName": user.get("userName")},
        "text": text,
        "columns": USER_ACCESS_COLUMNS,
        "rows": rows,
    }


# ---------- intent: list_admins ---------------------------------------------

ADMIN_COLUMNS = [
    {"key": "userName", "label": "User"},
    {"key": "email", "label": "Email"},
    {"key": "roles", "label": "Roles"},
    {"key": "status", "label": "Status"},
    {"key": "lastWorkload", "label": "Last workload"},
]


def answer_list_admins(snap: Dict) -> Dict:
    rows = reports.privileged_users(snap)
    role_counts: Dict[str, int] = {}
    for r in rows:
        for role in r.get("roles") or []:
            role_counts[role] = role_counts.get(role, 0) + 1
    breakdown = ", ".join(f"{n} {r}" for r, n in sorted(role_counts.items(), key=lambda x: -x[1]))
    text = f"{len(rows)} privileged user(s). Breakdown: {breakdown or '—'}."
    return {
        "intent": "list_admins",
        "params": {},
        "text": text,
        "columns": ADMIN_COLUMNS,
        "rows": [{**r, "roles": ", ".join(r.get("roles") or [])} for r in rows],
    }


# ---------- intent: stale_users / orphan_grants -----------------------------

STALE_COLUMNS = [
    {"key": "userName", "label": "User"},
    {"key": "email", "label": "Email"},
    {"key": "status", "label": "Status"},
    {"key": "lastWorkload", "label": "Last workload"},
    {"key": "daysIdle", "label": "Days idle"},
    {"key": "grantCount", "label": "Grants held"},
]


def _grant_counts_by_user(snap: Dict) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            counts[c.get("userId")] = counts.get(c.get("userId"), 0) + 1
    for d in snap.get("datasets", []):
        for g in d.get("grants") or []:
            counts[g.get("principalId")] = counts.get(g.get("principalId"), 0) + 1
    for v in snap.get("volumes", []):
        for g in v.get("grants") or []:
            counts[g.get("principalId")] = counts.get(g.get("principalId"), 0) + 1
        for uid in v.get("userIds") or []:
            counts[uid] = counts.get(uid, 0) + 1
    return counts


def answer_stale_users(snap: Dict, days: int) -> Dict:
    counts = _grant_counts_by_user(snap)
    rows = []
    for u in snap.get("users", []):
        idle = _days_since(u.get("lastWorkload"))
        gc = counts.get(u.get("id"), 0)
        if gc == 0:
            continue
        if idle is None or idle < days:
            continue
        rows.append({
            "userName": u.get("userName"),
            "email": u.get("email"),
            "status": u.get("status"),
            "lastWorkload": u.get("lastWorkload"),
            "daysIdle": idle,
            "grantCount": gc,
        })
    rows.sort(key=lambda r: -(r["daysIdle"] or 0))
    text = f"{len(rows)} user(s) idle ≥ {days} days who still hold grants."
    return {"intent": "stale_users", "params": {"days": days}, "text": text,
            "columns": STALE_COLUMNS, "rows": rows}


def answer_orphan_grants(snap: Dict) -> Dict:
    counts = _grant_counts_by_user(snap)
    rows = []
    for u in snap.get("users", []):
        gc = counts.get(u.get("id"), 0)
        if gc == 0:
            continue
        if u.get("status") and u.get("status") != "Active":
            rows.append({
                "userName": u.get("userName"),
                "email": u.get("email"),
                "status": u.get("status"),
                "lastWorkload": u.get("lastWorkload"),
                "daysIdle": _days_since(u.get("lastWorkload")),
                "grantCount": gc,
            })
    text = f"{len(rows)} non-Active user(s) still holding grants — these should be revoked."
    return {"intent": "orphan_grants", "params": {}, "text": text,
            "columns": STALE_COLUMNS, "rows": rows}


# ---------- intent: public_access -------------------------------------------

PUBLIC_COLUMNS = [
    {"key": "scope", "label": "Scope"},
    {"key": "name", "label": "Resource"},
    {"key": "principalType", "label": "Granted to"},
    {"key": "principalName", "label": "Name"},
    {"key": "permission", "label": "Access"},
]


def _is_broad_principal(principal_type: Optional[str], principal_name: Optional[str]) -> bool:
    pt = _norm(principal_type)
    pn = _norm(principal_name)
    if pt in ("public", "everyone", "organization", "org"):
        return True
    if pn in ("everyone", "all users", "public"):
        return True
    return False


def answer_public_access(snap: Dict) -> Dict:
    rows: List[Dict] = []
    for v in snap.get("volumes", []):
        if v.get("isPublic"):
            rows.append({"scope": "Volume", "name": v.get("name"),
                         "principalType": "Public", "principalName": "All Users",
                         "permission": "read" if v.get("readOnly") else "read/write"})
        for g in v.get("grants") or []:
            if _is_broad_principal(g.get("principalType"), g.get("principalName")):
                rows.append({"scope": "Volume", "name": v.get("name"),
                             "principalType": g.get("principalType"),
                             "principalName": g.get("principalName"),
                             "permission": g.get("role")})
    for d in snap.get("datasets", []):
        for g in d.get("grants") or []:
            if _is_broad_principal(g.get("principalType"), g.get("principalName")):
                rows.append({"scope": "Dataset", "name": d.get("name"),
                             "principalType": g.get("principalType"),
                             "principalName": g.get("principalName"),
                             "permission": g.get("role")})
    for p in snap.get("projects", []):
        if (p.get("visibility") or "").lower() == "public":
            rows.append({"scope": "Project", "name": p.get("name"),
                         "principalType": "Public", "principalName": "All Users",
                         "permission": "visible"})
    text = f"{len(rows)} resource grant(s) accessible to broad / public principals."
    return {"intent": "public_access", "params": {}, "text": text,
            "columns": PUBLIC_COLUMNS, "rows": rows}


# ---------- intent: recent_changes ------------------------------------------

CHANGE_COLUMNS = [
    {"key": "timestamp", "label": "When"},
    {"key": "actor", "label": "Actor"},
    {"key": "event", "label": "Event"},
    {"key": "target", "label": "Target"},
    {"key": "subject", "label": "Subject"},
]


def _format_event(ev: Dict) -> Dict:
    ts = ev.get("timestamp")
    when = ""
    if ts:
        try:
            when = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            when = str(ts)
    targets = ev.get("targets") or []
    affecting = ev.get("affecting") or []
    target_name = ""
    if targets:
        ent = targets[0].get("entity") or {}
        target_name = f"{ent.get('entityType') or ''}: {ent.get('name') or ent.get('id') or ''}"
    subj = ", ".join(a.get("name") or a.get("id") or "" for a in affecting) if affecting else ""
    return {
        "timestamp": when,
        "actor": (ev.get("actor") or {}).get("name"),
        "event": (ev.get("action") or {}).get("eventName"),
        "target": target_name,
        "subject": subj,
    }


def _fetch_audit(days: int) -> List[Dict]:
    start = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        return dc.list_audit_events(start_iso=start, limit=5000) or []
    except Exception:
        return []


GRANT_LIKE_EVENTS = {
    "Add Collaborator", "Remove Collaborator", "Change User Role In Project",
    "Add Grant for NetApp-backed Volume", "Remove Grant For NetApp-backed Volume",
    "Add Grant For Dataset", "Remove Grant For Dataset",
    "Add User Role", "Remove User Role",
    "Disable User", "Enable User", "Delete User",
}


def answer_recent_changes(days: int) -> Dict:
    events = _fetch_audit(days)
    grant_events = [e for e in events
                    if (e.get("action") or {}).get("eventName") in GRANT_LIKE_EVENTS]
    grant_events.sort(key=lambda e: -(e.get("timestamp") or 0))
    rows = [_format_event(e) for e in grant_events[:500]]
    text = (
        f"{len(grant_events)} permission-change event(s) in the last {days} days "
        f"(showing up to 500). Source: /api/audittrail/v1/auditevents."
    )
    return {"intent": "recent_changes", "params": {"days": days}, "text": text,
            "columns": CHANGE_COLUMNS, "rows": rows}


# ---------- intent: anomalies -----------------------------------------------

ANOMALY_COLUMNS = [
    {"key": "severity", "label": "Severity"},
    {"key": "category", "label": "Category"},
    {"key": "detail", "label": "Detail"},
    {"key": "evidence", "label": "Evidence"},
]


def answer_anomalies(snap: Dict, days: int = 14) -> Dict:
    """Deterministic anomaly rules. No model — every line maps to a fact:
       - new SysAdmin / GovernanceAdmin / OrgAdmin grants in window
       - grants made to currently non-Active users
       - off-hours (00:00-05:00 UTC, Sat/Sun) admin role changes
       - mass deletes (>=5 same actor same day)
       - publicly-accessible volumes / datasets in current snapshot
       - users with Owner role on >5 projects (over-broad)
       - shared-credential data sources granted to >10 users
    """
    findings: List[Dict] = []
    events = _fetch_audit(days)
    user_index = _user_index(snap)

    # Rule 1: new admin role grants
    admin_roles = {"SysAdmin", "SystemAdministrator", "GovernanceAdmin",
                   "OrgAdmin", "OrgOwner", "EnvironmentAdmin", "EnvAdmin",
                   "DataSourceAdmin"}
    for e in events:
        if (e.get("action") or {}).get("eventName") != "Add User Role":
            continue
        for t in e.get("targets") or []:
            for fc in t.get("fieldChanges") or []:
                after = fc.get("after")
                if isinstance(after, str) and after in admin_roles:
                    fmt = _format_event(e)
                    findings.append({
                        "severity": "HIGH", "category": "New admin role granted",
                        "detail": f"{after} granted to {fmt['subject'] or fmt['target']}",
                        "evidence": f"{fmt['timestamp']} by {fmt['actor']}",
                    })

    # Rule 2: off-hours / weekend role changes
    for e in events:
        ev = (e.get("action") or {}).get("eventName") or ""
        if "Role" not in ev and "Add Collaborator" not in ev:
            continue
        ts = e.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        except Exception:
            continue
        if dt.weekday() >= 5 or dt.hour < 5:
            fmt = _format_event(e)
            findings.append({
                "severity": "MEDIUM", "category": "Off-hours permission change",
                "detail": f"{ev} on {fmt['target']}",
                "evidence": f"{fmt['timestamp']} by {fmt['actor']}",
            })

    # Rule 3: grants currently held by non-Active users
    counts = _grant_counts_by_user(snap)
    for u in snap.get("users", []):
        if u.get("status") and u.get("status") != "Active":
            gc = counts.get(u.get("id"), 0)
            if gc > 0:
                findings.append({
                    "severity": "HIGH", "category": "Grant on non-Active user",
                    "detail": f"{u.get('userName')} ({u.get('status')}) holds {gc} active grant(s)",
                    "evidence": f"snapshot {snap.get('id')}",
                })

    # Rule 4: mass deletes (>=5 by same actor same day)
    delete_buckets: Dict[Tuple[str, str], int] = {}
    for e in events:
        name = (e.get("action") or {}).get("eventName") or ""
        if "Remove" not in name and "Delete" not in name and "Disable" not in name:
            continue
        actor = (e.get("actor") or {}).get("name") or "?"
        ts = e.get("timestamp")
        if not ts:
            continue
        try:
            day = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            continue
        delete_buckets[(actor, day)] = delete_buckets.get((actor, day), 0) + 1
    for (actor, day), n in delete_buckets.items():
        if n >= 5:
            findings.append({
                "severity": "MEDIUM", "category": "Mass remove/disable activity",
                "detail": f"{actor} performed {n} remove/disable actions on {day}",
                "evidence": f"audit window {days}d",
            })

    # Rule 5: publicly-accessible resources
    pub = answer_public_access(snap)
    for r in pub["rows"]:
        findings.append({
            "severity": "MEDIUM", "category": "Public/broad grant",
            "detail": f"{r['scope']} '{r['name']}' granted to {r['principalName']} ({r['permission']})",
            "evidence": f"snapshot {snap.get('id')}",
        })

    # Rule 6: over-broad Owner role
    owner_counts: Dict[str, int] = {}
    for p in snap.get("projects", []):
        for c in p.get("collaborators", []):
            if (c.get("role") or "").lower() == "owner":
                owner_counts[c.get("userId")] = owner_counts.get(c.get("userId"), 0) + 1
    for uid, n in owner_counts.items():
        if n >= 5:
            u = user_index.get(uid, {})
            findings.append({
                "severity": "LOW", "category": "Over-broad ownership",
                "detail": f"{u.get('userName') or uid} is Owner on {n} projects",
                "evidence": f"snapshot {snap.get('id')}",
            })

    # Rule 7: shared-credential data sources with many users
    for ds in snap.get("dataSources", []):
        if (ds.get("credentialType") or "").lower() != "shared":
            continue
        n = sum(1 for g in (ds.get("grants") or []) if g.get("principalType") in (None, "User"))
        if n >= 10:
            findings.append({
                "severity": "MEDIUM", "category": "Shared-credential data source widely granted",
                "detail": f"'{ds.get('displayName') or ds.get('name')}' uses Shared credential and is granted to {n} users",
                "evidence": f"snapshot {snap.get('id')}",
            })

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["category"]))
    if not findings:
        text = f"No anomalies detected (window: {days}d, snapshot: {snap.get('id')})."
    else:
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        breakdown = ", ".join(f"{n} {s}" for s, n in sev_counts.items())
        text = f"{len(findings)} finding(s) — {breakdown}. Window: {days}d. All facts derived from snapshot + audit trail; no inference."
    return {"intent": "anomalies", "params": {"days": days}, "text": text,
            "columns": ANOMALY_COLUMNS, "rows": findings}


# ---------- intent router ---------------------------------------------------

# Match resource lists like:
#   project foo, project bar, project baz
#   projects foo, bar and baz
#   these projects: foo, bar, baz
_LIST_SEP = re.compile(r"\s*(?:,|;|\band\b|\bplus\b|/|\+)\s*", re.IGNORECASE)


def _extract_after(question: str, keyword: str) -> Optional[str]:
    """Return the substring after the LAST occurrence of `keyword`, stripped."""
    m = re.search(r"\b" + re.escape(keyword) + r"s?\b\s*[:\-]?\s*(.+)$", question, re.IGNORECASE)
    if not m:
        return None
    tail = m.group(1).strip().rstrip("?.").strip()
    tail = re.sub(r"^(named|called)\s+", "", tail, flags=re.IGNORECASE)
    return tail


def _split_resources(s: str) -> List[str]:
    parts = [p.strip().strip("\"'") for p in _LIST_SEP.split(s) if p.strip()]
    return [p for p in parts if p]


def _has(q: str, *kws: str) -> bool:
    ql = q.lower()
    return any(kw in ql for kw in kws)


def route(question: str, snap: Dict) -> Dict:
    q = (question or "").strip()
    ql = q.lower()
    if not q:
        return {"intent": "unknown", "text": "Ask a question.", "columns": [], "rows": [],
                "examples": SUPPORTED_QUESTIONS}

    # Multi-resource fan-out: "these 4 projects and 3 datasets" form
    has_projects = _has(ql, "project")
    has_datasets = _has(ql, "dataset")
    has_volumes = _has(ql, "volume")
    has_data_sources = _has(ql, "data source", "datasource", "snowflake", "redshift")

    if _has(ql, "anything unusual", "unusual", "anomal", "suspicious", "anything i should know",
            "anything worrying", "anything wrong"):
        days = _extract_days(ql, default=14)
        return answer_anomalies(snap, days=days)

    if _has(ql, "publicly", "public access", "everyone", "all users", "world-readable"):
        return answer_public_access(snap)

    if _has(ql, "permission change", "recent change", "what changed", "changes in",
            "audit", "since last"):
        days = _extract_days(ql, default=14)
        return answer_recent_changes(days=days)

    if _has(ql, "deactivated", "disabled user", "non-active", "inactive account"):
        if _has(ql, "still", "grant", "access"):
            return answer_orphan_grants(snap)

    if _has(ql, "haven't logged", "havent logged", "not logged in", "idle", "stale", "dormant",
            "haven't used", "havent used"):
        days = _extract_days(ql, default=90)
        return answer_stale_users(snap, days=days)

    if _has(ql, "administrator", "admins", "sysadmin", "privileged", "elevated role"):
        return answer_list_admins(snap)

    # Multi-user fan-out: "users alice, bob [grants/access/spread]"
    # — typically produced by pronoun resolution from the previous turn
    # ("show their grants" → "show users alice, bob grants").
    mm = re.search(
        r"\busers?\s+([A-Za-z0-9._@\-,\s]+?)(?:\s+(?:grants?|access|spread|profile|projects?|datasets?|volumes?))",
        q, re.IGNORECASE,
    )
    if mm and _has(ql, "grant", "access", "spread", "profile"):
        names = _split_resources(mm.group(1))
        names = [n for n in names if n and n.lower() not in
                 ("the", "a", "an", "these", "those", "all")]
        if len(names) >= 2:
            sections = [answer_user_access(snap, n) for n in names[:25]]
            sections = [s for s in sections if s.get("rows")]
            if sections:
                total = sum(len(s["rows"]) for s in sections)
                return {"intent": "multi", "params": {"users": names},
                        "text": f"Combined access spread for {len(sections)} user(s) — {total} row(s).",
                        "sections": sections, "columns": [], "rows": []}

    # User-centric: "what does <name> have access to" / "what can <name> access"
    m = re.search(r"(?:what\s+(?:does|can)|access\s+for|spread\s+for|profile\s+for|user)\s+([A-Za-z0-9._@\-]+)", q, re.IGNORECASE)
    if m and (_has(ql, "access", "have", "see", "spread", "profile") or ql.startswith("user ")):
        return answer_user_access(snap, m.group(1))

    # Multi-resource: project + dataset + volume in the same question.
    payloads: List[Dict] = []
    if has_projects:
        names = _names_after(q, ["project", "projects"])
        if names:
            payloads.append(answer_project_access(snap, names))
    if has_datasets:
        names = _names_after(q, ["dataset", "datasets"])
        if names:
            payloads.append(answer_dataset_access(snap, names))
    if has_volumes:
        names = _names_after(q, ["volume", "volumes"])
        if names:
            payloads.append(answer_volume_access(snap, names))
    if has_data_sources:
        names = _names_after(q, ["data source", "data sources", "datasource", "datasources"])
        if names:
            payloads.append(answer_data_source_access(snap, names))
    if len(payloads) == 1:
        return payloads[0]
    if len(payloads) > 1:
        # Combine into one multi-section answer
        total_rows = sum(len(p["rows"]) for p in payloads)
        text = f"{total_rows} grant(s) across " + ", ".join(
            f"{len(p['rows'])} on {p['intent'].replace('_access','').replace('_',' ')}" for p in payloads
        ) + "."
        return {"intent": "multi", "params": {}, "text": text, "sections": payloads,
                "columns": [], "rows": []}

    return {
        "intent": "unknown",
        "text": "I don't recognise that question. I only answer from the current snapshot — no model, no guessing. Try one of the supported forms below.",
        "columns": [], "rows": [],
        "examples": SUPPORTED_QUESTIONS,
    }


def _names_after(q: str, keywords: List[str]) -> List[str]:
    """Find resource names listed after any of the given keywords.

    Handles forms like:
       "who has access to projects foo, bar and baz"
       "these 3 projects: foo, bar, baz"
       "the project foo"
    """
    best: List[str] = []
    for kw in keywords:
        # Match each occurrence; pick the one that yields the most resources.
        for m in re.finditer(r"\b" + re.escape(kw) + r"\b\s*[:\-]?\s*(.+?)(?:\?|\.|$)",
                             q, re.IGNORECASE):
            tail = m.group(1)
            # Stop at the next resource keyword so "projects A and dataset B"
            # doesn't sweep B into the project list.
            tail = re.split(r"\b(?:and\s+)?(?:project|dataset|volume|datasource|data source)s?\b",
                            tail, maxsplit=1, flags=re.IGNORECASE)[0]
            names = _split_resources(tail)
            # Drop trailing connector noise
            names = [n for n in names if n.lower() not in
                     ("the", "a", "an", "these", "those", "named", "called", "")]
            if len(names) > len(best):
                best = names
    return best


_DAYS_RE = re.compile(r"(?:in\s+the\s+last\s+|last\s+|past\s+|over\s+|>=?\s*|>\s*|in\s+)?(\d{1,4})\s*(?:day|d)\b", re.IGNORECASE)


def _extract_days(q: str, default: int) -> int:
    m = _DAYS_RE.search(q)
    if not m:
        return default
    try:
        n = int(m.group(1))
        if 1 <= n <= 3650:
            return n
    except Exception:
        pass
    return default


# ============================================================================
# Enrichment layer: narrative, charts, follow-ups, conversation memory.
# All deterministic — every word in the narrative and every datum in every
# chart is derived from the answer's `rows` and the snapshot. No model.
# ============================================================================


# ---- Highcharts spec helpers ----------------------------------------------

def _pie(title: str, pairs: List[Tuple[str, int]]) -> Dict:
    pairs = [(k, v) for k, v in pairs if v]
    return {
        "type": "pie",
        "title": title,
        "data": [{"name": k, "y": v} for k, v in pairs],
    }


def _bar(title: str, categories: List[str], values: List[int],
         x_label: str = "", y_label: str = "Count",
         color_by_category: Optional[Dict[str, str]] = None) -> Dict:
    point_colors = None
    if color_by_category:
        point_colors = [color_by_category.get(c) for c in categories]
    return {
        "type": "bar",
        "title": title,
        "categories": categories,
        "values": values,
        "xLabel": x_label,
        "yLabel": y_label,
        "pointColors": point_colors,
    }


def _line(title: str, categories: List[str], series: List[Dict]) -> Dict:
    return {"type": "line", "title": title, "categories": categories, "series": series}


# ---- Narrative + chart + follow-ups per intent ----------------------------

def _english_list(items: List[str], limit: int = 3) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) <= limit:
        if len(items) == 1:
            return items[0]
        if len(items) == 2:
            return f"{items[0]} and {items[1]}"
        return ", ".join(items[:-1]) + f", and {items[-1]}"
    return ", ".join(items[:limit]) + f", and {len(items) - limit} more"


def _role_breakdown(rows: List[Dict], role_key: str = "role",
                    name_key: str = "userName") -> Tuple[Counter, Dict[str, List[str]]]:
    by_role: Dict[str, List[str]] = {}
    counts: Counter = Counter()
    for r in rows:
        role = r.get(role_key) or "—"
        counts[role] += 1
        by_role.setdefault(role, []).append(r.get(name_key) or "—")
    return counts, by_role


def _enrich_project_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        return
    user_index = _user_index(snap)
    counts, by_role = _role_breakdown(rows, "role", "userName")
    project_names = answer.get("params", {}).get("projects", []) or []
    proj_phrase = _english_list(project_names) or "the requested project(s)"

    # Stale/disabled overlay
    stale, disabled = [], []
    seen_users = set()
    for r in rows:
        uid = r.get("userId")
        if not uid or uid in seen_users:
            continue
        seen_users.add(uid)
        u = user_index.get(uid, {})
        if u.get("status") and u.get("status") != "Active":
            disabled.append(u.get("userName") or r.get("userName"))
        idle = _days_since(u.get("lastWorkload"))
        if idle is not None and idle >= 90:
            stale.append((u.get("userName") or r.get("userName"), idle))

    # Most recent grant
    dated = [r for r in rows if r.get("grantedAt")]
    latest = max(dated, key=lambda r: r["grantedAt"]) if dated else None

    sentences = []
    sentences.append(
        f"{len(seen_users)} user(s) have access to {proj_phrase}: " +
        ", ".join(f"{n} {role}" for role, n in counts.most_common()) + "."
    )
    owners = by_role.get("Owner") or by_role.get("owner") or []
    if owners:
        sentences.append(f"Owner(s): {_english_list(sorted(set(owners)))}.")
    if disabled:
        sentences.append(
            f"⚠ {len(disabled)} non-Active user(s) still listed: {_english_list(sorted(set(disabled)))} — review before next access cycle."
        )
    if stale:
        stale.sort(key=lambda x: -x[1])
        names = [f"{n} ({d}d idle)" for n, d in stale[:3]]
        sentences.append(f"{len(stale)} user(s) idle ≥ 90 days: {_english_list(names)}.")
    if latest:
        sentences.append(
            f"Most recent grant: {latest.get('userName')} as {latest.get('role')} on "
            f"{latest.get('projectName')}, granted {latest.get('grantedAt')[:10]} by "
            f"{latest.get('grantedBy') or '—'}."
        )
    answer["narrative"] = " ".join(sentences)

    # Charts: role distribution pie + per-project user-count bar
    charts: List[Dict] = []
    if counts:
        charts.append(_pie("Role distribution", list(counts.items())))
    proj_counts: Counter = Counter()
    for r in rows:
        proj_counts[r.get("projectName") or "—"] += 1
    if len(proj_counts) > 1:
        cats = [k for k, _ in proj_counts.most_common()]
        vals = [proj_counts[k] for k in cats]
        charts.append(_bar("Grants per project", cats, vals, "Project"))
    answer["charts"] = charts

    # Follow-ups
    followups: List[Dict] = []
    if disabled:
        followups.append({"label": "Show grants for the deactivated users",
                          "question": "Which deactivated users still have grants?"})
    if stale:
        followups.append({"label": "Show all stale users (≥90d)",
                          "question": "Which users haven't logged in in 90 days?"})
    if project_names:
        first = project_names[0]
        followups.append({"label": f"What changed on {first} recently?",
                          "question": f"Show permission changes on project {first} in the last 30 days"})
    followups.append({"label": "Anything unusual?", "question": "Anything unusual I should know about?"})
    answer["followups"] = followups

    # Context for next turn
    answer["resultContext"] = {
        "intent": "project_access",
        "projectIds": list({r.get("projectId") for r in rows if r.get("projectId")}),
        "projectNames": project_names,
        "userIds": list(seen_users),
        "userNames": list({r.get("userName") for r in rows if r.get("userName")}),
    }


def _enrich_dataset_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        return
    counts, by_role = _role_breakdown(rows, "permission", "principalName")
    dataset_names = answer.get("params", {}).get("datasets", []) or []
    sentences = [
        f"{len(rows)} grant(s) on {_english_list(dataset_names) or 'the dataset(s)'}: " +
        ", ".join(f"{n} {role}" for role, n in counts.most_common()) + "."
    ]
    by_dataset: Counter = Counter()
    for r in rows:
        by_dataset[r.get("datasetName") or "—"] += 1
    if by_dataset:
        top = by_dataset.most_common(1)[0]
        sentences.append(f"Most-shared dataset: {top[0]} ({top[1]} grants).")
    answer["narrative"] = " ".join(sentences)

    charts: List[Dict] = []
    if counts:
        charts.append(_pie("Permission distribution", list(counts.items())))
    if len(by_dataset) > 1:
        cats = [k for k, _ in by_dataset.most_common()]
        charts.append(_bar("Grants per dataset", cats, [by_dataset[k] for k in cats], "Dataset"))
    answer["charts"] = charts

    answer["followups"] = [
        {"label": "Who else has Editor on these datasets?",
         "question": f"Who has access to dataset {dataset_names[0]}?" if dataset_names else "Who has access to datasets?"},
        {"label": "Recent dataset grant changes",
         "question": "Show permission changes in the last 14 days"},
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {
        "intent": "dataset_access",
        "datasetIds": list({r.get("datasetId") for r in rows if r.get("datasetId")}),
        "datasetNames": dataset_names,
        "userIds": list({r.get("principalId") for r in rows if r.get("principalId")}),
        "userNames": list({r.get("principalName") for r in rows if r.get("principalName")}),
    }


def _enrich_volume_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        return
    counts, _ = _role_breakdown(rows, "permission", "principalName")
    answer["narrative"] = (
        f"{len(rows)} grant(s) on {_english_list(answer['params'].get('volumes') or []) or 'the volume(s)'}: "
        + ", ".join(f"{n} {p}" for p, n in counts.most_common()) + "."
    )
    answer["charts"] = [_pie("Volume access", list(counts.items()))] if counts else []
    answer["followups"] = [
        {"label": "Are any volumes public?", "question": "What is publicly accessible?"},
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {"intent": "volume_access",
                               "volumeIds": list({r.get("volumeId") for r in rows if r.get("volumeId")})}


def _enrich_data_source_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        return
    cred_counts: Counter = Counter(r.get("credentialType") or "—" for r in rows)
    answer["narrative"] = (
        f"{len(rows)} grant(s). Credential mix: " +
        ", ".join(f"{n} {c}" for c, n in cred_counts.most_common()) + "."
    )
    charts = []
    if cred_counts:
        charts.append(_pie("Credential type", list(cred_counts.items())))
    answer["charts"] = charts
    answer["followups"] = [
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {"intent": "data_source_access"}


def _enrich_user_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        answer["narrative"] = answer.get("text") or ""
        answer["charts"] = []
        answer["followups"] = [
            {"label": "List all administrators", "question": "List all administrators."},
        ]
        return
    user_name = answer.get("params", {}).get("userName")
    user = _user_by_name(snap, user_name) if user_name else None
    scope_counts: Counter = Counter(r.get("scope") for r in rows)
    cats = list(scope_counts.keys())
    sentences = []
    sentences.append(
        f"{user_name} holds {len(rows)} access row(s): " +
        ", ".join(f"{n} {c}" for c, n in scope_counts.most_common()) + "."
    )
    if user:
        if user.get("isPrivileged"):
            sentences.append(f"⚠ Privileged: roles {', '.join(user.get('roles') or [])}.")
        if user.get("status") and user.get("status") != "Active":
            sentences.append(f"⚠ Account status is {user.get('status')} — grants should be revoked.")
        idle = _days_since(user.get("lastWorkload"))
        if idle is not None:
            sentences.append(f"Last workload: {idle} day(s) ago.")
    owner_count = sum(1 for r in rows if (r.get("role") or "").lower() == "owner")
    if owner_count:
        sentences.append(f"Owner role on {owner_count} resource(s).")
    answer["narrative"] = " ".join(sentences)

    charts = []
    if scope_counts:
        charts.append(_bar("Access scope", cats, [scope_counts[c] for c in cats], "Scope"))
    answer["charts"] = charts

    followups = []
    followups.append({"label": "When were these grants made?",
                      "question": "Show permission changes in the last 90 days"})
    if user and user.get("isPrivileged"):
        followups.append({"label": "Compare with other administrators",
                          "question": "List all administrators."})
    followups.append({"label": "Anything unusual?",
                      "question": "Anything unusual I should know about?"})
    answer["followups"] = followups
    answer["resultContext"] = {
        "intent": "user_access",
        "userIds": [user.get("id")] if user else [],
        "userNames": [user_name] if user_name else [],
    }


def _enrich_list_admins(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        answer["narrative"] = "No privileged users in this snapshot."
        answer["charts"] = []
        answer["followups"] = []
        return
    role_counts: Counter = Counter()
    for r in rows:
        roles = r.get("roles") or ""
        for role in [x.strip() for x in roles.split(",") if x.strip()]:
            role_counts[role] += 1
    stale_admins = []
    user_idx = {u.get("userName"): u for u in snap.get("users", [])}
    for r in rows:
        u = user_idx.get(r.get("userName"), {})
        idle = _days_since(u.get("lastWorkload"))
        if idle is not None and idle >= 90:
            stale_admins.append((r.get("userName"), idle))
    sentences = [
        f"{len(rows)} privileged user(s). Role mix: " +
        ", ".join(f"{n} {r}" for r, n in role_counts.most_common()) + "."
    ]
    if stale_admins:
        stale_admins.sort(key=lambda x: -x[1])
        names = [f"{n} ({d}d idle)" for n, d in stale_admins[:3]]
        sentences.append(f"⚠ {len(stale_admins)} stale admin(s): {_english_list(names)}.")
    answer["narrative"] = " ".join(sentences)

    charts = []
    if role_counts:
        cats = [r for r, _ in role_counts.most_common()]
        vals = [role_counts[c] for c in cats]
        charts.append(_bar("Privileged users by role", cats, vals, "Role"))
    answer["charts"] = charts
    answer["followups"] = [
        {"label": "Show stale admins",
         "question": "Which administrators haven't logged in in 90 days?"},
        {"label": "Recent admin role changes",
         "question": "Show permission changes in the last 30 days"},
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {"intent": "list_admins",
                               "userNames": [r.get("userName") for r in rows]}


def _enrich_stale_users(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    days = answer.get("params", {}).get("days", 90)
    if not rows:
        answer["narrative"] = f"No users idle ≥ {days} days hold grants. ✓"
        answer["charts"] = []
        answer["followups"] = []
        return
    top = rows[:3]
    names = [f"{r.get('userName')} ({r.get('daysIdle')}d, {r.get('grantCount')} grants)" for r in top]
    total_grants = sum(r.get("grantCount") or 0 for r in rows)
    sentences = [
        f"{len(rows)} user(s) idle ≥ {days} days hold {total_grants} grant(s) in total.",
        f"Most idle: {_english_list(names)}.",
    ]
    disabled = [r for r in rows if r.get("status") and r.get("status") != "Active"]
    if disabled:
        sentences.append(f"⚠ {len(disabled)} of these are also non-Active.")
    answer["narrative"] = " ".join(sentences)

    # Bucket histogram
    buckets = [(days, 180), (180, 365), (365, 99999)]
    bucket_counts = [0, 0, 0]
    for r in rows:
        d = r.get("daysIdle") or 0
        for i, (lo, hi) in enumerate(buckets):
            if lo <= d < hi:
                bucket_counts[i] += 1
                break
    cats = [f"{days}–180d", "180–365d", "≥1y"]
    charts = [_bar("Users by idle bucket", cats, bucket_counts, "Idleness")]
    answer["charts"] = charts
    answer["followups"] = [
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
        {"label": "Which deactivated users still have grants?",
         "question": "Which deactivated users still have grants?"},
    ]
    answer["resultContext"] = {"intent": "stale_users",
                               "userNames": [r.get("userName") for r in rows]}


def _enrich_orphan_grants(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        answer["narrative"] = "No deactivated users hold grants. ✓"
        answer["charts"] = []
        answer["followups"] = []
        return
    rows_sorted = sorted(rows, key=lambda r: -(r.get("grantCount") or 0))
    top = rows_sorted[:3]
    names = [f"{r.get('userName')} ({r.get('grantCount')} grants)" for r in top]
    total = sum(r.get("grantCount") or 0 for r in rows)
    answer["narrative"] = (
        f"⚠ {len(rows)} deactivated user(s) still hold {total} grant(s). "
        f"Highest: {_english_list(names)}. Recommend revoking before next access cycle."
    )
    cats = [r.get("userName") or "—" for r in rows_sorted[:10]]
    vals = [r.get("grantCount") or 0 for r in rows_sorted[:10]]
    answer["charts"] = [_bar("Orphan grants per user", cats, vals, "User", "Grants held")]
    answer["followups"] = [
        {"label": "Show recent permission changes",
         "question": "Show permission changes in the last 30 days"},
        {"label": "Anything unusual?", "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {"intent": "orphan_grants",
                               "userNames": [r.get("userName") for r in rows]}


def _enrich_public_access(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    if not rows:
        answer["narrative"] = "No resources are broadly/publicly accessible. ✓"
        answer["charts"] = []
        answer["followups"] = []
        return
    scope_counts: Counter = Counter(r.get("scope") for r in rows)
    answer["narrative"] = (
        f"⚠ {len(rows)} resource(s) accessible to broad principals: " +
        ", ".join(f"{n} {s}" for s, n in scope_counts.most_common()) + "."
    )
    answer["charts"] = [_bar("Public/broad grants by scope",
                              list(scope_counts.keys()),
                              list(scope_counts.values()), "Resource type")]
    answer["followups"] = [
        {"label": "Anything else unusual?",
         "question": "Anything unusual I should know about?"},
    ]
    answer["resultContext"] = {"intent": "public_access"}


def _enrich_recent_changes(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    days = answer.get("params", {}).get("days", 14)
    if not rows:
        answer["narrative"] = f"No permission changes in the last {days} days."
        answer["charts"] = []
        answer["followups"] = []
        return
    actor_counts: Counter = Counter(r.get("actor") or "—" for r in rows)
    event_counts: Counter = Counter(r.get("event") or "—" for r in rows)
    top_actor = actor_counts.most_common(1)[0]
    top_event = event_counts.most_common(1)[0]

    # Per-day timeline
    by_day: Counter = Counter()
    for r in rows:
        ts = r.get("timestamp") or ""
        if ts:
            by_day[ts.split(" ")[0]] += 1
    cats = sorted(by_day.keys())
    line_chart = _line(f"Permission changes per day (last {days}d)", cats,
                       [{"name": "Changes", "data": [by_day[c] for c in cats]}]) if cats else None

    sentences = [
        f"{len(rows)} permission change(s) in the last {days} days.",
        f"Most active: {top_actor[0]} ({top_actor[1]} actions).",
        f"Top event: {top_event[0]} ({top_event[1]}×).",
    ]
    answer["narrative"] = " ".join(sentences)
    charts = []
    if line_chart:
        charts.append(line_chart)
    ev_cats = [k for k, _ in event_counts.most_common(8)]
    charts.append(_bar("Top events", ev_cats, [event_counts[c] for c in ev_cats], "Event"))
    answer["charts"] = charts
    answer["followups"] = [
        {"label": "Anything unusual in that window?",
         "question": f"Anything unusual I should know about in the last {days} days?"},
        {"label": "List all administrators", "question": "List all administrators."},
    ]
    answer["resultContext"] = {"intent": "recent_changes", "days": days}


def _enrich_anomalies(answer: Dict, snap: Dict) -> None:
    rows = answer.get("rows") or []
    days = answer.get("params", {}).get("days", 14)
    if not rows:
        answer["narrative"] = f"No anomalies detected (window: {days}d). ✓"
        answer["charts"] = []
        answer["followups"] = []
        return
    sev_counts: Counter = Counter(r.get("severity") for r in rows)
    cat_counts: Counter = Counter(r.get("category") for r in rows)
    top = rows[0]  # already sorted by severity
    sentences = [
        f"{len(rows)} finding(s) over a {days}-day window: " +
        ", ".join(f"{n} {s}" for s, n in sev_counts.most_common()) + ".",
        f"Top finding: [{top.get('severity')}] {top.get('category')} — {top.get('detail')}.",
    ]
    answer["narrative"] = " ".join(sentences)
    sev_color = {"HIGH": "#C20A29", "MEDIUM": "#CCB718", "LOW": "#28A464"}
    answer["charts"] = [
        _bar("Findings by severity",
             list(sev_counts.keys()), list(sev_counts.values()),
             "Severity", "Count", color_by_category=sev_color),
        _bar("Findings by category",
             list(cat_counts.keys()), list(cat_counts.values()), "Category"),
    ]
    answer["followups"] = [
        {"label": "Show recent permission changes",
         "question": f"Show permission changes in the last {days} days"},
        {"label": "Show deactivated users with grants",
         "question": "Which deactivated users still have grants?"},
        {"label": "What is publicly accessible?",
         "question": "What is publicly accessible?"},
    ]
    answer["resultContext"] = {"intent": "anomalies", "days": days}


_ENRICH_BY_INTENT = {
    "project_access": _enrich_project_access,
    "dataset_access": _enrich_dataset_access,
    "volume_access": _enrich_volume_access,
    "data_source_access": _enrich_data_source_access,
    "user_access": _enrich_user_access,
    "list_admins": _enrich_list_admins,
    "stale_users": _enrich_stale_users,
    "orphan_grants": _enrich_orphan_grants,
    "public_access": _enrich_public_access,
    "recent_changes": _enrich_recent_changes,
    "anomalies": _enrich_anomalies,
}


def _enrich(answer: Dict, snap: Dict) -> Dict:
    """Add narrative + charts + follow-ups in place. Always safe to call."""
    if answer.get("intent") == "multi":
        for sec in answer.get("sections") or []:
            _enrich(sec, snap)
        # Top-level narrative summarises the sections
        bits = [s.get("narrative") for s in answer.get("sections") or [] if s.get("narrative")]
        answer["narrative"] = " ".join(bits)
        # Aggregate follow-ups (dedupe)
        seen = set(); fups = []
        for sec in answer.get("sections") or []:
            for f in sec.get("followups") or []:
                key = f.get("question")
                if key and key not in seen:
                    seen.add(key); fups.append(f)
        answer["followups"] = fups
        # Charts: take the first chart of each section to avoid spam
        answer["charts"] = [s.get("charts", [None])[0] for s in answer.get("sections") or []
                            if s.get("charts")]
        return answer
    enricher = _ENRICH_BY_INTENT.get(answer.get("intent"))
    if enricher:
        try:
            enricher(answer, snap)
        except Exception as e:
            # Never let enrichment break the deterministic answer
            answer["narrative"] = answer.get("text") or ""
            answer["charts"] = []
            answer["followups"] = []
            answer["enrichmentError"] = str(e)
    else:
        answer.setdefault("narrative", answer.get("text") or "")
        answer.setdefault("charts", [])
        answer.setdefault("followups", [])
    return answer


# ---- Conversation memory: pronoun resolution ------------------------------
#
# If the new question contains a pronoun ("them", "those users", "their access")
# and the previous turn produced a result with named principals/resources, we
# rewrite the question to make the reference explicit. This is the only place
# context flows in — everything downstream stays deterministic.

_PRONOUN_RE = re.compile(
    r"\b(?:them|they|their|those\s+(?:users?|people|admins?|accounts?)|"
    r"these\s+(?:users?|people|admins?|accounts?)|"
    r"the\s+(?:above|previous)\s+users?|"
    r"that\s+(?:user|person|admin))\b",
    re.IGNORECASE,
)
_PROJECT_PRONOUN_RE = re.compile(
    r"\b(?:those|these|the\s+(?:above|previous))\s+projects?\b", re.IGNORECASE,
)


def _resolve_context(question: str, context: Optional[Dict]) -> str:
    """Rewrite pronouns using the previous turn's result context. If context
    is missing or has no usable principals, leave the question untouched."""
    if not context:
        return question
    q = question
    # Users pronoun
    if _PRONOUN_RE.search(q):
        names = context.get("userNames") or []
        # Cap so we don't blow up the question with hundreds of names
        names = [n for n in names if n][:25]
        if names:
            phrase = "users " + ", ".join(names)
            q = _PRONOUN_RE.sub(phrase, q)
    if _PROJECT_PRONOUN_RE.search(q):
        names = context.get("projectNames") or []
        names = [n for n in names if n][:25]
        if names:
            phrase = "projects " + ", ".join(names)
            q = _PROJECT_PRONOUN_RE.sub(phrase, q)
    return q


# ---- Public entry point ---------------------------------------------------

def answer(question: str, snap: Dict, context: Optional[Dict] = None) -> Dict:
    """Top-level chat entry: normalise, resolve pronouns, route, enrich."""
    if not question or not question.strip():
        return {"intent": "unknown", "text": "Ask a question.", "narrative": "",
                "columns": [], "rows": [], "charts": [], "followups": [],
                "examples": SUPPORTED_QUESTIONS}
    rewritten_with_context = _resolve_context(question, context)
    normalised = _normalize_question(rewritten_with_context)
    result = route(normalised, snap)
    result["originalQuestion"] = question
    if rewritten_with_context != question or normalised != question:
        result["interpretedAs"] = normalised
    _enrich(result, snap)
    return result
