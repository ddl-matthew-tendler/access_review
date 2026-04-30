"""Audit-trail-driven projection of permission state.

Replays Domino audit events (oldest-first) into a projected model that fills
gaps left by the resource APIs:

  * per-user **global roles** — `/v4/users` doesn't expose them; "Update User
    Global Roles" events do.
  * **NetApp volume grants & project-mounts** — `/v4/datamount/all` filters by
    accessibility, so a service account that doesn't hold direct grants gets
    `[]`. The audit trail records every grant/mount regardless.
  * **dataset grants** — supplements `/api/datasetrw/v1/datasets/{id}/grants`
    when that endpoint is restricted.
  * **last-login** per user (when login events are emitted).

Snapshot.take_snapshot() merges this projection on top of the polled resource
state. The projection is the source of truth for fields the resource APIs
hide.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set


# ---- Event-name constants (copy them out so they're easy to tweak) ---------

EVT_USER_ROLES = "Update User Global Roles"
EVT_VOLUME_GRANT_ADD = "Add Grant for NetApp-backed Volume"
EVT_VOLUME_GRANT_REMOVE = "Remove Grant from NetApp-backed Volume"
EVT_VOLUME_PROJECT_ADD = "Add NetApp-backed Volume to Project"
EVT_VOLUME_PROJECT_REMOVE = "Remove NetApp-backed Volume from Project"
EVT_VOLUME_CREATE = "Create NetApp-backed Volume"
EVT_VOLUME_DELETE = "Delete NetApp-backed Volume"
EVT_DATASET_GRANT_ADD = "Add Grant For Dataset"
EVT_DATASET_GRANT_REMOVE = "Remove Grant For Dataset"
EVT_PROJECT_COLLAB_ADD = "Add Collaborator"
EVT_PROJECT_COLLAB_REMOVE = "Remove Collaborator"
EVT_LOGIN_NAMES = {"User Login", "Authenticate User", "Login"}

# Data sources: live API exposes `permissions.userAndOrganizationIds` but no
# grant history. "Change Data Source Permissions" carries the membership delta;
# "Create Data Source" / "Add Datasource Credentials" / "Add Datasource to
# Project" round out the lifecycle for grantedAt/grantedBy provenance.
EVT_DS_PERMS_CHANGE = "Change Data Source Permissions"
EVT_DS_CREATE = "Create Data Source"
EVT_DS_CREDS_ADD = "Add Datasource Credentials"
EVT_DS_PROJECT_ADD = "Add Datasource to Project"

# Organizations: /v4/organizations gives current members but no join/leave
# timestamps. These events let us reconstruct membership history.
EVT_ORG_USERS_ADD = "Add Users To Organization"
EVT_ORG_USER_REMOVE = "Remove User From Organization"
EVT_ORG_CREATE = "Create Organization"


# Normalize Domino's internal role-grant strings to user-facing labels.
# Datasets: DatasetRwReader / DatasetRwEditor / DatasetRwOwner -> Reader / Editor / Owner
# Volumes:  VolumeReader / VolumeUser / VolumeOwner          -> Reader / Editor / Owner
def normalize_grant_role(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return raw
    s = str(raw)
    mapping = {
        "DatasetRwReader": "Reader",
        "DatasetRwEditor": "Editor",
        "DatasetRwOwner": "Owner",
        "VolumeReader": "Reader",
        "VolumeUser": "Editor",
        "VolumeOwner": "Owner",
    }
    return mapping.get(s, s)


def _entity(target: Dict) -> Dict:
    return target.get("entity") or {}


def _field_after(target: Dict, field_name: str) -> Optional[str]:
    for fc in target.get("fieldChanges") or []:
        if fc.get("fieldName") == field_name:
            return fc.get("after")
    return None


def _field_added(target: Dict, field_name: str) -> List[Dict]:
    for fc in target.get("fieldChanges") or []:
        if fc.get("fieldName") == field_name:
            return fc.get("added") or []
    return []


def _field_removed(target: Dict, field_name: str) -> List[Dict]:
    for fc in target.get("fieldChanges") or []:
        if fc.get("fieldName") == field_name:
            return fc.get("removed") or []
    return []


def _affecting_of_type(ev: Dict, entity_type: str) -> List[Dict]:
    return [a for a in (ev.get("affecting") or []) if a.get("entityType") == entity_type]


def project(events: List[Dict]) -> Dict:
    """Replay the event stream and return a projected state dict.

    Returns:
        {
          "userGlobalRoles": {userId: {"name", "roles": set[str], "lastChange": ts}},
          "volumeGrants":    {volumeId: {"name", "grants": {userId: roleStr}}},
          "volumeProjects":  {volumeId: set[projectId]},
          "datasetGrants":   {datasetId: {"name", "grants": {userId: roleStr}}},
          "projectCollaborators": {projectId: {userName: roleStr}},
          "lastLogin":       {userId: tsMs},
          "discoveredVolumes": {volumeId: {"name", "createdAt", "createdBy", "deleted": bool}},
          "dataSourceGrants":  {dsId: {"name", "createdAt", "createdBy",
                                       "grants": {pid: {role, principalName,
                                                        grantedAt, grantedBy}}}},
          "organizationMembers": {orgId: {"name", "createdAt", "createdBy",
                                          "members": {key: {userId, userName,
                                                            addedAt, addedBy,
                                                            removedAt, removedBy}}}},
          "eventCounts":     {eventName: count},
        }
    """
    user_roles: Dict[str, Dict] = defaultdict(lambda: {"name": None, "roles": set(), "lastChange": None})
    volume_grants: Dict[str, Dict] = defaultdict(lambda: {"name": None, "grants": {}})
    volume_projects: Dict[str, Set[str]] = defaultdict(set)
    dataset_grants: Dict[str, Dict] = defaultdict(lambda: {"name": None, "grants": {}})
    project_collabs: Dict[str, Dict[str, str]] = defaultdict(dict)
    last_login: Dict[str, int] = {}
    discovered_volumes: Dict[str, Dict] = {}
    # data_source_grants[dsId] = {
    #   "name": str, "createdAt": ts, "createdBy": actor,
    #   "grants": {principalId: {"role": str, "grantedAt": ts, "grantedBy": actor}}
    # }
    data_source_grants: Dict[str, Dict] = defaultdict(
        lambda: {"name": None, "createdAt": None, "createdBy": None, "grants": {}}
    )
    # organization_members[orgId] = {
    #   "name": str, "createdAt": ts, "createdBy": actor,
    #   "members": {userIdOrName: {"addedAt": ts, "addedBy": actor,
    #                              "removedAt": ts | None, "removedBy": actor | None}}
    # }
    organization_members: Dict[str, Dict] = defaultdict(
        lambda: {"name": None, "createdAt": None, "createdBy": None, "members": {}}
    )
    event_counts: Dict[str, int] = defaultdict(int)

    for ev in events:
        action = (ev.get("action") or {})
        name = action.get("eventName")
        ts = ev.get("timestamp")
        actor = (ev.get("actor") or {}).get("name")
        event_counts[name or "(unknown)"] += 1

        targets = ev.get("targets") or []
        affecting = ev.get("affecting") or []
        in_ctx = ev.get("in") or {}

        if name == EVT_USER_ROLES:
            for t in targets:
                e = _entity(t)
                uid = e.get("id"); uname = e.get("name")
                if not uid:
                    continue
                state = user_roles[uid]
                state["name"] = uname or state["name"]
                state["lastChange"] = ts
                for added in _field_added(t, "roles"):
                    state["roles"].add(added.get("name") if isinstance(added, dict) else str(added))
                for removed in _field_removed(t, "roles"):
                    rname = removed.get("name") if isinstance(removed, dict) else str(removed)
                    state["roles"].discard(rname)

        elif name == EVT_VOLUME_GRANT_ADD or name == EVT_VOLUME_GRANT_REMOVE:
            vols = _affecting_of_type(ev, "netAppVolume")
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "user":
                    continue
                uid = e.get("id") or e.get("name")
                role = _field_after(t, "grantRole") or "VolumeUser"
                for v in vols:
                    vid = v.get("id"); vname = v.get("name")
                    if not vid:
                        continue
                    vg = volume_grants[vid]
                    vg["name"] = vname or vg["name"]
                    if name == EVT_VOLUME_GRANT_ADD:
                        vg["grants"][uid] = role
                    else:
                        vg["grants"].pop(uid, None)

        elif name == EVT_VOLUME_PROJECT_ADD or name == EVT_VOLUME_PROJECT_REMOVE:
            vols = []
            for t in targets:
                e = _entity(t)
                if e.get("entityType") == "netAppVolume" and e.get("id"):
                    vols.append(e)
            projs = _affecting_of_type(ev, "project")
            if not projs and in_ctx.get("entityType") == "project":
                projs = [in_ctx]
            for v in vols:
                vid = v.get("id")
                volume_grants[vid]["name"] = v.get("name") or volume_grants[vid]["name"]
                for p in projs:
                    pid = p.get("id")
                    if not pid:
                        continue
                    if name == EVT_VOLUME_PROJECT_ADD:
                        volume_projects[vid].add(pid)
                    else:
                        volume_projects[vid].discard(pid)

        elif name == EVT_VOLUME_CREATE:
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "netAppVolume":
                    continue
                vid = e.get("id")
                if not vid:
                    continue
                discovered_volumes[vid] = {
                    "id": vid,
                    "name": e.get("name"),
                    "createdAt": ts,
                    "createdBy": actor,
                    "deleted": False,
                }
                volume_grants[vid]["name"] = e.get("name") or volume_grants[vid]["name"]

        elif name == EVT_VOLUME_DELETE:
            for t in targets:
                e = _entity(t)
                vid = e.get("id")
                if vid and vid in discovered_volumes:
                    discovered_volumes[vid]["deleted"] = True

        elif name == EVT_DATASET_GRANT_ADD or name == EVT_DATASET_GRANT_REMOVE:
            ds_list = _affecting_of_type(ev, "dataset")
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "user":
                    continue
                uid = e.get("id") or e.get("name")
                role = _field_after(t, "grantRole") or "DatasetRwReader"
                for ds in ds_list:
                    did = ds.get("id"); dname = ds.get("name")
                    if not did:
                        continue
                    dg = dataset_grants[did]
                    dg["name"] = dname or dg["name"]
                    if name == EVT_DATASET_GRANT_ADD:
                        dg["grants"][uid] = role
                    else:
                        dg["grants"].pop(uid, None)

        elif name == EVT_PROJECT_COLLAB_ADD or name == EVT_PROJECT_COLLAB_REMOVE:
            pid = (in_ctx.get("id") if in_ctx.get("entityType") == "project" else None)
            if not pid:
                continue
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "user":
                    continue
                uname = e.get("name")
                role = _field_after(t, "role")
                if name == EVT_PROJECT_COLLAB_ADD and uname:
                    project_collabs[pid][uname] = role or "Contributor"
                elif name == EVT_PROJECT_COLLAB_REMOVE and uname:
                    project_collabs[pid].pop(uname, None)

        elif name == EVT_DS_PERMS_CHANGE:
            # `affecting` carries the dataSource entity; `targets` may be the
            # data source itself (with fieldChanges on userIds /
            # userAndOrganizationIds), or per-user user targets. Handle both.
            ds_list = _affecting_of_type(ev, "dataSource") or _affecting_of_type(ev, "datasource")
            if not ds_list and (in_ctx.get("entityType") in ("dataSource", "datasource")):
                ds_list = [in_ctx]
            if not ds_list:
                # Fall back to target if it's the data source itself.
                for t in targets:
                    e = _entity(t)
                    if e.get("entityType") in ("dataSource", "datasource") and e.get("id"):
                        ds_list = [e]
                        break
            for ds in ds_list:
                dsid = ds.get("id")
                if not dsid:
                    continue
                state = data_source_grants[dsid]
                state["name"] = ds.get("name") or state["name"]
                # Shape A: target is the data source, fieldChanges have
                # added/removed lists of user IDs (or {id, name}).
                for t in targets:
                    e = _entity(t)
                    if e.get("entityType") in ("dataSource", "datasource") and e.get("id") == dsid:
                        for field in ("userIds", "userAndOrganizationIds", "users", "principals"):
                            for added in _field_added(t, field):
                                pid = added.get("id") if isinstance(added, dict) else str(added)
                                pname = added.get("name") if isinstance(added, dict) else None
                                if not pid:
                                    continue
                                state["grants"][pid] = {
                                    "role": "DataSourceUser",
                                    "principalName": pname,
                                    "grantedAt": ts,
                                    "grantedBy": actor,
                                }
                            for removed in _field_removed(t, field):
                                pid = removed.get("id") if isinstance(removed, dict) else str(removed)
                                state["grants"].pop(pid, None)
                # Shape B: targets are individual users, action implicit.
                for t in targets:
                    e = _entity(t)
                    if e.get("entityType") != "user" or not e.get("id"):
                        continue
                    # If fieldChanges show role/access removal, drop; else add.
                    removed_flag = bool(_field_removed(t, "access") or _field_removed(t, "userIds"))
                    if removed_flag:
                        state["grants"].pop(e["id"], None)
                    else:
                        state["grants"][e["id"]] = {
                            "role": "DataSourceUser",
                            "principalName": e.get("name"),
                            "grantedAt": ts,
                            "grantedBy": actor,
                        }

        elif name == EVT_DS_CREATE:
            for t in targets:
                e = _entity(t)
                if e.get("entityType") not in ("dataSource", "datasource"):
                    continue
                dsid = e.get("id")
                if not dsid:
                    continue
                state = data_source_grants[dsid]
                state["name"] = e.get("name") or state["name"]
                state["createdAt"] = ts
                state["createdBy"] = actor
                # Creator is the implicit owner — surfaces if the live API
                # response loses ownerId for any reason.
                actor_id = (ev.get("actor") or {}).get("id")
                if actor_id and actor_id not in state["grants"]:
                    state["grants"][actor_id] = {
                        "role": "DataSourceOwner",
                        "principalName": actor,
                        "grantedAt": ts,
                        "grantedBy": actor,
                    }

        elif name == EVT_ORG_USERS_ADD:
            # `in` (or `affecting`) carries the organization; `targets` are users.
            org = None
            if in_ctx.get("entityType") == "organization":
                org = in_ctx
            else:
                orgs_aff = _affecting_of_type(ev, "organization")
                if orgs_aff:
                    org = orgs_aff[0]
            if not org or not org.get("id"):
                continue
            oid = org["id"]
            state = organization_members[oid]
            state["name"] = org.get("name") or state["name"]
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "user":
                    continue
                key = e.get("id") or e.get("name")
                if not key:
                    continue
                state["members"][key] = {
                    "userId": e.get("id"),
                    "userName": e.get("name"),
                    "addedAt": ts,
                    "addedBy": actor,
                    "removedAt": None,
                    "removedBy": None,
                }

        elif name == EVT_ORG_USER_REMOVE:
            org = None
            if in_ctx.get("entityType") == "organization":
                org = in_ctx
            else:
                orgs_aff = _affecting_of_type(ev, "organization")
                if orgs_aff:
                    org = orgs_aff[0]
            if not org or not org.get("id"):
                continue
            oid = org["id"]
            state = organization_members[oid]
            state["name"] = org.get("name") or state["name"]
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "user":
                    continue
                key = e.get("id") or e.get("name")
                if not key:
                    continue
                existing = state["members"].get(key) or {
                    "userId": e.get("id"),
                    "userName": e.get("name"),
                    "addedAt": None,
                    "addedBy": None,
                }
                existing["removedAt"] = ts
                existing["removedBy"] = actor
                state["members"][key] = existing

        elif name == EVT_ORG_CREATE:
            for t in targets:
                e = _entity(t)
                if e.get("entityType") != "organization":
                    continue
                oid = e.get("id")
                if not oid:
                    continue
                state = organization_members[oid]
                state["name"] = e.get("name") or state["name"]
                state["createdAt"] = ts
                state["createdBy"] = actor

        elif name in EVT_LOGIN_NAMES:
            for t in targets:
                e = _entity(t)
                if e.get("entityType") == "user" and e.get("id"):
                    if not last_login.get(e["id"]) or ts > last_login.get(e["id"], 0):
                        last_login[e["id"]] = ts
            actor_id = (ev.get("actor") or {}).get("id")
            if actor_id:
                if not last_login.get(actor_id) or ts > last_login.get(actor_id, 0):
                    last_login[actor_id] = ts

    # Convert sets to sorted lists for JSON-friendliness
    return {
        "userGlobalRoles": {
            uid: {"name": s["name"], "roles": sorted(s["roles"]), "lastChange": s["lastChange"]}
            for uid, s in user_roles.items()
        },
        "volumeGrants": {
            vid: {"name": s["name"], "grants": s["grants"]}
            for vid, s in volume_grants.items()
        },
        "volumeProjects": {vid: sorted(pids) for vid, pids in volume_projects.items()},
        "datasetGrants": {
            did: {"name": s["name"], "grants": s["grants"]}
            for did, s in dataset_grants.items()
        },
        "projectCollaborators": {pid: dict(d) for pid, d in project_collabs.items()},
        "lastLogin": {uid: datetime.fromtimestamp(ts/1000, tz=timezone.utc).isoformat()
                      for uid, ts in last_login.items()},
        "discoveredVolumes": discovered_volumes,
        "dataSourceGrants": {
            dsid: {
                "name": s["name"],
                "createdAt": s["createdAt"],
                "createdBy": s["createdBy"],
                "grants": {pid: dict(g) for pid, g in s["grants"].items()},
            }
            for dsid, s in data_source_grants.items()
        },
        "organizationMembers": {
            oid: {
                "name": s["name"],
                "createdAt": s["createdAt"],
                "createdBy": s["createdBy"],
                "members": {k: dict(m) for k, m in s["members"].items()},
            }
            for oid, s in organization_members.items()
        },
        "eventCounts": dict(event_counts),
        "totalEvents": len(events),
    }
