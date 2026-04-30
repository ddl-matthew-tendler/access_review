"""Thin wrapper around Domino APIs used by the permissions audit app.

Re-acquires auth on every call (PATs expire fast). Falls back to API_KEY_OVERRIDE
when set — required for governance endpoints which only accept X-Domino-Api-Key.
"""
import os
import sys
import time
import requests
from typing import Any, Dict, List, Optional


API_HOST = os.environ.get("DOMINO_API_HOST", "http://localhost:8899")


def _log(msg: str) -> None:
    print(f"[domino_client] {msg}", file=sys.stdout, flush=True)


def get_bearer_headers() -> Dict[str, str]:
    """Auth for /v4/* and /api/* (non-governance) endpoints."""
    api_key = os.environ.get("API_KEY_OVERRIDE")
    if api_key:
        return {"X-Domino-Api-Key": api_key}
    try:
        r = requests.get("http://localhost:8899/access-token", timeout=5)
        token = r.text.strip()
        if token.startswith("Bearer "):
            return {"Authorization": token}
        return {"Authorization": f"Bearer {token}"}
    except Exception as e:
        _log(f"bearer token fetch failed: {e}")
        return {}


def get_apikey_headers() -> Dict[str, str]:
    """Governance endpoints only accept X-Domino-Api-Key."""
    api_key = os.environ.get("API_KEY_OVERRIDE")
    if api_key:
        return {"X-Domino-Api-Key": api_key}
    return {}


def _get(path: str, *, governance: bool = False, params: Optional[Dict] = None) -> Any:
    url = f"{API_HOST}{path}"
    headers = get_apikey_headers() if governance else get_bearer_headers()
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            _log(f"GET {path} -> {r.status_code} {r.text[:200]}")
            return None
        return r.json()
    except Exception as e:
        _log(f"GET {path} failed: {e}")
        return None


# ---- Users / Orgs ----------------------------------------------------------

def list_users() -> List[Dict]:
    res = _get("/v4/users") or []
    return res if isinstance(res, list) else []


def list_organizations() -> List[Dict]:
    """Returns Org list with embedded `members: [{id, role}]`."""
    res = _get("/v4/organizations")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and "organizations" in res:
        return res["organizations"]
    return []


def get_principal() -> Dict:
    """Current auth principal — confirms isAdmin and canonical id."""
    return _get("/v4/auth/principal") or {}


def get_user_self() -> Dict:
    """Includes the `roles[]` array for the calling identity."""
    return _get("/v4/users/self") or {}


# ---- Projects --------------------------------------------------------------

def list_projects() -> List[Dict]:
    res = _get("/v4/projects") or []
    return res if isinstance(res, list) else []


def list_collaborators(project_id: str) -> List[Dict]:
    """Fallback only — /v4/projects already embeds collaborators inline."""
    res = _get(f"/v4/projects/{project_id}/collaborators") or []
    return res if isinstance(res, list) else []


# ---- Datasets --------------------------------------------------------------

def list_datasets() -> List[Dict]:
    """Returns flat list of dataset dicts. Domino wraps each as {dataset: {...}}."""
    res = _get("/api/datasetrw/v2/datasets")
    if not res:
        return []
    raw = res.get("datasets") if isinstance(res, dict) else res
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        d = item.get("dataset") if isinstance(item, dict) and "dataset" in item else item
        if isinstance(d, dict):
            out.append(d)
    return out


def list_dataset_grants(dataset_id: str) -> List[Dict]:
    res = _get(f"/api/datasetrw/v1/datasets/{dataset_id}/grants")
    if not res:
        return []
    if isinstance(res, dict) and "grants" in res:
        return res["grants"]
    return res if isinstance(res, list) else []


# ---- External Data Volumes (NetApp / NFS / SMB / EFS) ----------------------

def list_data_mounts() -> List[Dict]:
    """Returns DataMountDto[] for all registered external volumes."""
    res = _get("/v4/datamount/all", params={"updateStatuses": "false"})
    return res if isinstance(res, list) else []


# ---- Audit events (used to derive last-login) ------------------------------

_AUDIT_PATH = "/api/audittrail/v1/auditevents"
_AUDIT_PAGE_SIZE = 1000
_AUDIT_MAX_EVENTS = 25000  # safety cap; tune in production


def list_audit_events(start_iso: Optional[str] = None,
                      end_iso: Optional[str] = None,
                      event_type: Optional[str] = None,
                      limit: Optional[int] = None) -> List[Dict]:
    """Page through Domino's audit trail. Returns oldest-first. Each event:
       { timestamp(ms), actor{id,name}, action{eventName,...},
         targets[{entity, fieldChanges[]}], affecting[], in?, metadata }
    Filtering by start/end/eventType is applied client-side for portability —
    different Domino releases expose different query parameters.
    """
    cap = limit or _AUDIT_MAX_EVENTS
    out: List[Dict] = []
    offset = 0
    while len(out) < cap:
        page_size = min(_AUDIT_PAGE_SIZE, cap - len(out))
        params = {"limit": page_size, "offset": offset}
        page = _get(_AUDIT_PATH, params=params)
        if not page:
            break
        events = page.get("events") if isinstance(page, dict) else page
        if not isinstance(events, list) or not events:
            break
        out.extend(events)
        if len(events) < page_size:
            break
        offset += len(events)
    # Client-side filter
    if event_type or start_iso or end_iso:
        from dateutil import parser as _dp
        start_ms = int(_dp.parse(start_iso).timestamp() * 1000) if start_iso else None
        end_ms = int(_dp.parse(end_iso).timestamp() * 1000) if end_iso else None
        out = [
            e for e in out
            if (not event_type or (e.get("action") or {}).get("eventName") == event_type)
               and (start_ms is None or (e.get("timestamp") or 0) >= start_ms)
               and (end_ms is None or (e.get("timestamp") or 0) <= end_ms)
        ]
    out.sort(key=lambda e: e.get("timestamp") or 0)
    return out


# ---- Whitelabel ------------------------------------------------------------

def get_whitelabel() -> Dict:
    return _get("/v4/admin/whitelabel/configurations") or {}
