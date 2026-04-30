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
REMOTEFS_HOST = os.environ.get("DOMINO_REMOTE_FILE_SYSTEM_HOSTPORT", API_HOST)


def _log(msg: str) -> None:
    print(f"[domino_client] {msg}", file=sys.stdout, flush=True)


def _looks_internal(host: str) -> bool:
    h = (host or "").lower()
    return ("nucleus-" in h) or ("domino-platform" in h) or ("localhost" in h)


# Cached at runtime by the FastAPI middleware (see app.py) — required for
# /api/audittrail because no env var reliably names the install's public URL.
_PUBLIC_HOST_CACHE: str = ""


def set_public_host(host: str) -> None:
    """Called by middleware on each incoming request to remember the install's
    public URL (e.g., https://life-sciences-demo.domino-eval.com)."""
    global _PUBLIC_HOST_CACHE
    if host and not _looks_internal(host):
        _PUBLIC_HOST_CACHE = host.rstrip("/")


def _public_host() -> str:
    """The external Domino URL (https://...) — required for /api/audittrail
    because that microservice isn't routable from the in-cluster API_HOST."""
    if _PUBLIC_HOST_CACHE:
        return _PUBLIC_HOST_CACHE
    from urllib.parse import urlparse
    candidates = [
        os.environ.get("DOMINO_URL"),
        os.environ.get("DOMINO_HOST"),
        os.environ.get("DOMINO_DNS_NAME"),
        os.environ.get("DOMINO_DOMAIN"),
        os.environ.get("DOMINO_RUN_PUBLIC_URL"),
    ]
    for c in candidates:
        if not c:
            continue
        c = c.strip()
        if _looks_internal(c):
            continue
        if c.startswith(("http://", "https://")):
            try:
                p = urlparse(c)
                if p.scheme and p.netloc:
                    return f"{p.scheme}://{p.netloc}"
            except Exception:
                pass
        return f"https://{c.rstrip('/')}"
    return ""


def _host_for(path: str) -> str:
    """Different Domino microservices live on different internal hostnames.
    Route by path prefix so callers can keep writing /remotefs/v1/...
    """
    if path.startswith("/remotefs/"):
        return REMOTEFS_HOST
    if path.startswith("/api/audittrail/"):
        # Audit-trail isn't proxied by nucleus-frontend in this cluster;
        # the in-cluster service name varies by release. Use the public URL
        # — the same approach the audit-export app uses successfully.
        return _public_host() or API_HOST
    return API_HOST


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


def _get(path: str, *, governance: bool = False, params: Optional[Dict] = None,
         expect_json: bool = True) -> Any:
    url = f"{_host_for(path)}{path}"
    headers = get_apikey_headers() if governance else get_bearer_headers()
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code != 200:
            _log(f"GET {path} -> {r.status_code} {r.text[:200]}")
            return None
        return r.json() if expect_json else r.text
    except Exception as e:
        _log(f"GET {path} failed: {e}")
        return None


def _post(path: str, body: Dict, *, governance: bool = False) -> Any:
    url = f"{_host_for(path)}{path}"
    headers = get_apikey_headers() if governance else get_bearer_headers()
    headers = {**headers, "Content-Type": "application/json"}
    try:
        r = requests.post(url, headers=headers, json=body, timeout=30)
        if r.status_code != 200:
            _log(f"POST {path} -> {r.status_code} {r.text[:200]}")
            return None
        return r.json()
    except Exception as e:
        _log(f"POST {path} failed: {e}")
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
#
# History: this app originally hit /v4/datamount/all, which filters by
# accessibility — for a service account without explicit grants it returns
# []. Domino's own UI uses /remotefs/v1/volumes?filter_strictly_by_volume_roles=false
# which is the cross-user view. Grants live on the per-volume detail endpoint.

def list_volumes(status: str = "Active", page_size: int = 200) -> List[Dict]:
    """All registered external data volumes (NetApp/NFS/SMB/EFS), paginated.
    Returns the volume summary records. Each contains
    {id, name, uniqueName, filesystemId, filesystemName, dataPlaneId, status,
     capacity, path, createdBy, createdAt, ...}.
    """
    out: List[Dict] = []
    offset = 0
    while True:
        page = _get("/remotefs/v1/volumes", params={
            "limit": page_size,
            "offset": offset,
            "filter_strictly_by_volume_roles": "false",
            "status": status,
        })
        if not page:
            break
        items = page.get("data") if isinstance(page, dict) else page
        if not isinstance(items, list) or not items:
            break
        out.extend(items)
        if len(items) < page_size:
            break
        offset += len(items)
    return out


def get_volume_detail(volume_id: str) -> Dict:
    """Per-volume detail. Embeds `grants[{targetId, targetRole, targetName,
    isOrganization}]` and `projects[]` (null if not project-mounted)."""
    return _get(f"/remotefs/v1/volumes/{volume_id}") or {}


# Legacy adapter — keeps snapshot.py working until Phase 2 rewrites the
# projection. Translates new /remotefs/v1 shape into the old DataMountDto-ish
# shape (userIds[], userGrants{}, volumeType, readOnly, mountPath).
def list_data_mounts() -> List[Dict]:
    vols = list_volumes()
    out: List[Dict] = []
    for v in vols:
        detail = get_volume_detail(v["id"])
        grants = detail.get("grants") or []
        user_ids: List[str] = []
        user_grants: Dict[str, str] = {}
        for g in grants:
            if g.get("isOrganization"):
                continue  # org grants handled separately in Phase 2
            tid = g.get("targetId")
            if not tid:
                continue
            user_ids.append(tid)
            user_grants[tid] = g.get("targetRole") or "VolumeUser"
        out.append({
            "id": v["id"],
            "name": v.get("name"),
            "volumeType": "Nfs",  # NetApp-backed volumes are NFS; refined in Phase 2
            "dataPlaneId": v.get("dataPlaneId"),
            "readOnly": False,
            "mountPath": v.get("path"),
            "userIds": user_ids,
            "userGrants": user_grants,
            "filesystemName": v.get("filesystemName"),
            "filesystemId": v.get("filesystemId"),
            "uniqueName": v.get("uniqueName"),
            "createdBy": (v.get("createdBy") or {}).get("userName"),
            "createdAt": v.get("createdAt"),
            "status": v.get("status"),
            "projects": detail.get("projects") or [],
            "rawGrants": grants,
        })
    return out


# ---- Audit events ----------------------------------------------------------
#
# Audit-trail is the only Domino API in this app that requires X-Domino-Api-Key
# (not Bearer). The GET /auditevents endpoint, hit on the external public host,
# is the same pattern used successfully by the audit-trail-export app.

_AUDIT_PATH = "/api/audittrail/v1/auditevents"
_AUDIT_PAGE_SIZE = 1000
_AUDIT_MAX_EVENTS = 25000  # safety cap


def list_audit_events(start_iso: Optional[str] = None,
                      end_iso: Optional[str] = None,
                      event_type: Optional[str] = None,
                      limit: Optional[int] = None) -> List[Dict]:
    """Page through Domino's audit trail. Returns oldest-first.

    Each event:
      { timestamp(ms), actor{id,name,firstName,lastName},
        action{eventName, using[], traceId, electronicallySigned},
        targets[{entity{entityType,id,name}, fieldChanges[{fieldName, after, before?}]}],
        affecting[{entityType,id,name}], metadata }
    """
    api_key = os.environ.get("DOMINO_USER_API_KEY") or os.environ.get("API_KEY_OVERRIDE")
    if not api_key:
        _log("audit: no DOMINO_USER_API_KEY set; cannot fetch audit events")
        return []
    headers = {"Content-Type": "application/json", "X-Domino-Api-Key": api_key}
    host = _host_for(_AUDIT_PATH)
    if not host:
        _log("audit: no public host found; cannot fetch audit events")
        return []
    cap = limit or _AUDIT_MAX_EVENTS
    base_params: Dict[str, Any] = {}
    if start_iso:
        from dateutil import parser as _dp
        base_params["startTimestamp"] = int(_dp.parse(start_iso).timestamp() * 1000)
    if end_iso:
        from dateutil import parser as _dp
        base_params["endTimestamp"] = int(_dp.parse(end_iso).timestamp() * 1000)

    out: List[Dict] = []
    offset = 0
    while len(out) < cap:
        page_size = min(_AUDIT_PAGE_SIZE, cap - len(out))
        params = {**base_params, "limit": page_size, "offset": offset}
        try:
            r = requests.get(f"{host}{_AUDIT_PATH}", headers=headers, params=params, timeout=30)
            if r.status_code != 200:
                _log(f"audit GET -> {r.status_code} {r.text[:160]}")
                break
            page = r.json()
        except Exception as e:
            _log(f"audit fetch failed: {e}")
            break
        events = page.get("events") if isinstance(page, dict) else page
        if not isinstance(events, list) or not events:
            break
        out.extend(events)
        if len(events) < page_size:
            break
        offset += len(events)

    if event_type:
        wanted = {event_type} if isinstance(event_type, str) else set(event_type)
        out = [e for e in out if (e.get("action") or {}).get("eventName") in wanted]
    out.sort(key=lambda e: e.get("timestamp") or 0)
    return out


# Convenience: index audit events by (eventName, target_id) so the projection
# can populate "Granted at / Granted by" without re-walking the whole trail.
GRANT_EVENT_NAMES = (
    "Add Collaborator",
    "Change User Role In Project",
    "Add Grant for NetApp-backed Volume",
    "Add Grant For Dataset",
)


def audit_grant_history() -> List[Dict]:
    """All grant-related audit events, oldest-first. Caller indexes as needed.
    Single fetch + client-side filter (the GET endpoint doesn't accept
    eventName as a query param)."""
    wanted = set(GRANT_EVENT_NAMES)
    return [e for e in list_audit_events()
            if (e.get("action") or {}).get("eventName") in wanted]


# ---- Admin Users page (canonical roles, lastWorkload, active, serviceAccount)
#
# /v4/users on this Domino release returns only basic fields — no roles,
# no last activity, no service-account flag. The legacy /admin/users page
# renders that data server-side in HTML. We scrape it.

_ADMIN_USERS_PATH = "/admin/users"


def scrape_admin_users() -> List[Dict]:
    """Parse /admin/users HTML. Returns list of:
       { username, name, signedUp, practitionerWorkloads, lastWorkload,
         ownedProjects, recentProjects, runs, newRuns, active (bool),
         dominoEmployee (bool), serviceAccount (bool), roles (list[str]) }
    Returns [] if the page is unreachable (e.g., caller isn't SysAdmin).
    """
    html = _get(_ADMIN_USERS_PATH, expect_json=False)
    if not html or not isinstance(html, str):
        return []
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        _log("beautifulsoup4 not installed; cannot scrape /admin/users")
        return []
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table", class_=lambda c: c and "users" in c.split())
    if not table:
        _log("/admin/users: users table not found")
        return []
    out: List[Dict] = []
    for tr in table.select("tbody tr"):
        cells = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
        if len(cells) < 13:
            continue
        roles_raw = cells[12]
        roles = [r.strip() for r in roles_raw.replace("\n", ",").split(",") if r.strip()]
        out.append({
            "username": cells[0],
            "name": cells[1],
            "signedUp": cells[2],
            "practitionerWorkloads": cells[3],
            "lastWorkload": None if cells[4] in ("-", "—", "") else cells[4],
            "ownedProjects": cells[5],
            "recentProjects": cells[6],
            "runs": cells[7],
            "newRuns": cells[8],
            "active": cells[9].lower().startswith("y"),
            "dominoEmployee": cells[10].lower().startswith("y"),
            "serviceAccount": cells[11].lower().startswith("y"),
            "roles": roles,
        })
    return out


# ---- Whitelabel ------------------------------------------------------------

def get_whitelabel() -> Dict:
    return _get("/v4/admin/whitelabel/configurations") or {}
