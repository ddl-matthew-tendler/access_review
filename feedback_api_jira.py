"""
QUANTA feedback API: each submission becomes a ticket in the EXT Jira project (Extension Delivery),
in To Do with label feedback-untriaged. "Report a problem" files as Bug; "Suggest an improvement" or no choice files as Story.
The component is the app's name.

Mount in the app's FastAPI backend:
    from feedback_api_jira import build_feedback_router
    app.include_router(build_feedback_router(), prefix="/api")
get_user defaults to the domino-username header; pass the app's own whoami dependency if it has one.
The router also serves the browser files: api/feedback/widget.js and api/feedback/html-to-image.js
(downloaded once by the server if html-to-image.js is not committed next to this file).

Environment (set as Domino project or app environment variables):
    JIRA_BASE        https://dominodatalab.atlassian.net
    JIRA_EMAIL       service account email
    JIRA_API_TOKEN   service account API token
    JIRA_PROJECT     EXT (default)
    FEEDBACK_COMPONENT  optional override of the EXT component (default: the app's name; must exist in EXT)
    APP_ENV          novartis-dev
    FEEDBACK_DIR     fallback store if Jira is unreachable, e.g. /mnt/data/quanta-feedback
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

JIRA_BASE = os.environ.get("JIRA_BASE", "https://dominodatalab.atlassian.net")
JIRA_AUTH = (os.environ.get("JIRA_EMAIL", "").strip(), os.environ.get("JIRA_API_TOKEN", "").strip())
JIRA_PROJECT = os.environ.get("JIRA_PROJECT", "EXT").strip()
if JIRA_PROJECT == "QUANTA":   # QUANTA was decommissioned 16 Oct 2026; old env values route to EXT
    JIRA_PROJECT = "EXT"
APP_ENV = os.environ.get("APP_ENV", "novartis-dev")
FEEDBACK_DIR = Path(os.environ.get("FEEDBACK_DIR", "/mnt/data/quanta-feedback"))

ISSUE_TYPES = {"problem": "Bug", "improvement": "Story",
               "bug": "Bug", "data": "Bug", "confusing": "Story", "idea": "Story"}   # last four: older widget versions
APP_NAMES = {                         # widget app id -> app name, used as the EXT component
    "qc-hub": "SCE QC Hub",
    "rac-ram": "RAC/RAM",
    "publisher": "Publisher",
    "batch-runner": "Batch Runner",
    "permissions-app": "Permissions Admin App",
    "atlas": "Atlas",
}
DEFAULT_COMPONENT = os.environ.get("FEEDBACK_COMPONENT", "").strip()
TRIAGE_LABEL = "feedback-untriaged"
# EXT Bugs require these on create. Severity S0-S1 are left for triage to set.
BUG_SEVERITY_FIELD = "customfield_12907"
BUG_STEPS_FIELD = "customfield_13041"
BUG_EXPECTED_FIELD = "customfield_13042"
BUG_ACTUAL_FIELD = "customfield_13043"
SEVERITY = {4: "S2", 3: "S3", 2: "S3", 1: "S3"}
TYPE_LABELS = {"problem": "Problem", "improvement": "Improvement", "bug": "Something is broken", "data": "Data looks wrong",
               "confusing": "Hard to understand", "idea": "Suggestion"}
PRIORITY = {1: "Nice to have", 2: "Minor", 3: "Major", 4: "Critical"}   # widget urgency dots 1-4
# Widget urgency (4 = Critical) -> EXT priority (P0 highest). P0 is left for triage to set.
JIRA_PRIORITY = {4: "P1", 3: "P2", 2: "P3", 1: "P3"}
MAX_SHOT_BYTES = 5 * 1024 * 1024


# ---- ADF helpers (Jira Cloud description format) ----------------------------------
def _t(s, code=False, strong=False):
    marks = ([{"type": "code"}] if code else []) + ([{"type": "strong"}] if strong else [])
    return {"type": "text", "text": str(s), **({"marks": marks} if marks else {})}

def _p(*parts):
    return {"type": "paragraph", "content": [x if isinstance(x, dict) else _t(x) for x in parts]}

def _h(s):
    return {"type": "heading", "attrs": {"level": 3}, "content": [_t(s)]}

def _row(label, *value):
    return _p(_t(label + ": ", strong=True), *value)

def _bullets(lines):
    return {"type": "bulletList", "content": [
        {"type": "listItem", "content": [_p(line)]} for line in lines]}


# ---- deployment metadata (read once at startup) --------------------------------------
# Only these Domino variables are read. Never add tokens, API keys or credentials here.
DOMINO_VARS = {
    "project": ("DOMINO_PROJECT_OWNER", "DOMINO_PROJECT_NAME"),
    "runId": ("DOMINO_RUN_ID",),
    "hardwareTier": ("DOMINO_HARDWARE_TIER_ID",),
    "environment": ("DOMINO_ENVIRONMENT_ID",),
    "environmentRevision": ("DOMINO_ENVIRONMENT_REVISION_ID",),
}
STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")


def _git(repo: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=3)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _build_info() -> dict:
    repo = Path(os.environ.get("FEEDBACK_REPO_DIR", Path(__file__).resolve().parent))
    info = {"startedAt": STARTED_AT}
    sha = os.environ.get("GIT_SHA") or _git(repo, "rev-parse", "HEAD")
    if sha:
        info["commit"] = sha[:12]
        when = _git(repo, "log", "-1", "--format=%cI")
        if when:
            info["commitDate"] = when
        subject = _git(repo, "log", "-1", "--format=%s")
        if subject:
            info["commitMessage"] = subject[:100]
    version = os.environ.get("FEEDBACK_APP_VERSION")
    if not version:
        for f in ("package.json", "frontend/package.json"):
            try:
                version = json.loads((repo / f).read_text()).get("version")
            except (OSError, ValueError):
                continue
            if version:
                break
    if version:
        info["version"] = str(version)
    for key, names in DOMINO_VARS.items():
        vals = [os.environ.get(n, "") for n in names]
        if all(vals):
            info[key] = "/".join(vals)
    return info


BUILD_INFO = _build_info()


def _reporter(fb: dict, user: dict) -> dict:
    """Header/backend username is authoritative; name and email come from the widget's Domino lookup."""
    viewer = fb.get("viewer") or {}
    name = user.get("userName") or "unknown"
    if name in ("unknown", "") and viewer.get("userName"):
        name = viewer["userName"]
    same = viewer.get("userName") == name
    return {
        "userName": name,
        "fullName": viewer.get("fullName") if same and viewer.get("fullName") else user.get("fullName") or name,
        "email": viewer.get("email") if same else None,
        "mismatch": bool(viewer.get("userName")) and not same,
    }


def _app_name(app_id) -> str:
    """Name from APP_NAMES if mapped (also the EXT component), else a readable form of the id ("study-tracker" -> "Study Tracker")."""
    if app_id in APP_NAMES:
        return APP_NAMES[app_id]
    return " ".join(w.capitalize() for w in str(app_id or "App").replace("_", "-").split("-") if w)


def _problems(fb: dict) -> list:
    calls = fb.get("recentCalls") or []
    failed = [c for c in calls if str(c.get("status", ""))[:1] in ("4", "5", "n")]
    errors = fb.get("recentErrors") or []
    return ([f"{c.get('method')} {c.get('path')} \u2192 {c.get('status')}" for c in failed]
            + [f"JS error: {e.get('msg')}" for e in errors])


def _description(fb: dict, user: dict, expand: bool = True) -> dict:
    """Top: the feedback, one line of facts, detected problems. Below: technical details, collapsed."""
    ctx = fb.get("context") or {}
    clicks = fb.get("recentClicks") or []
    page = fb.get("page") or {}
    who = _reporter(fb, user)
    problems = _problems(fb)

    body = []
    text = str(fb.get("what", "")).strip()
    quote = [_p(line) for line in text.splitlines() if line.strip()] or [_p(_t("(No description, see screenshot)"))]
    if fb.get("expected"):
        quote.append(_p(_t("Expected: ", strong=True), str(fb["expected"])))
    body.append({"type": "panel", "attrs": {"panelType": "note"}, "content": quote})

    person = who["fullName"] + (f" ({who['email']})" if who["email"] else f" ({who['userName']})")
    if who["mismatch"]:
        person += f" [browser reported {fb['viewer'].get('userName')}]"
    screen = ctx.get("view") or page.get("title") or ""
    where = _app_name(fb.get("app")) + (f" / {screen}" if screen else "")
    when = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    facts = [person, where, when]
    if fb.get("priority") in PRIORITY:
        facts.append(f"Urgency {fb['priority']} of 4, {PRIORITY[fb['priority']]}")
    body.append(_p(_t(" \u00b7 ".join(facts))))

    if problems:
        top = [_p(_t(x, code=True)) for x in problems[:3]]
        if len(problems) > 3:
            top.append(_p(f"+{len(problems) - 3} more in Technical details"))
        body.append({"type": "panel", "attrs": {"panelType": "error"}, "content": top})

    tech = []
    b = BUILD_INFO
    if b.get("commit"):
        line = [_t(b["commit"], code=True)]
        if b.get("commitDate"):
            line.append(_t(f" from {b['commitDate'][:16].replace('T', ' ')}"))
        if b.get("commitMessage"):
            line.append(_t(f": {b['commitMessage']}"))
        tech.append(_row("Commit", *line))
    if b.get("version") and b["version"] != "0.0.0":
        tech.append(_row("App version", b["version"]))
    if fb.get("appVersion") and fb["appVersion"] != "unknown":
        tech.append(_row("Front-end bundle", _t(fb["appVersion"], code=True)))
    dom = [f"project {b['project']}" if b.get("project") else "", f"run {b['runId']}" if b.get("runId") else "",
           f"hardware {b['hardwareTier']}" if b.get("hardwareTier") else "", f"app started {b['startedAt'][:16].replace('T', ' ')} UTC"]
    tech.append(_row("Domino", ", ".join(x for x in dom if x) + f" ({APP_ENV})"))
    if page.get("dominoPath"):
        tech.append(_row("Domino page", _t(page["dominoPath"], code=True)))
    c = fb.get("client") or {}
    if c:
        scale = f" at {round(float(c.get('dpr') or 1) * 100)}%" if c.get("dpr") else ""
        bits = [c.get("browser") or "", f"{c.get('screen') or c.get('viewport') or ''}{scale}".strip(), c.get("lang") or "", c.get("tz") or ""]
        tech.append(_row("Browser", ", ".join(x for x in bits if x)))
    tech.append(_row("Filed by", f"{who['fullName']} ({who['userName']}" + (f", {who['email']}" if who["email"] else "") + ")"))
    for k, v in ctx.items():
        tech.append(_row(f"Context {k}", str(v)))
    if clicks:
        tech.append(_row("Click trail", " > ".join((x.get("label") or "?")[:40] for x in clicks[-5:])))
    calls = fb.get("recentCalls") or []
    failed = [x for x in calls if str(x.get("status", ""))[:1] in ("4", "5", "n")]
    if failed:
        tech.append(_p(_t("Failed API calls", strong=True)))
        tech.append(_bullets([f"{x.get('method')} {x.get('path')} returned {x.get('status')} in {x.get('ms', '?')} ms"
                              f" (request {x.get('requestId') or 'n/a'})" for x in failed]))
    errors = fb.get("recentErrors") or []
    if errors:
        tech.append(_p(_t("JS errors", strong=True)))
        tech.append(_bullets([f"{e.get('msg')}" + (f" at {e['src']}" if e.get("src") else "") for e in errors]))
    tech.append(_p("Screenshot and full payload (feedback.json) attached."))

    if expand:
        body.append({"type": "expand", "attrs": {"title": "Technical details"}, "content": tech})
    else:
        body += [_h("Technical details"), *tech]
    return {"type": "doc", "version": 1, "content": body}


def _adf(*lines) -> dict:
    return {"type": "doc", "version": 1, "content": [_p(line) for line in lines if line]}


def _bug_fields(fb: dict) -> dict:
    """Required EXT Bug fields, filled from what the widget captured."""
    ctx = fb.get("context") or {}
    page = fb.get("page") or {}
    screen = ctx.get("view") or page.get("title") or "the page shown in the screenshot"
    clicks = [(x.get("label") or "?")[:40] for x in (fb.get("recentClicks") or [])[-5:]]
    what = str(fb.get("what") or "").strip()
    return {
        BUG_SEVERITY_FIELD: {"value": SEVERITY.get(fb.get("priority"), "S3")},
        BUG_STEPS_FIELD: _adf(f"Reported from {_app_name(fb.get('app'))}, {screen}.",
                              f"Last clicks: {' > '.join(clicks)}" if clicks else "",
                              "Screenshot and page details attached."),
        BUG_ACTUAL_FIELD: _adf(what or "No details given; see the screenshot."),
        BUG_EXPECTED_FIELD: _adf(str(fb.get("expected") or "").strip() or "Not stated separately; see Actual Outcome."),
    }


def _summary(fb: dict) -> str:
    text = " ".join(str(fb.get("what") or fb.get("expected") or "").split())
    first = text.split(". ")[0][:90].rstrip(".") or "(screenshot only)"
    tag = f"[{PRIORITY[fb['priority']]}] " if fb.get("priority") in PRIORITY else ""
    return f"{tag}{_app_name(fb.get('app'))} \u00b7 {TYPE_LABELS.get(fb.get('type'), 'Feedback')}: {first}"


def _app_label(app_id) -> str:
    name = APP_NAMES.get(app_id, str(app_id))
    return "app-" + "-".join("".join(c if c.isalnum() else " " for c in name.lower()).split())


def _component(app_id) -> str:
    return DEFAULT_COMPONENT or _app_name(app_id)


def _fallback_save(fid: str, rec: dict, shot: Optional[bytes]):
    day = FEEDBACK_DIR / datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        day.mkdir(parents=True, exist_ok=True)
    except OSError:
        day = Path("/tmp/quanta-feedback") / day.name
        day.mkdir(parents=True, exist_ok=True)
    (day / f"{fid}.json").write_text(json.dumps(rec, indent=2))
    if shot:
        (day / f"{fid}.png").write_bytes(shot)


HERE = Path(__file__).resolve().parent


HTML_TO_IMAGE_URL = "https://cdn.jsdelivr.net/npm/html-to-image@1.11.11/dist/html-to-image.js"


def _html_to_image_path() -> Optional[Path]:
    """Repo copy if present; otherwise downloaded once by the server (the browser never calls the CDN)."""
    local = HERE / "html-to-image.js"
    if local.is_file():
        return local
    cache = Path(os.environ.get("FEEDBACK_DIR", "/tmp")) / "html-to-image-1.11.11.js"
    if not cache.is_file():
        try:
            res = httpx.get(HTML_TO_IMAGE_URL, timeout=15, follow_redirects=True)
            res.raise_for_status()
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(res.content)
        except (httpx.HTTPError, OSError) as err:
            print(f"[feedback] html-to-image download failed: {err!r}; commit html-to-image.js next to this file", flush=True)
            return None
    return cache


def domino_user(request: Request) -> dict:
    """Username Domino adds to every app request. Default get_user."""
    name = request.headers.get("domino-username", "unknown")
    return {"userName": name, "fullName": name}


def build_feedback_router(get_user: Callable = domino_user) -> APIRouter:
    r = APIRouter(tags=["feedback"])

    @r.get("/feedback/widget.js")
    def widget_js():
        return FileResponse(HERE / "feedback-widget.js", media_type="text/javascript")

    @r.get("/feedback/html-to-image.js")
    def html_to_image_js():
        # Served from the app so screenshots work behind proxies that block public CDNs.
        path = _html_to_image_path()
        if not path:
            raise HTTPException(404, "html-to-image.js not available")
        return FileResponse(path, media_type="text/javascript")

    @r.get("/feedback/build")
    def build():
        """Version metadata this app adds to tickets. Contains no credentials."""
        return BUILD_INFO

    @r.post("/feedback")
    async def create(payload: str = Form(...),
                     screenshot: Optional[UploadFile] = File(None),
                     user: dict = Depends(get_user)):
        try:
            fb = json.loads(payload)
        except ValueError:
            raise HTTPException(400, "payload is not JSON")

        shot = await screenshot.read() if screenshot is not None else None
        if shot and len(shot) > MAX_SHOT_BYTES:
            raise HTTPException(413, "Screenshot over 5 MB")

        who = _reporter(fb, user)
        rec = {**fb, "user": {k: who[k] for k in ("userName", "fullName", "email")},
               "env": APP_ENV, "receivedAt": datetime.now(timezone.utc).isoformat(),
               "build": BUILD_INFO}

        fields = {
            "project": {"key": JIRA_PROJECT},
            "issuetype": {"name": ISSUE_TYPES.get(fb.get("type"), "Story")},
            "summary": _summary(fb),
            "description": _description(fb, user),
            "labels": ["feedback", TRIAGE_LABEL, f"fb-{fb.get('type') or 'unspecified'}", _app_label(fb.get("app")), f"env-{APP_ENV}",
                       "by-" + "".join(c if c.isalnum() or c in "-_." else "-" for c in who["userName"])],
        }
        if fb.get("priority") in PRIORITY:
            fields["labels"].append(f"prio-{fb['priority']}")   # tester's raw 1-4 value
            fields["priority"] = {"name": JIRA_PRIORITY[fb["priority"]]}
        component = _component(fb.get("app"))
        fields["components"] = [{"name": component}]
        if fields["issuetype"]["name"] == "Bug":
            fields.update(_bug_fields(fb))

        try:
            if not all(JIRA_AUTH):
                raise httpx.HTTPError("JIRA_EMAIL or JIRA_API_TOKEN is not set; add it to the Domino project's environment variables and restart the app")
            async with httpx.AsyncClient(base_url=JIRA_BASE, auth=JIRA_AUTH, timeout=20) as jira:
                res = await jira.post("/rest/api/3/issue", json={"fields": fields})
                if res.status_code == 400 and "description" in res.text:
                    # Some Jira projects reject the collapsible section; retry with a plain heading instead.
                    fields["description"] = _description(fb, user, expand=False)
                    res = await jira.post("/rest/api/3/issue", json={"fields": fields})
                if res.status_code == 400 and "priority" in res.text and "priority" in fields:
                    # Priority not on the create screen; the prio-N label still carries it.
                    fields.pop("priority")
                    res = await jira.post("/rest/api/3/issue", json={"fields": fields})
                if res.status_code >= 400 and "components" in res.text:
                    print(f"[feedback] EXT has no component named '{component}'; ask an EXT admin to add it", flush=True)
                if res.status_code >= 400:
                    print(f"[feedback] Jira create failed {res.status_code}: {res.text[:1000]}", flush=True)
                res.raise_for_status()
                key = res.json()["key"]
                files = [("file", ("feedback.json", json.dumps(rec, indent=2).encode(), "application/json"))]
                if shot:
                    files.append(("file", ("screenshot.png", shot, "image/png")))
                att = await jira.post(f"/rest/api/3/issue/{key}/attachments", files=files,
                                      headers={"X-Atlassian-Token": "no-check"})
                if att.status_code >= 400:   # ticket exists; keep it and log the missing attachments
                    print(f"[feedback] {key} attachments failed {att.status_code}: {att.text[:500]}", flush=True)
            return {"id": key, "url": f"{JIRA_BASE}/browse/{key}"}
        except httpx.HTTPError as err:
            print(f"[feedback] Jira error: {err!r}", flush=True)
            fid = f"FB-{datetime.now(timezone.utc):%y%m%d}-{uuid.uuid4().hex[:5].upper()}"
            _fallback_save(fid, rec, shot)
            return {"id": fid, "url": None, "queued": True, "error": str(err)[:300]}

    return r
