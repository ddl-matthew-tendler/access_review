# Domino Access Review

Compliance app for GxP Pharma customers running on Domino Data Lab. Answers the question every auditor asks: **"At this exact moment, who has access to which projects, datasets, NetApp volumes, and global roles?"** — and produces a frozen, dated, signable artifact for periodic access review.

Modeled on what compliance teams already get from Veeva Vault, MasterControl, and SailPoint.

## What it does

| Report | Question it answers |
|---|---|
| **User Access Listing** | User × Project × Role at this moment |
| **Verify a User** | Spot-check one user's full access — projects, datasets, volumes, global roles. Includes ground-truth reconciliation. |
| **Privileged Users** | Who holds SysAdmin / GovernanceAdmin / Org-Admin |
| **Dormant Accounts** | Who hasn't logged in for 90+ days |
| **External Volumes** | Every NetApp / NFS / SMB / EFS volume + who can access it |
| **Snapshots Library** | Frozen point-in-time snapshots, exportable to PDF/CSV |
| **Debug** | Endpoint coverage, audit event counts, principal info |

## Architecture

The app uses a **hybrid four-source merge** to overcome Domino API visibility gaps:

1. **Resource APIs** (`/v4/users`, `/v4/projects`, `/v4/datasetrw`, `/v4/datamount`) — primary state
2. **`/v4/auth/principal`** — confirms calling identity's admin flag
3. **Audit-trail projection** (`/api/audittrail/v1/auditevents`) — replays every grant/revoke event to construct authoritative state. Discovers volumes the resource API hides (e.g., when the calling identity isn't a member). Source of truth for per-user role changes going forward.
4. **`roles_seed.json`** — bootstrap file for roles assigned before audit retention started. Populate once from the admin UI; audit trail keeps it current after that.

Each role/grant carries a `source` field so an auditor can see whether a fact came from a polled API, the audit replay, or the seed.

## Why this matters

Veeva Vault, MasterControl, and SailPoint customers already run quarterly access reviews. This brings Domino into the same audit-readiness baseline — same column shapes, same export formats, ready for an Annex 11 §12 / GAMP 5 O8 inspection.

## Stack

- Python + FastAPI on `0.0.0.0:8888`, started by `app.sh`
- React + Ant Design 5 via CDN (no build step)
- Domino theme (`#543FDE` primary, Inter font)
- Snapshots persisted to `/domino/datasets/local/access_review/snapshots/`
- PDF export via WeasyPrint

## Running locally

```bash
export DOMINO_API_HOST="https://your-domino.example.com"
export API_KEY_OVERRIDE="..."        # service account key with admin scope
bash app.sh
# open http://localhost:8888
```

## Running on Domino

Standard Domino app — `app.sh` binds to `0.0.0.0:8888`. Provide `API_KEY_OVERRIDE` as an environment variable on the workspace/app config (or omit it to use the launching user's bearer token; the launching user must hold the necessary scopes).

## Reconciliation testing

Use `test_reconciliation.py` to verify the app's output matches a Ground Truth Pack:

```bash
python test_reconciliation.py ground_truth/matt.json
```

Ground truth file format:

```json
{
  "userName": "matt_tendler_domino",
  "expectedRoles": ["Practitioner", "SysAdmin"],
  "expectedProjects": [
    {"projectName": "supply_risk_radar", "role": "Owner"}
  ],
  "expectedVolumes": ["NetApp_App", "skill-test-volume"]
}
```

Exit code 0 = all match, 1 = one or more failures.

## Files

```
app.py                  FastAPI: routes, exports, debug + verify endpoints
domino_client.py        Auth + endpoint wrappers
snapshot.py             Snapshot capture, persistence, diff
audit_projection.py     Replays audit events into projected state
roles_seed.py           Loader for bootstrap_roles seed file
roles_seed.json         Bootstrap seed (populate from admin UI)
reports.py              Per-report row builders
pdf_export.py           HTML→PDF via WeasyPrint
static/                 React (CDN) frontend
ground_truth/           Sample ground-truth packs for AC testing
test_reconciliation.py  CI-friendly reconciliation harness
ACCEPTANCE_CRITERIA.md  10 pass/fail acceptance criteria
AC_RESULTS.md           Latest live test results
```

## Known Domino API gaps (and how this app handles them)

| Gap | Fallback |
|---|---|
| `/v4/users` doesn't expose per-user global roles | Audit trail (`Update User Global Roles` events) + `roles_seed.json` |
| `/v4/datamount/all` filters by accessibility — empty for service accounts without explicit grants | Audit trail (`Add Grant for NetApp-backed Volume`, `Add NetApp-backed Volume to Project`, `Create NetApp-backed Volume`) |
| `/v4/users` doesn't expose `status`, `licenseType`, `mfaEnabled`, `lastLogin` | `lastLogin` from audit `User Login` events; others marked as defaults until the customer provides an admin export |
| No `/auditevents` on some releases | Endpoint discovered at `/api/audittrail/v1/auditevents` on this instance — codebase paginates 1000 events at a time |

## Roadmap

- **Phase 2**: Access Change Audit Trail report (diffing snapshots + replaying events). Scheduled snapshot capture via Domino Job.
- **Phase 3**: Periodic Review Campaign with per-project reviewer assignment + 21 CFR Part 11 e-signature.
- **Phase 4**: WORM storage for signed snapshots; IQ/OQ/PQ validation package.
