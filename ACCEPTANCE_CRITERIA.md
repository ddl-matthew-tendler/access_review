# Acceptance Criteria — Domino Permissions Audit App (Phase 1 MVP)

The test method throughout is **ground-truth reconciliation**: the user provides a known list of users (and ideally projects, datasets, volumes) for a target Domino instance, and we verify the app surfaces the same access state the user can see in the Domino UI. Each AC is binary pass/fail.

The list of users / projects / volumes the user provides ahead of time is referred to below as the **Ground Truth Pack** — see the section at the end for what to provide.

---

## AC-1 — Connectivity & auth

**Goal:** the app reaches Domino with the credentials provided.

| # | Test | Pass criteria |
|---|------|---------------|
| 1.1 | `GET /api/health` returns `ok: true` | `userCount` matches Ground Truth user total ±0 |
| 1.2 | `hasApiKey: true` when `API_KEY_OVERRIDE` is set | True |
| 1.3 | App stops auto-falling-back to dummy mode | Dummy toggle is **off** by default after page load |

---

## AC-2 — User completeness

**Goal:** every user in Ground Truth appears in the app's user listing exactly once.

| # | Test | Pass criteria |
|---|------|---------------|
| 2.1 | Take a fresh snapshot, open **User access listing**. For each user in the Ground Truth Pack, search by username and confirm at least one row exists | 100% of Ground Truth users found |
| 2.2 | No duplicate user IDs across the snapshot's `users[]` | `len(users) == len(set(u.id))` |
| 2.3 | For each user, `email`, `status` (Active/Disabled), and `licenseType` are present and match the Ground Truth Pack | ≥95% field-level match (allow for whitelabel/license naming differences) |
| 2.4 | Users disabled in Domino show `status: Disabled` | 100% match |

---

## AC-3 — Project permissions per user (the core ask)

**Goal:** for each user, the app correctly reports every project they have access to and the role on each.

| # | Test | Pass criteria |
|---|------|---------------|
| 3.1 | Pick 5 users from Ground Truth spanning role types (Owner, Admin, Contributor, ResultsConsumer, LauncherUser). For each, filter the User Access Listing by username | Set of (project, role) rows the app shows == set in Ground Truth Pack |
| 3.2 | Pick a project from Ground Truth. Open Project Role Matrix for it | Set of users + roles == Ground Truth project membership |
| 3.3 | Project owners always appear with role `Owner` (not omitted as v4 collaborators API does) | 100% of project owners present |
| 3.4 | A user removed from a project after Snapshot A and present in Snapshot B does NOT appear in Snapshot A's listing for that project | Verified by diff of A vs B |

---

## AC-4 — Global / platform permissions per user

**Goal:** for each user, system-level roles (SysAdmin, Org Owner, Env Admin, Data Source Admin) are correctly reported.

| # | Test | Pass criteria |
|---|------|---------------|
| 4.1 | The Privileged User Report contains every user listed as a SysAdmin in Ground Truth | 100% match |
| 4.2 | No false positives: every row in Privileged Report is in Ground Truth's privileged list | 100% match |
| 4.3 | For each privileged user, the `roles[]` field contains the correct privileged role name | ≥90% match (Domino's role taxonomy may vary by version) |
| 4.4 | MFA flag is correct for each privileged user | 100% match against Ground Truth (or marked "unknown" consistently if Domino doesn't expose it) |
| 4.5 | Org membership: each user's organizations match Ground Truth `org_membership` | 100% match |

---

## AC-5 — Data permissions per user (Datasets)

**Goal:** for each user, every dataset grant they hold is reported.

| # | Test | Pass criteria |
|---|------|---------------|
| 5.1 | Pick 3 datasets from Ground Truth. Open Project Role Matrix → datasets section for the parent project | All Ground Truth grants for those datasets are present |
| 5.2 | A grant of permission `admin` / `write` / `read` is reported with the same `permission` value | 100% match |
| 5.3 | If a dataset is granted to an organization, the app resolves which users that means (or clearly tags `principalType: Organization`) | Either expanded user list matches, or org name is shown verbatim |

---

## AC-6 — Data permissions per user (External Data Volumes — NetApp / NFS / SMB / EFS)

**Goal:** for each user, every external volume they can access is reported with the correct mount path and read-only flag.

| # | Test | Pass criteria |
|---|------|---------------|
| 6.1 | Open **External volumes** page. Total count matches Ground Truth volume count | 100% match |
| 6.2 | For each NetApp NFS volume in Ground Truth, the app shows `volumeType: Nfs` and the correct `mountPath` | 100% match |
| 6.3 | Pick a user from Ground Truth with direct volume access. Filter Volumes by their username | All `principalType: User` rows for that user match Ground Truth `userIds` |
| 6.4 | Pick a project from Ground Truth with a project-mount. Filter Volumes by project name | All `principalType: Project` rows match Ground Truth `projectIds` |
| 6.5 | Volumes flagged `isPublic: true` appear with `principalType: Public` and a danger-colored tag | 100% match |
| 6.6 | Read-only volumes show `permission: read` (not `read/write`) | 100% match |
| 6.7 | The "Public-mounted" stat card on the Volumes page equals the count of volumes with `isPublic: true` | 100% match |

---

## AC-7 — Last-login & dormant detection

**Goal:** the dormant report correctly identifies inactive accounts using `/auditevents` of type `UserLogin`.

| # | Test | Pass criteria |
|---|------|---------------|
| 7.1 | Provide one user known to have logged in within the last 7 days. They do NOT appear in dormant list at threshold = 90 | Pass |
| 7.2 | Provide one user known to have not logged in for >180 days. They appear with recommendation `Disable account (>180d inactive)` | Pass |
| 7.3 | Disabled accounts always appear regardless of last-login | Pass |
| 7.4 | Threshold input changes the listing live (90 → 30 expands rows) | Pass |
| 7.5 | If `/auditevents` is unavailable / returns nothing, the report is not silently empty — every user gets `recommendation: No login record — investigate` | Pass |

---

## AC-8 — Snapshot immutability & audit-readiness

**Goal:** snapshots are frozen, dated, and exportable in a form an auditor would accept.

| # | Test | Pass criteria |
|---|------|---------------|
| 8.1 | Take Snapshot A. Note its ID + counts | Snapshot file exists at `/domino/datasets/local/permissions_app/snapshots/{id}.json` |
| 8.2 | Manually grant a new project collaborator in Domino. Take Snapshot B | Snapshot B counts differ; A is unchanged on disk |
| 8.3 | `GET /api/snapshots/{a}/diff/{b}` reports the new grant under `projectRolesGranted` | Pass |
| 8.4 | PDF export of any report displays: title, snapshot ID, snapshot timestamp, taker, row count | Pass |
| 8.5 | CSV export round-trips through Excel without column shifts | Pass |
| 8.6 | Snapshots library lists snapshots in reverse chronological order | Pass |

---

## AC-9 — Spot-check end-to-end (the customer demo test)

**Goal:** prove the customer demo works for one named user end-to-end.

For one specific Ground Truth user (recommend: a non-admin Contributor on 2+ projects, with at least one dataset grant and at least one NetApp volume mount):

| # | Test | Pass criteria |
|---|------|---------------|
| 9.1 | Search User Access Listing for them | All projects + roles match |
| 9.2 | They do NOT appear in Privileged Report | Pass |
| 9.3 | They do NOT appear in Dormant Report (assuming recent login) | Pass |
| 9.4 | Volumes page filtered to their username shows every NetApp / NFS / SMB / EFS volume they can read | 100% match |
| 9.5 | Export a PDF of their User Access Listing (filtered by their username) | PDF opens, shows the same rows |

---

## AC-10 — UX checklist (per skill `ux-review`)

| # | Test | Pass criteria |
|---|------|---------------|
| 10.1 | Exactly one Primary button per view | Pass |
| 10.2 | Truncated cells (email, project name) have tooltips with full content | Pass |
| 10.3 | No custom dark TopNav — Domino's nav remains visible above the app | Pass |
| 10.4 | Numeric columns right-aligned (Days inactive, counts) | Pass |
| 10.5 | Empty states explain what / why / what next (e.g., Privileged page when nobody is privileged) | Pass |
| 10.6 | Disabled "Take snapshot" button (in dummy mode) has a tooltip explaining why | Pass |

---

# Ground Truth Pack — what you provide

To run AC-2 through AC-9 we need a **frozen-in-time** ground truth from your target Domino instance, captured at roughly the same moment as the app's first snapshot (within ~10 minutes is fine).

## Option A — minimum (covers ACs 2, 3, 6, 9)

A single CSV or spreadsheet with these columns, one row per **(user, project, role)** pair plus a separate sheet/section per other resource:

**Sheet 1: users**
```
user_id, username, email, full_name, status, license_type, is_privileged, privileged_roles, mfa_enabled, last_login_iso
```

**Sheet 2: project_access** (one row per user-project-role)
```
user_id, username, project_id, project_name, role, granted_at_iso
```

**Sheet 3: dataset_grants**
```
dataset_id, dataset_name, project_id, principal_type, principal_id, principal_name, permission
```

**Sheet 4: volumes** (NetApp / NFS / SMB / EFS)
```
volume_id, volume_name, volume_type, mount_path, read_only, is_public, granted_user_ids, granted_project_ids
```

**Sheet 5: organizations** (optional but improves AC-4)
```
org_id, org_name, member_user_ids
```

## Option B — fastest (covers AC-9 only, ~30 min to assemble)

Pick **one specific user** and provide a single page describing their full access:
- Username, email, status, license type
- Every project they're on + role
- Every privileged/system role they hold
- Every dataset grant they hold
- Every NetApp / external volume they can read or write

We use them as the demo of "the system can answer the compliance question for any one user."

## What we also need from you

| Item | Purpose |
|---|---|
| `DOMINO_API_HOST` | URL of the target Domino instance |
| Service-account API key (with admin scope) for `API_KEY_OVERRIDE` | Required to see all users / governance / `/v4/datamount/all`. The service account must hold a SysAdmin-equivalent role |
| Confirmation the service account can see the user list (at minimum: `curl -H "X-Domino-Api-Key: ..." {host}/v4/users` returns >0 rows) | Sanity check before we run the suite |
| Time window for the test | So the snapshot timestamp is close to when you froze the Ground Truth Pack |
| (Optional) A test project where it's safe to grant/revoke a collaborator | For AC-8.2 (snapshot diff). If not safe, we can skip 8.2 and 8.3 |
| (Optional) The Domino release version | Some endpoint shapes vary across releases; helps us debug field-name mismatches |

## Test workflow once you provide the pack

1. You hand me the Ground Truth Pack + API host + service-account key.
2. I deploy the app to the target Domino instance (or run it locally pointed at the host).
3. I call `POST /api/snapshots` to capture a snapshot at time T.
4. I run AC-1 through AC-10 and produce a results matrix: Pass / Fail / Partial, with specific row-level mismatches called out.
5. Each Fail becomes a defect with: which Domino API field we expected vs got, and a proposed fix.
