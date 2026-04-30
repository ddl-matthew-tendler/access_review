"""Parity check: snapshot dataset/volume counts vs Domino admin pages.

Run inside Domino (or with API_KEY_OVERRIDE pointing to a SysAdmin key) where
both the admin pages and the listing endpoints are reachable. Fails loudly if
the snapshot drops resources the admin page lists — guards against the
visibility-filter sliver bug we fixed.

Usage:
    python test_admin_parity.py
    python test_admin_parity.py --strict  # exit nonzero on any drift
"""
from __future__ import annotations

import os
import sys

import domino_client as dc
import snapshot as snapmod


def main() -> int:
    strict = "--strict" in sys.argv

    print(f"DOMINO_API_HOST={os.environ.get('DOMINO_API_HOST', 'unset')}")
    print(f"API_KEY_OVERRIDE={'set' if os.environ.get('API_KEY_OVERRIDE') else 'NOT SET'}")
    principal = dc.get_principal()
    print(f"calling as: {principal.get('canonicalName')} (admin={principal.get('isAdmin')})")
    print()

    admin_datasets = dc.scrape_admin_datasets()
    admin_volumes = dc.scrape_admin_netapp_volumes()
    api_datasets = dc.list_datasets()
    api_volumes = dc.list_data_mounts()

    print(f"/admin/dataSets       → {len(admin_datasets)} datasets")
    print(f"/api/datasetrw/v2     → {len(api_datasets)} datasets")
    print(f"/admin/netappVolumes  → {len(admin_volumes)} volumes")
    print(f"/v4/datamount/all     → {len(api_volumes)} volumes")
    print()

    if not admin_datasets and not admin_volumes:
        print("WARNING: both admin scrapes returned 0 — caller is likely not SysAdmin.")
        print("Set API_KEY_OVERRIDE to a SysAdmin user's API key and re-run.")
        return 1 if strict else 0

    snap = snapmod.take_snapshot(taken_by="parity-test")
    snap_ds = len(snap.get("datasets", []))
    snap_vols = len(snap.get("volumes", []))
    print(f"snapshot.datasets     → {snap_ds}")
    print(f"snapshot.volumes      → {snap_vols}")
    print()

    drift = 0
    if admin_datasets and snap_ds < len(admin_datasets):
        diff = len(admin_datasets) - snap_ds
        print(f"FAIL: snapshot missing {diff} datasets vs admin page")
        drift += diff
    elif admin_datasets:
        print(f"OK: snapshot dataset count >= admin ({snap_ds} >= {len(admin_datasets)})")

    if admin_volumes and snap_vols < len(admin_volumes):
        diff = len(admin_volumes) - snap_vols
        print(f"FAIL: snapshot missing {diff} volumes vs admin page")
        drift += diff
    elif admin_volumes:
        print(f"OK: snapshot volume count >= admin ({snap_vols} >= {len(admin_volumes)})")

    if drift and admin_datasets:
        admin_ids = {d.get("id") for d in admin_datasets if d.get("id")}
        snap_ids = {d.get("id") for d in snap.get("datasets", [])}
        missing = admin_ids - snap_ids
        if missing:
            print(f"\nDataset IDs in admin but missing from snapshot ({len(missing)}):")
            for did in list(missing)[:10]:
                row = next((d for d in admin_datasets if d.get("id") == did), {})
                print(f"  {did}  {row.get('name', '?')}  owner={row.get('ownerUsernames') or row.get('ownerNames')}")
            if len(missing) > 10:
                print(f"  ... and {len(missing) - 10} more")

    return (1 if drift else 0) if strict else 0


if __name__ == "__main__":
    sys.exit(main())
