#!/usr/bin/env python3
"""check_interop — does each shipped APK serve the contract in INTEROP.md?

Reads intent-filter actions from APK manifests (no device, no SDK) and compares
them against interop-contract.json. Catches the silent case: an app that is
supposed to answer an intent and does not.

    python3 check_interop.py --contract interop-contract.json *.apk
    python3 check_interop.py --contract interop-contract.json --json apks/*.apk

Exit 0 clean · 1 a contract action has no server · 2 unreadable input
"""
import argparse
import json
import sys
from pathlib import Path

try:
    from loguru import logger
    logger.remove()                     # androguard logs through loguru
except Exception:
    pass

from androguard.core.apk import APK      # noqa: E402

NS = "{http://schemas.android.com/apk/res/android}"


def actions_of(apk_path: Path):
    apk = APK(str(apk_path))
    xml = apk.get_android_manifest_xml()
    acts = {el.get(NS + "name") for el in xml.iter("action") if el.get(NS + "name")}
    return apk.get_package(), apk.get_androidversion_name(), acts


def main() -> int:
    ap = argparse.ArgumentParser(description="check APKs against the interop contract")
    ap.add_argument("apks", nargs="+", type=Path)
    ap.add_argument("--contract", type=Path, required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    contract = json.loads(args.contract.read_text())
    shipped = {}
    for path in args.apks:
        if not path.exists():
            print(f"no such file: {path}", file=sys.stderr)
            return 2
        try:
            pkg, ver, acts = actions_of(path)
            shipped[pkg] = {"version": ver, "actions": sorted(acts)}
        except Exception as e:
            print(f"cannot read {path}: {e}", file=sys.stderr)
            return 2

    rows, missing = [], []
    for section in ("standard", "custom"):
        for action, spec in contract.get(section, {}).items():
            found = [p for p, d in shipped.items() if action in d["actions"]]
            optional = spec.startswith("any")
            ok = bool(found) or optional
            rows.append({"section": section, "action": action, "spec": spec,
                         "found_in": found, "ok": ok})
            if not ok:
                missing.append(action)

    if args.json:
        print(json.dumps({"packages": shipped, "contract": rows, "missing": missing}, indent=2))
    else:
        print(f"{len(shipped)} APKs read")
        for pkg, d in sorted(shipped.items()):
            print(f"  {pkg:26s} v{d['version']:6s} {len(d['actions'])} actions")
        print("\ncontract (from nijatva-core/INTEROP.md)")
        for r in rows:
            mark = "OK  " if r["ok"] else "MISS"
            found = ", ".join(r["found_in"]) or "NONE"
            print(f"  {mark} {r['action']:34s} spec={r['spec']:22s} found={found}")
        print(f"\nmissing: {len(missing)}"
              + ("" if not missing else "  → " + ", ".join(missing)))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
