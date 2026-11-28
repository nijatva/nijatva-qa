#!/usr/bin/env python3
"""njqa — no-device QA for a Nijatva APK.

Checks an APK against the suite policy without an Android SDK, emulator or phone.
Everything it reports is read from the APK itself; nothing is guessed.

    python3 njqa.py apk path/to/app.apk --class utility
    python3 njqa.py apk app.apk --class browser --json

Exit codes: 0 clean · 1 policy violation · 2 unreadable APK
"""
import argparse
import hashlib
import logging
import json
import re
import sys
import zipfile
from pathlib import Path

BANNED_GROUPS = {
    "com/google/firebase": "Firebase",
    "com/google/android/gms": "Play Services",
    "com/google/android/play": "Play Core",
    "com/google/android/ads": "Mobile Ads",
    "com/google/android/tagmanager": "Tag Manager",
    "com/crashlytics": "Crashlytics",
    "com/google/ads/mediation": "Ads mediation",
    "com/amplitude": "Amplitude",
    "io/sentry": "Sentry (self-hosted only, needs a decision)",
    "com/facebook/ads": "Facebook Ads",
}

# App classes from SECURITY-POLICY.md §2.4
ALLOWED = {
    "utility":  {"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
                 "android.permission.POST_NOTIFICATIONS", "android.permission.VIBRATE"},
    "media":    {"android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO",
                 "android.permission.READ_MEDIA_AUDIO", "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
                 "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
                 "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
                 "android.permission.POST_NOTIFICATIONS"},
    "phone":    {"android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                 "android.permission.CALL_PHONE", "android.permission.READ_PHONE_STATE",
                 "android.permission.READ_CALL_LOG", "android.permission.READ_SMS",
                 "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
                 "android.permission.POST_NOTIFICATIONS", "android.permission.VIBRATE",
                 "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"},
    "browser":  {"android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
                 "android.permission.POST_NOTIFICATIONS",
                 "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"},
    "vault":    {"android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT",
                 "android.permission.QUERY_ALL_PACKAGES", "android.permission.POST_NOTIFICATIONS"},
}
NEVER = {
    "android.permission.MANAGE_EXTERNAL_STORAGE": "banned: use SAF or the Photo Picker",
    "android.permission.SYSTEM_ALERT_WINDOW": "banned: overlay permission",
    "android.permission.REQUEST_INSTALL_PACKAGES": "allowed only for the store client",
    "android.permission.ACCESS_FINE_LOCATION": "no location in this suite; manual city entry instead",
    "android.permission.ACCESS_COARSE_LOCATION": "no location in this suite",
}
MIN_TARGET_SDK = 34


logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.ERROR)


def scan_dex(apk: Path):
    """Banned groups live in the dex string pool as plain UTF-8 — no full parse needed."""
    hits = {}
    with zipfile.ZipFile(apk) as z:
        for name in z.namelist():
            if not name.endswith(".dex"):
                continue
            blob = z.read(name)
            for needle, label in BANNED_GROUPS.items():
                if needle.encode() in blob:
                    hits.setdefault(label, []).append(name)
    return hits


def against_index(report: dict, index_path: Path):
    """Compare the APK against its entry in index-v1.json — the check the audit
    prompt called UNVERIFIED: hash, certificate and versionCode."""
    index = json.loads(index_path.read_text())
    entries = index.get("packages", {}).get(report["package"], [])
    if not entries:
        return [f"package {report['package']} is not in the index"]
    match = next((e for e in entries if str(e.get("versionCode")) == str(report["versionCode"])), None)
    if not match:
        have = ", ".join(str(e.get("versionName")) for e in entries)
        return [f"versionCode {report['versionCode']} not in the index (index has {have})"]
    problems = []
    if match.get("hash", "").lower() != report["sha256"].lower():
        problems.append(f"sha256 mismatch: index {match.get('hash','')[:16]}… vs apk {report['sha256'][:16]}…")
    idx_sig = (match.get("sig") or "").lower()
    if idx_sig and report.get("cert_sha256") and idx_sig != report["cert_sha256"].lower():
        problems.append(f"signer mismatch: index {idx_sig[:16]}… vs apk {report['cert_sha256'][:16]}…")
    if str(match.get("minSdkVersion")) != str(report["minSdk"]):
        problems.append(f"minSdk mismatch: index {match.get('minSdkVersion')} vs apk {report['minSdk']}")
    return problems


def check(apk: Path, app_class: str):
    from androguard.core.apk import APK  # imported late so --help works without it

    a = APK(str(apk))
    perms = sorted(p for p in a.get_permissions() if not p.startswith(f"{a.get_package()}."))
    allowed = ALLOWED[app_class]

    problems, warnings = [], []
    for p in perms:
        if p in NEVER:
            problems.append(f"permission {p.split('.')[-1]}: {NEVER[p]}")
        elif p not in allowed:
            # SECURITY-POLICY §2.4 is an allow-list, not advice: a permission outside it
            # fails the build, otherwise the policy is decorative.
            problems.append(f"permission {p.split('.')[-1]} is not in the {app_class} allow-list")

    target = int(a.get_target_sdk_version() or 0)
    if target < MIN_TARGET_SDK:
        problems.append(f"targetSdk {target} < {MIN_TARGET_SDK} (index policy)")

    if a.is_debuggable() if hasattr(a, "is_debuggable") else False:
        problems.append("android:debuggable is true — this is not a release build")

    banned = scan_dex(apk)
    for label, dexes in banned.items():
        problems.append(f"banned SDK present: {label} (in {', '.join(dexes)})")

    exported = []
    try:
        for tag in ("activity", "service", "receiver", "provider"):
            for item in a.get_all_attribute_value(tag, "name", format_value=True) or []:
                exported.append(item)
    except Exception:
        pass

    cert = None
    try:
        certs = a.get_certificates()
        if certs:
            cert = certs[0].sha256.hex() if hasattr(certs[0], "sha256") else None
    except Exception:
        pass
    if not cert:
        with zipfile.ZipFile(apk) as z:
            sigs = [n for n in z.namelist() if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n)]
        if not sigs:
            problems.append("no v1 signature block in META-INF — APK may be unsigned")

    report = {
        "apk": str(apk),
        "size_bytes": apk.stat().st_size,
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "package": a.get_package(),
        "versionName": a.get_androidversion_name(),
        "versionCode": a.get_androidversion_code(),
        "minSdk": a.get_min_sdk_version(),
        "targetSdk": target,
        "app_class": app_class,
        "permissions": perms,
        "banned_sdks": banned,
        "cert_sha256": cert,
        "problems": problems,
        "warnings": warnings,
    }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description="no-device QA for a Nijatva APK")
    ap.add_argument("command", choices=["apk"])
    ap.add_argument("path", type=Path)
    ap.add_argument("--class", dest="app_class", default="utility", choices=sorted(ALLOWED))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--index", type=Path, help="path to index-v1.json to verify against")
    args = ap.parse_args()

    if not args.path.exists():
        print(f"no such file: {args.path}", file=sys.stderr)
        return 2
    try:
        r = check(args.path, args.app_class)
    except Exception as e:
        print(f"cannot read APK: {e}", file=sys.stderr)
        return 2

    index_problems = []
    if args.index:
        if not args.index.exists():
            print(f"no such index: {args.index}", file=sys.stderr)
            return 2
        index_problems = against_index(r, args.index)
        r["index_problems"] = index_problems
        r["problems"] += index_problems

    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"\n{r['package']}  {r['versionName']} (code {r['versionCode']})  "
              f"minSdk {r['minSdk']} · targetSdk {r['targetSdk']}  "
              f"{r['size_bytes']/1e6:.1f} MB")
        print(f"sha256 {r['sha256'][:32]}…   class={r['app_class']}")
        print(f"\npermissions ({len(r['permissions'])}):")
        for p in r["permissions"]:
            print(f"   {p.split('.')[-1]}")
        print(f"\nbanned SDKs: {', '.join(r['banned_sdks']) if r['banned_sdks'] else 'none'}")
        print(f"certificate: {r['cert_sha256'][:32] + '…' if r['cert_sha256'] else 'not readable'}")
        if args.index:
            print(f"\nindex check ({args.index.name}): "
                  f"{'matches' if not index_problems else str(len(index_problems)) + ' mismatch(es)'}")
        for w in r["warnings"]:
            print(f"  WARN  {w}")
        for p in r["problems"]:
            print(f"  FAIL  {p}")
        print(f"\n{'PASS — nothing violates policy' if not r['problems'] else str(len(r['problems'])) + ' policy violation(s)'}")
    return 1 if r["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
