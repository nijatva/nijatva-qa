# nijatva-qa — testing that does not need a phone

A Nijatva app should be checked on every PR without a developer installing anything.
This repository holds the checks that can run in CI, and the short list that genuinely
cannot.

## The four tiers

| Tier | Runs where | Cost | Catches |
|---|---|---|---|
| **0 — source** | CI, seconds | free | banned dependencies, binaries in git, permission allow-list in the manifest, `targetSdk`, exported components, string parity |
| **1 — APK** | CI, ~30 s per app | free | what actually shipped: package, versionCode, minSdk, permissions, banned SDKs in the dex, signature presence, size, sha256, **and a match against `index-v1.json`** |
| **2 — JVM tests** | CI, no emulator | ~1–2 min | app logic and Compose/View screens via Robolectric + Compose UI test. Lives in each app, scaffolded by `nijatva-templates` |
| **3 — device** | a real phone | minutes of a human | launcher mask, Android 13 themed icons, permission dialogs, SMS/call roles, camera quality, battery, install **and update** from the index |

Tiers 0–1 are here. Tier 2 belongs in the template. Tier 3 is a checklist and always will be —
pretending otherwise is how a privacy claim dies.

## Usage

```bash
pip install -r requirements-qa.txt

# inspect a built APK against the policy for its app class
python3 njqa.py apk app-release.apk --class media

# also verify it against the suite index: sha256, signer, versionCode, minSdk
python3 njqa.py apk app-release.apk --class media --index index-v1.json

# machine-readable
python3 njqa.py apk app-release.apk --class utility --json
```

Exit codes: `0` clean · `1` policy violation · `2` unreadable APK.

App classes and their allow-lists come from `SECURITY-POLICY.md` §2.4:
`utility` · `media` · `phone` · `browser` · `vault`.

## What it already proved

Run against the real Photo Editor 1.6.0 release:

```
com.nijatva.photo.editor  1.6.0 (code 7)  minSdk 26 · targetSdk 35  6.5 MB
sha256 ceccb4f247fccfedd7a76b7f20607249…
permissions (3): READ_EXTERNAL_STORAGE, READ_MEDIA_IMAGES, WRITE_EXTERNAL_STORAGE
banned SDKs: none
certificate: 32ef7fb704c1ad0666a0177dd69d8116…
index check (index-v1.json): matches
PASS — nothing violates policy
```

Both the sha256 and the signing certificate match the index entry. That was listed as
**UNVERIFIED** in the audit — it is now verified, without a phone and without the Android SDK.

## What it cannot do

- Run the app. No runtime behaviour, no crashes, no layout at runtime.
- See a launcher mask or themed icons — those need a device.
- Judge camera quality, battery, or SMS/telephony behaviour.
- Decide whether a permission is *needed* — only whether it is allowed.

## Adding it to an app repo

```yaml
jobs:
  build: { ... }

  qa:
    needs: build
    uses: nijatva/nijatva-qa/.github/workflows/njqa.yml@main
    with:
      app-class: media
      strict-index: true      # once the app is indexed
```

The report lands as an artifact called `njqa-report`.
