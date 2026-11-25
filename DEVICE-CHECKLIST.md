# Device checklist — tier 3, the part that needs a human

Run before an app is indexed. Five minutes on a real phone. Nothing here can be automated.

## Install and update
- [ ] Installs from the index URL on a clean device
- [ ] Updates over the previous version **without uninstall**
- [ ] The installed signer matches the index fingerprint (Settings → Apps → App info)

## Launcher
- [ ] Icon is not clipped by the launcher mask (circle, squircle, teardrop)
- [ ] Themed / monochrome icon renders on Android 13+ when themed icons are on
- [ ] Label is not truncated in the drawer

## First run
- [ ] Privacy banner shows the truth: SAF state and whether INTERNET is held
- [ ] Revoking folder access shows an empty state, not a crash
- [ ] Every permission dialog appears only when the feature is first used
- [ ] Back button exits cleanly; no permission is requested on launch

## The app's own role
- [ ] Dialer / Contacts / Messages / Calendar: holds the default-app role and works after reboot
- [ ] Camera: capture, save, and the saved file appears in Gallery
- [ ] Files: SAF folder pick, persisted across restart
- [ ] Keyboard: no INTERNET permission in App info, and typing works in another app

## Honesty
- [ ] Everything the store listing claims is visible in the app
- [ ] Nothing the listing claims is missing (no "coming soon" in a shipped build)
