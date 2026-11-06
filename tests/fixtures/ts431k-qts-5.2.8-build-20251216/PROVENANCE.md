# TS-431K / QTS 5.2.8 fixture provenance

- Captured from the owner's TS-431K on 2026-11-03 through read-only QTS HTTPS CGI calls.
- Firmware response: QTS 5.2.8 build 20251216; internal model alias `TS-X41`.
- Authentication used password plus TOTP. Password, TOTP, SID, and tokens were never written to this directory.
- Hostname, serial numbers, interface addresses, netmasks, MAC addresses, and DNS values were redacted before persistence.
- The three XML files passed a second pattern scan for IP, MAC, SID, and qtoken material before inclusion.
- File Station root pages were recaptured through the read-only HTTPS web path on 2026-11-06: 5 visible shares and 24 first-page entries. Share names, paths, file names, and folder names were replaced with non-identifying placeholders; no name hash is published. Only incident-significant `.7z`, `.deadbolt`, and `!!!READ_ME.txt` semantics may survive redaction.
- The File Station fixture passed structural validation plus manual review of 29 name fields and second scans for private/Tailscale IPs, MACs, SID/qtoken material, usernames, and unredacted entry names. It contains no credentials or session data.
- Offline replay is intentionally `partial`: capture depth is zero, so 22 observed child folders have no captured child page. No indicator was found, but this cannot be interpreted as clean.
- This fixture proves observed response shapes, not current or future device health.
