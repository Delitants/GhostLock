# kara experimental newer-firmware test v1

This experimental release exists only to test whether the published kara
GhostLock chain still reaches temporary uid 0 on an incremental build newer
than `0035334210436`.

It retains exact gates for `kara/AFTKA`, Android API 28, kernel string
`4.14.87+`, ARM32 userspace, four or more configured CPUs, ADB-shell uid 2000,
SELinux enforcing, and the CEC standby guard. The caller must supply the exact
observed newer incremental build. Baseline, older, malformed, or mismatched
build values are rejected.

`--probe-newer BUILD` does not enter the reclaim or kernel race.

`--live-newer BUILD RUN-KARA-EXPERIMENTAL-NEWER-I-ACCEPT-WATCHDOG-REBOOT`
performs one explicitly unvalidated live attempt. It can watchdog-reboot or
destabilize the device. It deliberately skips OTA containment and does not
install applications, remove packages, flash partitions, unlock the
bootloader, or provide persistent root. A successful attempt leaves temporary
root and SELinux permissive until reboot.

This artifact is CI-built, not live-validated on every newer firmware. Report
the complete audit output, incremental build, artifact SHA-256, probe result,
and whether live mode returned root or rebooted. Never publish device serials,
account data, credentials, firmware images, or DRM material.
