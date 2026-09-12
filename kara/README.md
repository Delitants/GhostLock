# GhostLock for Fire TV Stick 4K Max 1st Gen (`kara`)

This directory contains the complete temporary-root exploit that was tested on
one exact Amazon Fire TV Stick 4K Max 1st Generation firmware build. It is for
device owners and security researchers who understand that a kernel race can
crash or reboot the target.

## Exact supported target

All of these must match:

| Property | Required value |
| --- | --- |
| Device | `kara` |
| Model | `AFTKA` |
| Fire OS base | Fire OS 7 / Android 9 / API 28 |
| Incremental build | `0035334210436` (`PS7713/5443`) |
| Kernel | `4.14.87+` |
| Userspace | 32-bit ARM (`armeabi-v7a`) |
| CPU count | 4 |

Normal `--probe` and `--live` modes remain limited to this exact build. Never
run any mode on `mantis`, `mantra`, `karat`, or another kernel. The separately
labeled experimental modes below accept only a newer incremental build on the
same otherwise-exact target. Related MediaTek chips are not compatibility
evidence.

## What it does

The exploit uses a Fire OS 7/Linux 4.14 futex-PI stale-waiter path, controlled
reclaim, and exact build-specific kernel addresses to obtain temporary UID 0.
It starts a local command daemon. Root disappears after reboot.

It does not unlock the bootloader, install Magisk, flash a partition, modify
the read-only system image, or install a custom ROM.

## Build

On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential gcc-arm-linux-gnueabihf file
./kara/build.sh
```

The current branch output is
`kara/out/kara-ghostlock-experimental-newer.arm`. The immutable
`kara-PS7713-5443-v1` release remains the live-tested exact-build artifact.

## Safe probe

The probe validates identity, kernel, ABI, CPU count, ADB-shell UID, SELinux,
futex-PI support, PTY behavior, and the exact TCP multicast copy result. It does
not enter the reclaim or vulnerable race.

```sh
adb push kara/out/kara-ghostlock-PS7713-5443.arm /data/local/tmp/kara-ghostlock
adb shell chmod 700 /data/local/tmp/kara-ghostlock
adb shell /data/local/tmp/kara-ghostlock --probe
```

Continue only when it prints `V2 SAFE PROBE PASS`.

## Live temporary root

Warning: the live step is probabilistic and can trigger a watchdog reboot.
Ensure the exact firmware matches and keep the device on stable power.

```sh
adb shell /data/local/tmp/kara-ghostlock \
  --live RUN-KARA-PS7713-GHOSTLOCK-V2
adb shell /data/local/tmp/kara-ghostlock --cmd id
```

The second command must report UID 0. Do not rerun the live mode when a working
daemon already exists.

## Experimental newer-firmware test

The experimental commands accept only a decimal incremental build strictly
newer than `0035334210436`. Device, model, API, `4.14.87+` kernel string, ARM32
machine, CPU count, shell UID, SELinux, and CEC gates remain exact. A matching
kernel string does not prove that its hard-coded addresses are unchanged.

Safe probe only:

```sh
adb shell /data/local/tmp/kara-ghostlock \
  --probe-newer THE_EXACT_NEWER_INCREMENTAL_BUILD
```

One live root attempt:

```sh
adb shell /data/local/tmp/kara-ghostlock \
  --live-newer THE_EXACT_NEWER_INCREMENTAL_BUILD \
  RUN-KARA-EXPERIMENTAL-NEWER-I-ACCEPT-WATCHDOG-REBOOT
```

Live experimental mode can watchdog-reboot or destabilize the device. It does
not contain OTA, install apps, remove packages, or flash anything. On success,
SELinux is permissive and temporary root remains until reboot. Use the
standalone controller for build validation, reversible CEC handling, logging,
and commands that cannot be confused with the normal exact-build workflow.

For the safer end-to-end launcher/debloat workflow, use the public
[`firetv-kara-standalone`](https://github.com/Delitants/firetv-kara-standalone)
controller. It authenticates the release, runs the safe probe first, and
verifies each stage.

## Evidence and provenance

The live-tested private build had SHA-256:

```text
a42185d743ee1d4c9c46c1e35f5fa0a40f5e9a7f81450308c3eab297677847d5
```

A rebuild may differ when the compiler version changes. Release notes record
the compiler and the hash of the published artifact. See
[`PROVENANCE.md`](PROVENANCE.md) for attribution and licensing boundaries.
