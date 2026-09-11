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

Do not run this on `mantis`, `mantra`, `karat`, another build, or another
kernel. Related MediaTek chips are not compatibility evidence.

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

The output is `kara/out/kara-ghostlock-PS7713-5443.arm`.

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
