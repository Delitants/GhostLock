# kara PS7713/5443 temporary root v1

This release targets only `kara/AFTKA`, Android API 28, incremental build
`0035334210436`, kernel `4.14.87+`, and 32-bit ARM userspace.

Run `--probe` first. Live mode requires the exact confirmation token documented
in `kara/README.md`. The race can watchdog-reboot the device. Root is temporary
and disappears after reboot. No partition is flashed or modified.

The asset is built from the source in this release. GitHub publishes its
SHA-256 digest in release metadata; verify that digest before execution.
