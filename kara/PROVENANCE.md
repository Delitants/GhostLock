# Provenance

This directory adds the Amazon Fire TV `kara` target to the public GitHub fork
of [`R0rt1z2/GhostLock`](https://github.com/R0rt1z2/GhostLock). Keeping the
upstream Git history intact makes the relationship visible and avoids
presenting the complete tree as an unrelated original work.

The kara adaptation was developed from public GhostLock and Linux futex-PI
research, exact analysis of the `kara` Fire OS 7 kernel, and controlled testing
on an owned AFTKA device. It is not an Amazon firmware redistribution.

The live-tested correction uses `SCHED_BATCH` while preserving the waiter's
nice value. It rejects reclaim candidates below 18 of 24 matches and requires
the exact post-copy and kernel-pointer readbacks before continuing.

Upstream commit at the fork point:

```text
2cf26f9f27db5272fe2ed67a15d50b8dea83e4a6 Initial commit
```

The upstream repository contains no license file at that commit. This notice
does not invent or grant a license for upstream material. Contributors retain
their respective rights.
