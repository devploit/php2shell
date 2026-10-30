# Profile inventory

Generated from `profiles/*.json` by `tools/php2shell_inventory.py`.

| PHP | Build | zif_system | zval_ptr_dtor | htdata | stage1_n | forge | stage2_t | stage3 | RCE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 7.4.33 | php-7.4.33-bookworm-aarch64 | 0x309640 | 0x3f6024 | - | - | - | - | - | no |
| 7.4.33 | php-7.4.33-buster-amd64 | 0x335850 | 0x417d60 | - | 0 | 0 | 406 | - | no |
| 8.0.30 | php-8.0.30-bookworm-aarch64 | 0x31ef70 | 0x40ddb0 | - | - | - | - | - | no |
| 8.1.34 | php-8.1.34-bookworm-aarch64 | 0x341e08 | 0x42e7a0 | - | - | - | - | - | no |
| 8.1.34 | php-8.1.34-bullseye-amd64 | 0x36f470 | 0x457150 | - | 0 | 0 | 406 | - | no |
| 8.2.28 | php-8.2.28-bookworm-amd64 | 0x3928b0 | 0x47b630 | - | 0 | 0 | 406 | - | no |
| 8.2.34 | php-8.2.34-bookworm-aarch64 | 0x36ff48 | 0x4606c0 | - | 0 | 0 | 406 | - | no |
| 8.2.34 | php-8.2.34-bookworm-amd64 | 0x39b8a0 | 0x487650 | - | 0 | 0 | 406 | - | no |
| 8.3.0 | php-8.3.0-bookworm | 0x3771f0 | 0x467cf0 | - | 0 | 0 | 406 | - | no |
| 8.3.20 | php-8.3.20-bookworm-amd64 | 0x3a21d0 | 0x491bd0 | - | 892 | 63 | - | - | no |
| 8.3.33 | php-8.3.33-wordpress-mod_php | 0x377248 | 0x4737e0 | - | 815 | 63 | 406 | - | no |
| 8.3.35 | php-8.3.35-bookworm-aarch64 | 0x377428 | 0x46fcc0 | - | 841 | 63 | 406 | - | no |
| 8.3.35 | php-8.3.35-bookworm-amd64 | 0x3ac080 | 0x49ec50 | - | 841 | 63 | 406 | - | no |
| 8.4.2 | php-8.4.2-bookworm-amd64 | 0x4398b0 | 0x628ea0 | - | 0 | 0 | - | - | no |
| 8.4.5 | php-8.4.5-bookworm-amd64 | 0x43b660 | 0x62c420 | - | 892 | 63 | - | - | no |
| 8.4.6 | php-8.4.6-bookworm-amd64 | 0x43b940 | 0x62ca40 | - | 892 | 63 | 406 | - | no |
| 8.4.7 | php-8.4.7-bookworm-amd64 | 0x43b920 | 0x62cd60 | - | 892 | 63 | 406 | - | no |
| 8.4.8 | php-8.4.8-bookworm-amd64 | 0x43b940 | 0x62cd10 | - | 841 | 63 | 406 | - | no |
| 8.4.10 | php-8.4.10-bookworm-amd64 | 0x43b7d0 | 0x62cf70 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.11 | php-8.4.11-bookworm-amd64 | 0x446cb0 | 0x63d2e0 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.12 | php-8.4.12-bookworm-amd64 | 0x446cf0 | 0x63dc20 | - | 841 | 63 | 406 | - | no |
| 8.4.13 | php-8.4.13-bookworm-amd64 | 0x445bf0 | 0x63cbe0 | - | 841 | 63 | 406 | - | no |
| 8.4.14 | php-8.4.14-bookworm-amd64 | 0x445c30 | 0x63d020 | - | 841 | 63 | 406 | - | no |
| 8.4.15 | php-8.4.15-bookworm-amd64 | 0x445f70 | 0x63d420 | - | 841 | 63 | 406 | - | no |
| 8.4.16 | php-8.4.16-bookworm-amd64 | 0x446930 | 0x63de20 | - | 841 | 63 | 406 | - | no |
| 8.4.17 | php-8.4.17-bookworm-amd64 | 0x446cb0 | 0x63e520 | - | 841 | 63 | 406 | - | no |
| 8.4.18 | php-8.4.18-bookworm-amd64 | 0x446ff0 | 0x63eb20 | - | 841 | 63 | 406 | - | no |
| 8.4.19 | php-8.4.19-bookworm-amd64 | 0x4472f0 | 0x63efe0 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.20 | php-8.4.20-bookworm-amd64 | 0x447530 | 0x63f9e0 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.25 | php-8.4.25-bookworm-aarch64 | 0x42fa30 | 0x637ae0 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.25 | php-8.4.25-bookworm-amd64 | 0x464c70 | 0x65dc60 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.4.26 | php-8.4.26-bookworm-amd64 | 0x465370 | 0x65eb60 | 0x690d8 | 841 | 79 | 406 | carrier | yes |
| 8.4.26 | php-8.4.26-deb13-apxs2-amd64 | 0x3b19a0 | 0x584f00 | 0x6e0d8 | 892 | 79 | 442 | lab | yes |
| 8.5.0 | php-8.5.0-bookworm-amd64 | 0x56a420 | 0x781fe0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.0 | php-8.5.0-bookworm | 0x503510 | 0x731d80 | - | 841 | 63 | 406 | - | no |
| 8.5.1 | php-8.5.1-bookworm-amd64 | 0x56a9a0 | 0x7826a0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.2 | php-8.5.2-bookworm-amd64 | 0x56bca0 | 0x783de0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.3 | php-8.5.3-bookworm-amd64 | 0x56d1e0 | 0x785620 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.4 | php-8.5.4-bookworm-amd64 | 0x5705e0 | 0x788ba0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.5 | php-8.5.5-bookworm-amd64 | 0x570de0 | 0x789ae0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.6 | php-8.5.6-bookworm-amd64 | 0x595160 | 0x7ae6e0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.7 | php-8.5.7-bookworm-amd64 | 0x5960e0 | 0x7b0460 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.8 | php-8.5.8-bookworm-amd64 | 0x596620 | 0x7b0d60 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.9 | php-8.5.9-bookworm-amd64 | 0x598160 | 0x7b29a0 | 0x690d8 | 841 | 63 | 406 | vessel | yes |
| 8.5.10 | php-8.5.10-bookworm-aarch64 | 0x52e130 | 0x75d360 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.5.10 | php-8.5.10-bookworm-amd64 | 0x598d60 | 0x7b3860 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.5.11 | php-8.5.11-bookworm-aarch64 | 0x5314f0 | 0x761b80 | 0x690d8 | 841 | 63 | 406 | carrier | yes |
| 8.5.11 | php-8.5.11-bookworm-amd64 | 0x5996e0 | 0x7b47a0 | 0x690d8 | 841 | 63 | 406 | carrier | yes |

| 7.4.33 | php-7.4.33-fpm | 0x34c0a0 | 0x403be0 | - | - | - | - | - | yes |
| 8.0.30 | php-8.0.30-fpm | 0x359b20 | 0x4145e0 | - | - | - | - | - | yes |
| 8.1.33 | php-8.1.33-fpm | 0x367ca0 | 0x427120 | - | - | - | - | - | yes |
| 8.2.34 | php-8.2.34-fpm | 0x3769d0 | 0x439120 | - | - | - | - | - | yes |
| 8.3.35 | php-8.3.35-fpm | 0x37d5f0 | 0x446460 | - | - | - | - | - | yes |
| 8.4.0 | php-8.4.0-fpm | 0x384380 | 0x542dd0 | - | - | - | - | - | yes |
| 8.4.25 | php-8.4.25-fpm | 0x386460 | 0x549890 | - | - | - | - | - | yes |
| 8.4.26 | php-8.4.26-fpm | 0x386660 | 0x54a0d0 | - | - | - | - | - | yes |

**56 profiles, 30 with verified RCE** (48 Apache/mod_php + 8 PHP-FPM).



### RCE verified (official images, one worker, `display_errors=On`, `memory_limit=8M`)

- **8.4.26** — `php:8.4.26-apache` (bookworm). First verified build; used
  against the local 8.4.26 laboratory. Verified 3/3 manually and through the
  factory; forge length 79 differs from the other builds' 63. Fixed in 8.4.27.
- **8.4.25** — `php:8.4.25-apache` (amd64 and aarch64). Same layout family as
  8.4.26 (`htdata=0x690d8`, N=841). Fixed in 8.4.27.
- **8.4.20** — `php:8.4.20-apache`. Same layout family. Fixed in 8.4.27.
- **8.4.19, 8.4.11, 8.4.10** — `php:8.4.{10,11,19}-apache`. Same layout
  family (carrier stage 3, `htdata=0x690d8`, N=841). Fixed in 8.4.27.
- **8.5.10** — `php:8.5.10-apache` (amd64 and aarch64). Fixed in 8.5.12.
- **8.5.11** — `php:8.5.11-apache` (amd64 and aarch64). Fixed in 8.5.12.
- **8.5.0 – 8.5.9** — `php:8.5.{0..9}-apache`. **Vessel stage 3** (see
  below): the upstream carrier layout is unreachable on the early-8.5 heap,
  so S steers the dangling reference one page up onto B2's blob page and
  blob 1 embeds the reference pattern itself. The geometry calibrated on
  8.5.0/8.5.5 (under gdb and without it) was carried over to 8.5.1–8.5.9;
  the maintainer independently re-verified every early-8.5 row, 8.5.10 amd64
  and 8.5.11 aarch64 on 2026-10-30. Fixed in 8.5.12.

### Leaks reproduced, stage 3 misses

- **8.4.13, 8.4.8** — `php:8.4.{8,13}-apache`. Stages 1-2 calibrated;
  the stage-3 sweep ran out of attempts before a carrier placement was
  found. Fixed in 8.4.27.
- **8.3.35** — `php:8.3.35-apache` (amd64 and aarch64). Same shape: both leaks
  reproduce, the carrier stage 3 does not place the fake reference. A vessel
  adaptation was measured and does not fit this heap: the dangling reference
  lands ~0x13 pages below the blob pages and the early-8.5 geometry cannot
  reach it; a bin/graft-offset generalization is still needed. Fixed in
  8.3.36.
- **8.3.33** — `wordpress:7.1.1-apache` (PHP 8.3.33, mod_php). Stages 1-2
  reproduced; stage 3 not calibrated. Fixed in 8.3.36.

### Leak stage to re-run (cookie decode fix)

- **8.4.18 – 8.4.14, 8.4.12, 8.4.7, 8.4.6** — these sweeps recorded
  "heap/libphp leak not reproduced" before the `Set-Cookie` `'+'` decoding bug
  was fixed (`docs/upstream-changes.md`, section 3). 8.4.6/8.4.7 also hint at
  the older 8.3.x-era stage-1 geometry (N=892). The offsets are extracted and
  the labs rebuild in minutes; the profiles stay `rce=false` until the leaks
  and stage 3 are actually reproduced. 8.5.3 (listed here previously) was
  re-run with the fix and is now vessel-verified; the no-leak builds (8.4.2,
  8.4.5) and the stage-3 misses (8.4.8, 8.4.13) are queued for the same
  re-run.

### Stage-1 leak only

- **8.3.20, 8.4.5** — `php:8.3.20-apache`, `php:8.4.5-apache`. The stage-1
  stale block is taken by **v0892** (not v0841) and the chunk base leaks, but
  the stage-2 sweep — even with `--full-search` — finds no libphp pointer in
  the heap. The leak shape moved between 8.3.20→8.3.35 and 8.4.5→8.4.10.

### Stage 1 not reproduced

- **8.4.2, 8.2.34, 8.2.28, 8.1.34, 7.4.33** — official images
  (`php:8.4.2-apache`, `php:8.2.34-apache`, `php:8.2.28-apache`,
  `php:8.1-apache` on bullseye, `php:7.4-apache` on buster). The stage-1 probe
  does not reveal the stale-block index at all: the OOM-bailout UAF does not
  shape the heap the way 8.4.10+ does. Matches the author's aarch64 results
  (7.4.33, 8.0.30, 8.1.34, 8.2.34 all "leak shape differs"). 8.1 and 7.4 are
  EOL and will never be fixed; 8.2/8.4 are fixed in 8.2.35 / 8.4.27.

### The vessel stage 3 (early-8.5 heap layout)

On the early-8.5 builds (`php:8.5.0` – `php:8.5.9`, all vessel-verified) the
request machinery carves the 32-byte
(bin-3) page at chunk offset 0x68 before any of our multipart fields are
parsed, while B2's 15 fake-HashTable blobs (167-byte values, bin-13/192 B)
start one page later at 0x69. The upstream carrier string can therefore never
land on the dangling `PS(http_session_vars)` reference — it sits on 0x68, the
blobs on 0x69. `tools/php2shell_vessel.py` realigns the pages instead:

1. **S (prime)** grows an "early" field with a 160-byte value (one whole
   bin-13 page), pushing S's first bin-3 carve — the page holding the dangling
   reference — one page up: `R0(m) = 0x69000 + 0x160 + 0x80*m`, m = 3 with
   three `7:7` pads → `R0 = 0x692E0`.
2. **B2** drops the carrier string and every short-named field, so it carves
   no bin-3 slot of its own; its blob run starts at page 0x69 with blob 0's
   data at `chunk+0x690D8` and blob 1 — the *vessel* — at `chunk+0x69258`,
   whose bytes at `+0x88` sit exactly at `R0`.

The vessel is byte-identical to the canonical fake-HashTable blob except for
a 15-byte graft at offset 0x88 (over the fake cmd string's `h`/`len` fields,
both unread on the fire path): the reference pattern `gc(rc=1, IS_REFERENCE)`
plus the low 7 bytes of `htdata`, a NUL, and `val.u1 type_info = 0x0307`
(`IS_REFERENCE`, refcounted). At session close the destructor reads the
vessel as the stale reference, DELREFs `val.value` (blob 0's fake HashTable)
and fires `zif_system` with blob 0's command string.

Profiles store the vessel geometry in `stages`: `stage3_mode: "vessel"`,
`stage3_early`, `stage3_blobs`, `stage3_vessel_index` plus the usual pads.
The dispatcher and calibrator route to the vessel chain automatically
(`--stage3-mode vessel` on `php2shell_calibrate.py`).

### PHP-FPM profiles

The eight `*-fpm` profiles are **contributor-reported, not independently
confirmed** by the maintainer and are specific to their compilation
environment (the compile-time prefix shifts the heap). Re-run `calibrate` on
the host that will run the exploit; `no-oracle` leaks the chunk/PIE bases over
HTTP and does not need `/proc/<pid>/mem`.

### PHP 8.4.26 deb13/apxs2

The Debian 13/apxs2 profile is a **contributor-reported, not independently
confirmed** source build, not an official image. It needs a third stage-3
layout; the stage-1/2 offsets and the instance-dependent stage-3 behaviour are
documented in its profile and in
`docs/calibration-logs/8.4.26-deb13-apxs2.md`.

## Symbol offsets for more builds

`docs/offset-inventory.md` (generated by `tools/php2shell_offsets.py`) lists
the `zif_system` / `zval_ptr_dtor` offsets for every official image that was
inspected, cross-referenced with the heap-calibration state above — including
the EOL branches (7.4, 8.0, 8.1) where offsets are known but the stage-1 leak
does not reproduce.

## Coverage vs the catalog

`catalog/vulnerable.json` lists every branch from the advisory matrix
(5.4 → 8.5, plus 8.6 RC). The profiles above cover the representative official
images that were actually run. A version is exploitable only when a verified
profile exists for its exact build; the dispatcher refuses to guess.

To add a build, append it to `BUILDS` in `tools/php2shell_matrix.py` and run
the factory. Architecture matters: an `x86_64` image produces its own offsets
and heap layout, and so does each distro base (bookworm/bullseye/buster).
