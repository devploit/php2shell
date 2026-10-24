# The PHP-FPM chain

The upstream Apache chain (CVE-2026-109618 / CVE-2026-109619, stages 1-3)
needs a pre-RINIT out-of-memory bailout. Under PHP-FPM that bailout is fatal:
`fpm_main.c` treats it as `FPM_EXIT_SOFTWARE` and kills the worker, so the
Apache progress-cache UAF never survives to the next request.

The FPM-viable primitive is the **stale `BG(unserialize)` state** — the same
CVEs through a different window. Verified end-to-end on PHP 8.2.34, 8.3.35,
8.4.0, 8.4.25 and 8.4.26 (amd64, Debian-style user-prefix builds) in the local
laboratory; `cmd_patchcheck` confirms 8.4.27 leaves `level=0` (clean). PHP
<= 7.x cannot use this struct-freeing chain, but the same
`session.upload_progress` surface gives a pre-auth **session-file plant**
(`poison`), covered below.

> **Authorized testing only.** The chain is disruptive: it sends multi-megabyte
> bodies, triggers out-of-memory conditions and kills FPM workers. Use it only
> against systems you own or have written permission to test.

## Why FPM differs from mod_php

In mod_php the Apache chain reuses per-request heap state across HTTP
requests handled by the same prefork child. FPM's worker lifecycle differs in
two ways:

1. A pre-RINIT OOM kills the whole worker (`fpm_main.c:1871` →
   `FPM_EXIT_SOFTWARE`), so the progress-cache UAF cannot be consumed later.
2. `PHP_RINIT(basic)` runs `memset(&BG, 0, ...)` on **every** request that
   reaches RINIT, wiping `BG(unserialize)` — the stale window is exactly one
   request wide.

The chain therefore has to *re-claim* the stale struct inside the request that
still sees it, before RINIT runs. The rfc1867 multipart upload handler gives
exactly that window.

## Affected versions

`tools/php2shell_fpm_versions.py` is the single source of truth for the
affected-version matrix. Every release before the branch fix is vulnerable:

| Branch | Vulnerable | Fixed | This repository |
| --- | --- | --- | --- |
| 8.4 | 8.4.0 – 8.4.26 | 8.4.27 | **verified profiles (8.4.0, 8.4.25, 8.4.26)** |
| 8.3 | 8.3.0 – 8.3.35 | 8.3.36 | **verified profile (8.3.35)** |
| 8.2 | 8.2.0 – 8.2.34 | 8.2.35 | **verified profile (8.2.34)** |
| 7.4 / 7.2 (and older) | every release | **never patched** | session-file plant (`poison`); no struct-freeing chain |

(PHP 8.5 is fixed in 8.5.12 and is intentionally out of scope here.)
`is_vulnerable()`, `fixed_in()`, `affected_versions()` and `source_is_fixed()`
(which classifies a tarball by the presence of the upstream fix marker rather
than a version string) all resolve through that registry, and
`has_session_cancel_decode()` decides whether the struct-freeing chain can
apply to a build at all (it needs PHP 8.0+).

## The chain

All offsets are per build and live in `profiles/8.4.26-fpm.json`
(`fpm.basic_globals`, `fpm.bg_unserialize_*`, `libphp.zif_system` /
`libphp.zval_ptr_dtor`). Two structures matter (verified against the 8.4.26
sources):

- `BG(unserialize)` in `php_basic_globals`
  (`ext/standard/basic_functions.h`) is
  `{ struct php_unserialize_data *data; unsigned level; }` — `data` at
  `basic_globals + 872`, `level` at `+880` (the `fpm.bg_unserialize_*`
  profile fields).
- `struct php_unserialize_data` (`ext/standard/var_unserializer.re`) is
  `{ var_entries *last; var_dtor_entries *first_dtor, *last_dtor;
  HashTable *allowed_classes, *ref_props; zend_long cur_depth, max_depth;
  var_entries entries; }` with
  `var_entries = { zend_long used_slots; void *next; zval *data[1018]; }` —
  56 + 8160 = **8216 bytes** (`fpm.struct_size`). The forged `R:2` target
  lands in `entries.data[]`; the reclaim buffer overwrites the whole chunk.

### 1. Arm — post-RINIT OOM leaves `BG(unserialize)` stale

`producer` sends `GET app.php` with a cookie naming a large session
(`~4 MB`, built once by the builder pool with `cleanup=Off`).
`session_start()` decodes the session **post-RINIT**; the decode pushes
`level` to 1 and allocates the 8216-byte struct at `d`; the allocation storm
then hits `memory_limit=8M` and bails out. `zend_try` in `php_execute_script`
catches the bailout, the worker survives, and `BG(unserialize)` keeps
`{level=1, data=d}` pointing at the teardown-freed struct.

At this point `d` is dangling: the only live reference in the engine is the
stale `BG` pair. Every subsequent request that reaches RINIT memsets `BG`, so
the consumer must arrive *before* its own RINIT.

### 2. Locate and reclaim (oracle lab mode)

`Oracle` (local lab only) reads `/proc/<pid>/mem` at
`basic_globals + 872/+880` to get `d` and `level`, plus the worker's PIE base
for the FNM offsets. Two heap slots recycle the struct
(`0x7f07be280000` / `0x7f07be281000` on the reference build); a mismatch
self-corrects on retry (`cmd_endgame` verifies probe-arm `d` equals
consume-arm `d` and retries up to 4×, rebuilding the oracle after a dead
worker).

The consume request is a multipart POST (pre-RINIT): the rfc1867 handler runs
inside `php_hash_environment()`, i.e. **before** `zend_activate_modules()`
where `PHP_RINIT(basic)` would memset `BG`. `php_session_initialize()` →
`php_session_decode()` → `php_var_unserialize_init()` **reuses** `d`. A 4 MB
body (the `reclaim` part) reclaims `d`'s slot; the controlled content plants a
forged `var_entries` at the exact offsets of the original struct.

The 4 MB arm phase is posted to a **second endpoint** (the builder pool,
`memory_limit=64M`, `cleanup=Off`): posting it to the 8M chain pool would kill
the consumer worker before the fire.

### 2b. HTTP-only endgame (no `/proc/<pid>/mem`)

`no-oracle` removes the memory oracle from the exploit path. It needs two
absolute values that are stable for the lifetime of the FPM master (the
workers are forked from it): the Zend-MM chunk base and the php-fpm PIE base.
By default the client leaks both over HTTP; `--chunk`/`--pie` override them,
and local `/proc/<pid>/maps` is only a fallback (it never opens
`/proc/<pid>/mem`):

```sh
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 \
  --version 8.4.26 --command 'id>out/p1' --proof-file out/p1 \
  no-oracle
```

The 16384-byte reclaim covers both struct slots: `d = chunk + 0x81000`
with control offset `0xfe8`, and `d = chunk + 0x82000` with `0x1fe8`
(`fpm.no_oracle.candidates` in the profile). A throw-away pads+big request
normalizes the heap after the first arm, so the first candidate usually wins;
a mismatch crashes the worker and the next candidate is tried. The worker
still dies on success (HTTP 502) and the proof is the command's output file.

The HTTP leak reuses the stale-session string: the builder's `bigvar.php`
stores `k0..k3` before a 4 MB tail, a reclaimed 16 KB big field plants a forged
`zend_string` header over the freed k1 slot, its length spans the stale zval
array (chunk pointer) and the `execute_ex` handler table inside the chunk (PIE
pointer), and the app reflects the bytes. The read is retried because the
worker can abort after answering; `leak` prints the two bases.
Absolute bases change when the master restarts, so the leak is repeated per
run. This mode removes both the runtime `/proc/<pid>/mem` dependency and the
need to know the ASLR bases in advance.

### 3. Forge — reference → fake array → `zif_system`

The reclaimed buffer carries, at the offsets `php_var_unserialize` will read:

- a fake `zend_reference` (`IS_REFERENCE`, refcount 0) whose `val.type` is
  `IS_ARRAY` and whose `gc`/`val` buffers point into the same chunk;
- a fake `zend_array` (`zend_array` layout: `arData`, `nNumUsed`, `flags =
  HASH_FLAG_STATIC_KEYS (0x10)`, `pDestructor = zif_system`) with one bucket;
- a fake `zend_execute_data` frame (80 B) whose arg 1 (`execute_data + 0x50`)
  is a fake `zend_string` holding the command (≤ 87 bytes, no NUL);
- the command bytes themselves and a NUL terminator.

The consume request's session contains `r|R:2`; the forged buffer supplies the
`R:2` target, so `r` becomes an `IS_REFERENCE` to the fake array.

### 4. Fire — session shutdown calls `zif_system`

`consume` attaches `r`; the worker's session shutdown path does the rest:

1. `php_session_flush(1)` saves the session — plain arrays are never
   addref'd, and `php_add_var_hash`'s temporary ADDREF is balanced by the
   serialize var_hash destroy, so the save is safe;
2. `php_rshutdown_session_globals` → `zval_ptr_dtor(&PS(http_session_vars))`
   destroys `r` → DELREF the reference 1→0 → `zend_reference_destroy` →
   `i_zval_ptr_dtor(&ref->val)`;
3. the fake array's DELREF 1→0 → `zend_array_destroy` →
   `pDestructor != ZVAL_PTR_DTOR` → `zend_hash_destroy` (flags 0x10, no
   `HASH_FLAG_HAS_EMPTY_IND`, plain `pDestructor(&p->val)` loop);
4. `zif_system(frame)` runs with `RDI` = the execute frame; the fake
   `zend_string` at arg 1 is the command. `popen` executes it; the RETVAL
   write to garbage `RSI` and an interior `efree` abort the worker —
   acceptable: the proof is on disk and FPM respawns the worker.

`php_var_unserialize_destroy` is skipped at consume (level 2→1) and 8.4.26
has no RSHUTDOWN cleanup, so the fake dtor chunk at `d + 0x400` is never
walked during the request. The next request that reaches RINIT memsets `BG`
and re-arms from scratch — each `endgame` run is self-contained.

## Proof

The default command is `id>out/p1` (FPM pool cwd is `lab/fpm/webroot`, so
`out/` is served statically by nginx as `/out/p1`). The consumer request
exits **HTTP 502** (worker death after fire) — that is expected. Fetch the
proof separately:

```sh
curl http://127.0.0.1:8110/out/p1
# uid=1000(...) gid=1000(...) groups=...
```

On the reference run the proof was `uid=1000` (the unprivileged lab user),
i.e. real command execution inside the FPM worker.

## patchcheck

`cmd_patchcheck` runs the arm/probe sequence against a build and reports the
stale state:

```sh
python3 tools/php2shell_fpm.py patchcheck
# 8.4.26: BG.data=0x7f07be281000 level=1 STALE-ARMED
# 8.4.27: level=0 clean (both workers survive the post-RINIT OOM probe)
```

`patchcheck` iterates both laboratory builds (ports 8110/8120); it takes no
target arguments.

## Laboratory

`tools/php2shell_fpm_labs.py` runs two user-prefix builds behind one nginx
(no Docker, no root):

| Build | chain HTTP | builder HTTP | chain FPM | builder FPM |
| --- | --- | --- | --- | --- |
| 7.2.34 | :8268 | :8269 | :9168 | :9169 |
| 7.4.33 | :8336 | :8337 | :9236 | :9237 |
| 8.2.34 | :8406 | :8407 | :9306 | :9307 |
| 8.3.35 | :8478 | :8479 | :9378 | :9379 |
| 8.4.0 | :8480 | :8481 | :9380 | :9381 |
| 8.4.25 | :8130 | :8131 | :9021 | :9022 |
| 8.4.26 | :8110 | :8111 | :9001 | :9002 |
| 8.4.27 | :8120 | :8121 | :9011 | :9012 |

Every other built version gets a block of its own from
`php2shell_fpm_labs.builds_map()` (`make labs-fpm-ports` prints the mapping).

Pools (from `lab/fpm/php-fpm.conf.in`):

- **chain** — `memory_limit=8M`, session `cleanup=On` (the consumer worker);
- **builder** — `memory_limit=64M`, `cleanup=Off` (builds the ~4 MB session
  files consumed by `producer` and `build-oom`).

The builder webroot includes `bigvar.php` (the arm used by `leak`),
`leakvar.php` (a tunable variant for geometry research) and `refb.php` (a
benign short session). `app.php` can emit `X-Debug-*` diagnostics to
`/tmp/p2s_dbg.txt`; those headers are lab-only instrumentation.

Requirements: Python 3.11+, gcc for the user-prefix PHP builds
(`lab/fpm/build*.sh`). The default `endgame` also needs `yama
ptrace_scope=0` for the `/proc/<pid>/mem` oracle; `no-oracle` does not.

```sh
python3 tools/php2shell_fpm_labs.py up --only 8.4.26
python3 tools/php2shell_fpm_labs.py status
python3 tools/php2shell_fpm_labs.py smoke
python3 tools/php2shell_fpm_labs.py test      # primitive + endgame end-to-end
python3 tools/php2shell_fpm_labs.py down
```

Starting 8.4.27 alone (`up --only 8.4.27`) needs the shared nginx already
running; if the port check fails, start the FPM workers directly:

```sh
lab/fpm/runtime/php-8.4.27/sbin/php-fpm \
  -y lab/fpm/runtime/php-8.4.27/php-fpm.conf \
  -c lab/fpm/php.ini -p lab/fpm/runtime/php-8.4.27 --daemonize
```

## Driving the chain

Directly (recommended first runs):

```sh
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 \
  primitive
# forged benign var_entries; observable via app.php (r<TAB>value)

python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 \
  --version 8.4.26 --command 'id>out/p1' --proof-file out/p1 \
  endgame

# same fire, no /proc/<pid>/mem at exploit time
python3 tools/php2shell_fpm.py \
  --base http://127.0.0.1:8110 --builder http://127.0.0.1:8111 \
  --version 8.4.26 --command 'id>out/p1' --proof-file out/p1 \
  no-oracle
```

(Global options come before the subcommand.)

Via the dispatcher (`tools/php2shell_auto.py` fingerprints nginx and routes
to the FPM chain; the lab needs an explicit `--builder` because the consumer
endpoint alone is not enough for the 4 MB arm phase):

```sh
python3 tools/php2shell_auto.py \
  -u http://127.0.0.1:8110/index.php --sapi fpm \
  --builder http://127.0.0.1:8111
```

Tests: the unit suite always runs; the live lab tests are gated:

```sh
python3 -m unittest discover -s tests -v          # unit suite, skips live FPM
PHP2SHELL_FPM_LAB=1 python3 -m unittest \
  tests.test_fpm.FpmLabIntegrationTests -v        # primitive + endgame + no-oracle live
```

## Session-file plant (PHP 5.4-8.x, `poison`)

The other half of `session.upload_progress` works on **every** version,
including PHP <= 7.x where the struct-freeing chain does not apply:

1. `MULTIPART_EVENT_FORMDATA` copies the session id **from the POST body**
   without consulting `session.use_only_cookies`;
2. `MULTIPART_EVENT_FILE_START` installs it as `PS(id)` and writes the progress
   data there — kept by `session.upload_progress.cleanup=Off` on the builder;
3. the upload **filename** is stored and serialized into that file, so chosen
   bytes land in a session file of the attacker's choosing
   (`php_session_valid_key` limits the name to `[a-zA-Z0-9,-]`, so it is inside
   `save_path`, not a path traversal);
4. the application deserializes the file on its next `session_start()` and
   reflects it — over HTTP, no `/proc` anywhere.

```sh
python3 tools/php2shell_fpm.py --version 7.4.33 \
  --base http://127.0.0.1:8336 --builder http://127.0.0.1:8337 \
  poison --sid plant7x --payload 'PLANTED_MARKER'
```

This is arbitrary **session-file write** pre-auth, not RCE by itself: the
serializer rejects keys containing `|` (so the key cannot smuggle objects) and
the files handler validates the id, which rules out path traversal. Turning the
plant into code execution needs an application gadget or a local file include
in the target — which is why PHP <= 7.x is reported as *session plant* and RCE
is reserved for 8.0+, where the struct-freeing chain applies.

## Remote calibration (`calibrate`)

`calibrate` derives everything a profile needs **with HTTP requests only** —
no `/proc`, no local shell, no FPM PID. It is the same traffic the exploit
sends, so a build that calibrates is a build that exploits:

```sh
python3 tools/php2shell_fpm.py \
  --version 8.2.34 --base http://127.0.0.1:8406 --builder http://127.0.0.1:8407 \
  calibrate
```

Three phases, each validated by the answer of the target:

1. **Leak geometry** — the forged `zend_string` header is tried at a few
   content offsets; accepted when two consecutive OOB reads expose a chunk and
   a PIE pointer at the *same* offsets (which also fixes `chunk_base_off`).
2. **Reclaim geometry** — a forged `IS_LONG` zval reflected by `app.php` needs
   no PIE base, so it isolates the heap geometry (pad/size shapes and
   `(chunk offset, content offset)` pairs).
3. **PIE base** — the leaked pointer is rounded to 2 MB boundaries and each
   candidate is proven with a remote endgame until the proof file appears.

The result is written into `profiles/<version>-fpm.json`; `no-oracle` then
reproduces the RCE against that build.

## Unpatched matrix (`php2shell_fpm_matrix.py`)

`make matrix` (or `python3 tools/php2shell_fpm_matrix.py`) verifies the remote
chain on every unpatched build, one lab at a time so the ports never fight. For
each version it starts the lab, calibrates the profile over HTTP when it is not
verified yet, runs the 100%-remote `no-oracle` endgame, and prints one line per
version (patched releases are skipped by design):

```text
7.2.34    SESSION PLANT      pre-auth write into sess_<sid>
7.4.33    SESSION PLANT      pre-auth write into sess_<sid>
8.2.34    REMOTE RCE         uid=1000(...) ...
8.3.35    REMOTE RCE         uid=1000(...) ...
8.4.25    REMOTE RCE         uid=1000(...) ...
8.4.26    REMOTE RCE         uid=1000(...) ...
```

## Limitations and future work

- **Oracle lab mode.** `endgame` still uses the `/proc/<pid>/mem` oracle to
  resolve `d`. `no-oracle` drops that read at exploit time and leaks the
  chunk/PIE bases over HTTP by default; `--chunk`/`--pie` and local maps are
  overrides/fallbacks. The shipped chain still targets the loopback lab.
- **Per-build offsets.** `basic_globals` / `zif_system` / `zval_ptr_dtor` are
  PIE-relative offsets for the exact FPM build; another distro or version
  needs its own profile (`sapi: "fpm"`, see `profiles/schema.json`).
- **Command length.** ≤ 87 bytes, no NUL (fake `zend_string` carrier).
- **Worker death is expected.** The RETVAL/`efree` abort after `zif_system`
  kills the consumer worker; FPM respawns it. Long-lived targets see a brief
  502.
- **Two endpoints.** The arm phase must hit a larger pool than the consumer;
  a single-endpoint deployment would OOM the consumer worker.
- **8.4.27+ is clean.** `PHP_RINIT(basic)` reclaims/memsets the state before
  the window; `patchcheck` proves `level=0`.

See `profiles/8.4.26-fpm.json` for the verified profile and
`tools/php2shell_fpm.py` for the implementation.
