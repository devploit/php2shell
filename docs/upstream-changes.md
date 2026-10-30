# Upstream changes

The toolkit fetches the public 9bie research at a pinned commit:

```sh
python3 tools/bootstrap_upstream.py   # commit 4586f5c
```

The upstream repository has **no explicit license**, so this project does not
vendor its source and does not redistribute a patch file. Instead, the toolkit
applies the minimal changes in place at runtime (`tools/php2shell_upstream.py`)
and they are documented here for manual use.

## 1. SNI and the lab TLS context

In `Target._connect`:

```python
ctx = ssl._create_unverified_context()
s = ctx.wrap_socket(s, server_hostname=self.host)
```

Without SNI, some HTTPS servers and CDNs answer the handshake with
`TLSV1_ALERT_INTERNAL_ERROR`. The unverified context is for local laboratories
and authorized targets only.

## 2. Heap-parameter overrides

In `Exploit.__init__`, after the profile defaults:

```python
import os as _os
self.stage1_n = int(_os.environ.get("P2S_STAGE1_N", self.stage1_n))
self.stage1_forge_len = int(_os.environ.get("P2S_FORGE_LEN", 79))
self.stage2_t = int(_os.environ.get("P2S_STAGE2_T", self.stage2_t))
self.stage2_v = int(_os.environ.get("P2S_STAGE2_V", self.stage2_v))
```

The fixed forge length and the pointer filters are parameterised in the same
change:

```python
forge = bytearray(b"A" * self.stage1_forge_len)
if 0x10000 < v < 0x0001000000000000:
    ...
if not (0x10000 < p < 0x0001000000000000):
    ...
```

These overrides are what let one upstream checkout serve profiles with
different `stage1_n`, forge length and stage-2 parameters.

## 2b. Stage-3 pads override

In `Exploit.__init__`, right after the stage-2 overrides:

```python
pads_env = _os.environ.get("P2S_STAGE3_PADS")
if pads_env:
    self.stage3_pads = [tuple(int(x) for x in item.split(":"))
                        for item in pads_env.split(",") if item]
```

Profiles carry a `stage3_pads` list of `[name_len, value_len]` pairs;
`php2shell_auto.py` serializes it as `a:b,a:b,...` into `P2S_STAGE3_PADS` and
`php2shell_calibrate.py --stage3-pads` accepts an explicit spec of the same
form with repetition factors, e.g. `4:4x5,31:31x6`. An explicit spec is tried
on its own (with the three known `htdata` slots) and does not require
`--stage3-htdata`.

Explicit pads default to the **non-carrier** branch (`stage3_carrier: false`,
`upstream_profile: lab`): that is the branch where `stage3_fake_len`,
`stage3_fakes` and `stage3_b_name_len` are applied. Pass
`--stage3-carrier carrier` to calibrate the 15-byte upstream carrier instead.
The generated profile's `upstream_profile` follows the measured branch, so the
dispatcher runs the same branch that was calibrated.

The other stage-3 composition knobs (all optional profile fields, all
environment-driven the same way):

| profile field | env | effect |
| --- | --- | --- |
| `stage3_cookie` | `P2S_STAGE3_COOKIE` | send `Cookie: PHPSESSID=<32 bytes>` on the stage-3 first request |
| `stage3_wfields` | `P2S_STAGE3_WFIELDS` | small fill fields (5-char name, 1-byte value) prepended to request 1 |
| `stage3_fake_len` | `P2S_STAGE3_FAKE_LEN` | byte length of the fake-reference value (replaces the built-in 55-byte ref) |
| `stage3_fakes` | `P2S_STAGE3_FAKES` | number of fake-reference fields in the reclaim run (built-in: 2) |
| `stage3_b_name_len` | `P2S_STAGE3_B_NAME_LEN` | name length of the request-2 fields (built-in: 31) |

Rationale (measured on a source-built Debian 13 amd64 8.4.26 lab, Apache
2.4.69 apxs2, one prefork worker): non-docker builds shift the startup heap,
so every byte of the stage-3 composition is load-bearing. Measured facts:

- The freed session reference lands at `R0 = chunk+0x2260+0x60*K`, linear in
  the number K of preceding bin-32 pads (gdb watchpoint sweep 0..16). The two
  built-in layouts imply K=6/K=8 and misphase this build; five `(4,4)` pads
  (K=5) align the bin-56 reclaim slot so a 31-byte fake reference is written
  whole with chars at R0. The built-in 55-byte ref frames the same payload at
  R0+8 and never reclaims here, hence `stage3_fake_len`.
- Request 1 carries the PHPSESSID cookie and five 5-char/1-byte fill fields,
  request 2 uses 3-char field names (`15x` 167-byte fake hashtables then the
  fake references) — both participate in the phase.
- Stages 1-2 dispatch cleanly on every attempt with this build's offsets;
  stage 3 is instance-dependent: 4/4 runs on one apache master instance, 0/5+
  on others started the same way (matches the 8.4.25 probabilistic precedent
  and the known build-to-build lifecycle variance; rotate/restart and retry).
- Proof command runs inside the apache mount namespace (PrivateTmp): read it
  out-of-band (`nsenter -t <pid> -m -- cat /tmp/p9b`), the dispatcher reports
  the run as blind on such targets.

See `profiles/php-8.4.26-deb13-apxs2-amd64.json`.

## 3. Optional `noexpose` profile

For `expose_php=Off` research, the stage-1 bookworm parameters are combined with
the lab stage-3 pads. This profile is experimental and is not used by the
verified builds. Add it manually only if you are calibrating that configuration.

## Runtime behavior

- `php2shell_auto.py`, `php2shell_calibrate.py` and `php2shell_rce.py` call the
  shared patcher before importing/running the upstream.
- HTTPS runs with `--insecure` apply the SNI/TLS change.
- Direct manual use of `exploit.py` requires the snippets above.
