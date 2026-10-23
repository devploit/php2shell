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

## 3. Cookie '+' decoding

PHP `urlencode()`s the session id for the `Set-Cookie` header, and that
encoding writes a space byte (0x20) as `+`. urllib's `unquote_to_bytes()`
leaves `+` untouched, so any leaked pointer whose address contains a 0x20
byte is read back `0xB00000000` too high (0x20 → 0x2b) and every stage-3
address derived from it misses. In `parse_cookie`:

```python
raw = m.group(1).replace(b"+", b"%20")
return urllib.parse.unquote_to_bytes(raw.decode("latin1"))
```

A true `+` byte in memory arrives as `%2B` and decodes back to `+` either
way, so the rewrite is lossless. This matters for roughly 1 in 256 ASLR
epochs per leaked mapping; it is why some builds calibrated clean leaks but
never landed stage 3.

## 4. Optional `noexpose` profile

For `expose_php=Off` research, the stage-1 bookworm parameters are combined with
the lab stage-3 pads. This profile is experimental and is not used by the
verified builds. Add it manually only if you are calibrating that configuration.

## Runtime behavior

- `php2shell_auto.py`, `php2shell_calibrate.py` and `php2shell_rce.py` call the
  shared patcher before importing/running the upstream.
- HTTPS runs with `--insecure` apply the SNI/TLS change.
- Direct manual use of `exploit.py` requires the snippets above.
- The early-8.5 "vessel" stage 3 is our own module
  (`tools/php2shell_vessel.py`), not an upstream change: it reuses the patched
  upstream for stages 1-2 and only replaces the stage-3 requests. The
  technique is documented in `docs/profile-inventory.md`.
