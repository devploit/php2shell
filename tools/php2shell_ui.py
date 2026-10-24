#!/usr/bin/env python3
"""Terminal UI helpers for the PHP2Shell toolkit."""

from __future__ import annotations

import os
import shlex
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

BANNER = r"""
██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"""


class UI:
    def __init__(self, color: bool = True):
        self.color = bool(color) and os.environ.get("NO_COLOR") is None and sys.stdout.isatty()
        self.t0 = time.monotonic()

    # -- primitives ---------------------------------------------------------
    def c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def elapsed(self) -> str:
        total = time.monotonic() - self.t0
        return f"{int(total) // 60:02d}:{total % 60:05.2f}"

    def banner(self) -> None:
        print(self.c(CYAN + BOLD, BANNER))
        print(self.c(MAGENTA + BOLD, "  exploit by devploit  ·  CVE-2026-109618 / CVE-2026-109619"))
        print(self.c(DIM, "  automatic target detection, build profile dispatch and command execution"))
        print(self.c(DIM, "  authorized testing only\n"))

    def chain(self, index: str, text: str) -> None:
        print(self.c(BOLD + CYAN, f"[*] CHAIN {index}  ") + self.c(DIM, text))

    def stage(self, name: str, message: str = "") -> None:
        label = self.c(CYAN, f"{name:<10}")
        print(f"{self.c(DIM, self.elapsed())}  {label} {message}")

    def ok(self, message: str) -> None:
        self.stage("OK", self.c(GREEN, message))

    def info(self, message: str) -> None:
        self.stage("INFO", self.c(DIM, message))

    def warn(self, message: str) -> None:
        self.stage("WARN", self.c(YELLOW, message))

    def crit(self, message: str) -> None:
        self.stage("CRIT", self.c(RED, message))

    def command(self, cmd: list[str]) -> None:
        self.stage("DRY-RUN", self.c(DIM, shlex.join(cmd)))

    # -- upstream output ----------------------------------------------------
    def upstream(self, line: str) -> None:
        if "PROOF" in line:
            body = self.c(GREEN + BOLD, line)
        elif line.startswith("[+]"):
            body = self.c(GREEN, line)
        elif line.startswith("[-]"):
            body = self.c(YELLOW, line)
        elif line.startswith("[*]"):
            body = self.c(CYAN, line)
        else:
            body = self.c(DIM, line)
        print(f"   {self.c(DIM, '│')} {body}")

    # -- result -------------------------------------------------------------
    def result(self, success: bool, title: str, detail: str = "") -> None:
        width = 68
        inner = width - 4
        color = GREEN if success else RED
        print()
        print(self.c(color, "╭─ RESULT " + "─" * (width - 11) + "╮"))
        print(self.c(color, "│ ") + self.c(color + BOLD, title[:inner].ljust(inner)) + self.c(color, " │"))
        if detail:
            for line in detail.splitlines()[:4]:
                print(self.c(color, "│ ") + line[:inner].ljust(inner) + self.c(color, " │"))
        print(self.c(color, "╰" + "─" * (width - 2) + "╯"))
