#!/usr/bin/env python3
"""icsscanner-web.py — icsScanner web UI entrypoint (Phase 4 of the CLI "last mile" plan).

A local control panel over the exact same pipeline icsscanner.py (the CLI) drives — see
web/server.py's module docstring for the wiring. Binds 127.0.0.1 by default: this is a control
surface for a tool that fires real credentialed/destructive network traffic, same dual-use
discipline as the CLI's --yes consent gate — exposing it beyond localhost is an explicit,
warned-about opt-in, not a default.

Usage:
    python3 icsscanner-web.py
    python3 icsscanner-web.py --port 9000
    python3 icsscanner-web.py --host 0.0.0.0 --port 8807   # exposes the control panel to the
                                                            # network — only do this if you mean
                                                            # to, see the warning printed below

AUTHORIZED USE ONLY — only scan devices you own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import sys

from web.server import run_server

WARNING_BANNER = """
╔══════════════════════════════════════════════════════════════════════╗
║                      *** AUTHORIZED USE ONLY ***                     ║
║                                                                      ║
║  This starts a web control panel that can trigger live protocol      ║
║  traffic against ICS/OT devices, including real login attempts       ║
║  against published factory-default credentials.                     ║
║                                                                      ║
║  ONLY use against systems you have EXPLICIT WRITTEN AUTHORIZATION    ║
║  to test. By default this binds to 127.0.0.1 only (this machine).    ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="icsscanner-web",
        description="Start the icsScanner web UI (a control panel over the same engine icsscanner.py drives).",
    )
    parser.add_argument("--host", default="127.0.0.1", metavar="HOST", help="Bind address (default: 127.0.0.1, localhost-only).")
    parser.add_argument("--port", type=int, default=8807, metavar="PORT", help="Bind port (default: 8807).")
    return parser


def main() -> int:
    print(WARNING_BANNER)

    args = build_parser().parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[warn] Binding to {args.host!r}, not localhost — this control panel will be "
              f"reachable from other hosts on that interface. It has no authentication layer. "
              f"Only do this on a trusted, isolated network.\n")

    run_server(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
