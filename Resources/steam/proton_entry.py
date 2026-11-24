#!/usr/bin/env python3
"""Adapt Steam's compatibility-tool protocol to the shared MetalBridge launcher."""
import os
from pathlib import Path
import sys


def command(argv, env, host):
    if len(argv) < 2 or argv[0] not in ("run", "waitforexitandrun"):
        raise ValueError("expected run|waitforexitandrun FILE [ARG ...]")
    app_id = next((env[key] for key in ("SteamAppId", "SteamGameId", "STEAM_COMPAT_APP_ID",
                                       "STEAM_APP_ID") if env.get(key)), None)
    if not app_id or not (app_id.isascii() and app_id.isdecimal() and len(app_id) <= 20):
        raise ValueError("Steam must supply a numeric AppID")
    backend = env.get("METALBRIDGE_BACKEND", "auto")
    if backend not in ("auto", "native-inproc", "wine11-fex"):
        raise ValueError("invalid METALBRIDGE_BACKEND")
    wait = ["--wait"] if argv[0] == "waitforexitandrun" else []
    return [str(host), "run", "--backend", backend, "--app-id", app_id, *wait, "--", *argv[1:]]


if __name__ == "__main__":
    host = Path.home() / "Applications/MetalBridge.app/Contents/MacOS/MetalBridge"
    try:
        os.execv(host, command(sys.argv[1:], os.environ, host))
    except (OSError, ValueError) as error:
        sys.exit(f"MetalBridge: {error}")
