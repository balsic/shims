#!/bin/sh
set -eu
umask 077

if [ "$(uname -s)/$(uname -m)" != Darwin/arm64 ]; then
    echo "The signed Wine/FEX runtime requires Apple Silicon macOS." >&2
    exit 1
fi
case "$(/usr/bin/sw_vers -productVersion | cut -d. -f1)" in
    ''|*[!0-9]*) exit 1 ;;
esac
if [ "$(/usr/bin/sw_vers -productVersion | cut -d. -f1)" -lt 15 ]; then
    echo "The child runtime requires macOS 15 or later." >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then echo "Usage: $0 [MetalSharp-Wine-9.0-arm64.zip]" >&2; exit 64; fi
root="$HOME/.local/share/MetalBridge"
runtime="$root/runtime"
archive=MetalSharp-Wine-9.0-arm64.zip
digest=2522e4f6f3cb79f79a486041301d790a2c714d084e7f328e57736f464a12a254
mkdir -p "$root"
if [ -e "$runtime" ]; then
    if [ -f "$runtime/source.sha256" ] && [ "$(cat "$runtime/source.sha256")" = "$digest" ] &&
       [ -s "$runtime/components.json" ] && [ -x "$runtime/MetalSharp-Wine.app/Contents/MacOS/wine" ]; then
        echo "The pinned runtime is already installed at $runtime"
        exit 0
    fi
    echo "Existing runtime at $runtime has a different identity. Move it before installing." >&2
    exit 1
fi
stage=$(mktemp -d "$root/.bootstrap.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
if [ "$#" -eq 1 ]; then
    zip=$1
else
    zip="$stage/$archive"
    curl --fail --location --proto '=https' --retry 3 --output "$zip" \
        "https://github.com/metalsharp/MetalSharp-Wine/releases/download/v9.0/$archive"
fi
actual=$(/usr/bin/shasum -a 256 < "$zip" | awk '{print $1}')
if [ "$actual" != "$digest" ]; then echo "Runtime archive digest mismatch" >&2; exit 1; fi
mkdir "$stage/install"
/usr/bin/ditto -x -k "$zip" "$stage/install"
app="$stage/install/MetalSharp-Wine.app"
/usr/bin/codesign --verify --deep --strict "$app"
/usr/sbin/spctl --assess --type execute "$app"
for exe in wine wineserver; do /usr/bin/lipo "$app/Contents/MacOS/$exe" -verify_arch arm64; done
case "$(/usr/bin/arch -arm64 "$app/Contents/MacOS/wine" --version)" in
    wine-11.22*) ;;
    *) echo "Expected the pinned Wine 11.22 build with the crypt32 signing-attribute fix" >&2; exit 1 ;;
esac
python3 - "$app/Contents" "$stage/install" "$runtime" "$digest" <<'PY'
import json
import os
from pathlib import Path
import sys

contents, stage, destination = map(Path, sys.argv[1:4])
names = {"libarm64ecfex.dll", "libwow64fex.dll", "crypt32.dll", "d3d11.dll",
         "dxgi.dll", "d3d12.dll", "winhttp.dll", "ntdll.dll", "winemetal.so"}
inventory = sorted(p.relative_to(contents).as_posix() for p in contents.rglob("*")
                   if p.name.lower() in names and p.is_file())
present = {Path(p).name.lower() for p in inventory}
if missing := {"libarm64ecfex.dll", "libwow64fex.dll", "ntdll.dll", "crypt32.dll"} - present:
    sys.exit(f"Incomplete Wine/FEX bundle: missing {sorted(missing)}")
(stage / "components.json").write_text(json.dumps(inventory, indent=2) + "\n")
(stage / "source.sha256").write_text(sys.argv[4] + "\n")
# Atomic publication on the same volume. Concurrent installers cannot overwrite
# an already populated directory.
os.rename(stage, destination)
PY
echo "Installed native ARM64 Wine/FEX at $runtime"
