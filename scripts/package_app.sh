#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
swift build -c release --arch arm64
bin=$(swift build -c release --arch arm64 --show-bin-path)
target="${1:-$HOME/Applications/MetalBridge.app}"
if [ -e "$target" ]; then echo "Destination exists: $target" >&2; exit 1; fi
parent=$(dirname "$target")
mkdir -p "$parent"
stage=$(mktemp -d "$parent/.metalbridge.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
app="$stage/MetalBridge.app"
mkdir -p "$app/Contents/MacOS"
install -m 644 Resources/Info.plist "$app/Contents/Info.plist"
install -m 755 "$bin/MetalBridge" "$bin/MetalAppLauncher" "$app/Contents/MacOS/"
codesign --force --options runtime --sign "${SIGN_IDENTITY:--}" "$app/Contents/MacOS/MetalAppLauncher"
codesign --force --options runtime --entitlements MetalBridge.entitlements --sign "${SIGN_IDENTITY:--}" "$app"
codesign --verify --deep --strict "$app"
python3 -c 'import os, sys; os.rename(sys.argv[1], sys.argv[2])' "$app" "$target"
"/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister" -f "$target"
echo "$target"
