#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
trap 'exit 1' HUP INT TERM
python3 Tests/fixtures.py "$temp/answer.exe"
src=Sources/MetalBridgeLoader
cat > "$temp/module.modulemap" <<EOF
module MetalBridgeLoader { header "$PWD/$src/include/MetalBridgeLoader.h" export * }
EOF
cxxlib=-lstdc++
if [ "$(uname -s)" = Darwin ]; then cxxlib=-lc++; fi
for unit in "$src"/*.cpp Sources/NativeShims/ntdll_xnu.cpp; do
    "${CXX:-c++}" -std=c++20 -I"$src/include" -ISources/NativeShims/include -c "$unit" -o "$temp/$(basename "$unit").o"
done
swiftc -I "$temp" Tests/SharedCoreCheck.swift Sources/MetalBridgeDaemon/PEInspector.swift \
    Sources/MetalBridgeDaemon/PrefixManager.swift Sources/MetalBridgeDaemon/StartMenuLink.swift \
    "$temp"/*.o "$cxxlib" -o "$temp/shared-check"
"$temp/shared-check" "$temp/answer.exe"
