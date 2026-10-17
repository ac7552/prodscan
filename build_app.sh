#!/bin/bash
# Build ProdscanDashboard.app (native Swift + WKWebView wrapper) from source.
# Requires the Xcode Command Line Tools (swiftc). macOS, Apple Silicon or Intel.
set -e
cd "$(dirname "$0")"
APP="ProdscanDashboard.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp app/Info.plist "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"
xcrun swiftc app/main.swift -o "$APP/Contents/MacOS/ProdscanDashboard" \
    -framework Cocoa -framework WebKit
chmod +x "$APP/Contents/MacOS/ProdscanDashboard"

# Bundle the engine so the app is self-contained (reports go to
# ~/Library/Application Support/prodscan, so nothing is written inside the app).
RES="$APP/Contents/Resources"
mkdir -p "$RES/targets"
cp dashboard.py prodscan.py bbscan.py pocgen.py "$RES/"
cp targets/example.json "$RES/targets/" 2>/dev/null || true
# Bundle vendored libraries so client-side (dynamic JS library) PoCs run offline.
if [ -d pocs/vendor ]; then
    mkdir -p "$RES/pocs/vendor"
    cp pocs/vendor/*.js "$RES/pocs/vendor/" 2>/dev/null || true
fi
echo "Built $APP"
echo "Run it:  open $APP        (or move it to /Applications)"
