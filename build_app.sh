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
echo "Built $APP"
echo "Run it:  open $APP        (or move it to /Applications)"
