#!/usr/bin/env bash
# Rebuild the console and copy the bundle into the agent's embed dir (run before `go build`).
set -euo pipefail
cd "$(dirname "$0")"
npm ci --no-audit --no-fund
npm run build
rm -rf ../agent/internal/serving/webapp/console
mkdir -p ../agent/internal/serving/webapp/console
cp -r dist/* ../agent/internal/serving/webapp/console/
cp ../THIRD_PARTY_NOTICES.md ../agent/internal/serving/webapp/console/THIRD_PARTY_NOTICES.md
echo "embedded console refreshed at agent/internal/serving/webapp/console/"
