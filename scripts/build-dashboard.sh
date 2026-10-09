#!/usr/bin/env bash
# Rebuild the dashboard's web app (dashboard/) into dashboard/dist, which the
# ariodb binary embeds. Commit dashboard/dist afterwards so `cargo build`
# keeps working without Node.
#
#   ./scripts/build-dashboard.sh
#
# For front-end work, run ariodb with a dashboard on 127.0.0.1:8080 (for
# example ./scripts/demo.sh) and then `cd dashboard && npm run dev`: Vite
# serves the app with hot reload and passes /api to ariodb.
set -euo pipefail
cd "$(dirname "$0")/../dashboard"
npm ci --no-audit --no-fund
npm run build
echo "dashboard/dist:"
du -sh dist
ls -l dist/assets
