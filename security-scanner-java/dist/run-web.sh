#!/usr/bin/env bash
#
# SecureForge — launch the web dashboard
# Usage: ./run-web.sh [port]
#
set -e

PORT="${1:-8765}"
JAR_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$JAR_DIR/secureforge.jar"

if ! command -v java >/dev/null 2>&1; then
  echo "❌ Java is not installed. SecureForge needs Java 21 or later."
  echo "   Download: https://adoptium.net/"
  exit 1
fi

echo "🛡️  Starting SecureForge web UI on port $PORT ..."
echo "   Open http://localhost:$PORT in your browser."
echo ""
java -jar "$JAR" --web --port "$PORT"
