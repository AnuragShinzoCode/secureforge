#!/usr/bin/env bash
#
# SecureForge — run a one-off CLI scan and write reports
# Usage: ./scan.sh /path/to/project [output-dir]
#
set -e

TARGET="$1"
OUTPUT="${2:-./reports}"
JAR_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$JAR_DIR/secureforge.jar"

if [ -z "$TARGET" ]; then
  echo "Usage: ./scan.sh /path/to/project [output-dir]"
  exit 1
fi

if ! command -v java >/dev/null 2>&1; then
  echo "❌ Java is not installed. SecureForge needs Java 21 or later."
  echo "   Download: https://adoptium.net/"
  exit 1
fi

java -jar "$JAR" --target "$TARGET" --output "$OUTPUT"
