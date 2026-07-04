#!/bin/bash -eu
ROOT="${SRC:-$(pwd)}"
OUT_DIR="${OUT:-$ROOT/out}"
BUILD_DIR="$ROOT/build/classes"
JAR="$OUT_DIR/aegiswire.jar"
mkdir -p "$OUT_DIR" "$BUILD_DIR"
find "$BUILD_DIR" -type f -name '*.class' -delete 2>/dev/null || true
javac -encoding UTF-8 -d "$BUILD_DIR" $(find "$ROOT/src/main/java" "$ROOT/fuzz" -name '*.java' | sort)
jar cf "$JAR" -C "$BUILD_DIR" .
find_jazzer() {
  if [ -n "${JAZZER_API_PATH:-}" ]; then
    if [ -f "$JAZZER_API_PATH" ]; then dirname "$JAZZER_API_PATH"; return 0; fi
    if [ -f "$JAZZER_API_PATH/jazzer_api_deploy.jar" ]; then echo "$JAZZER_API_PATH"; return 0; fi
  fi
  for p in /usr/local/bin/jazzer /usr/bin/jazzer /opt/jazzer/jazzer; do
    if [ -x "$p" ]; then dirname "$p"; return 0; fi
  done
  return 1
}
JAZZER_DIR="$(find_jazzer || true)"
for target in HttpRequestFuzzer DnsMessageFuzzer TlsClientHelloFuzzer PolicyBundleFuzzer LogEventFuzzer; do
  cat > "$OUT_DIR/$target" <<EOF
#!/bin/bash -eu
SELF="\$(cd "\$(dirname "\$0")" && pwd)"
if [ -n "\${JAZZER:-}" ] && [ -x "\$JAZZER" ]; then
  exec "\$JAZZER" --cp="\$SELF/aegiswire.jar" --target_class=$target "\$@"
fi
for j in "$JAZZER_DIR/jazzer" /usr/local/bin/jazzer /usr/bin/jazzer /opt/jazzer/jazzer; do
  if [ -x "\$j" ]; then exec "\$j" --cp="\$SELF/aegiswire.jar" --target_class=$target "\$@"; fi
done
echo "jazzer launcher not found" >&2
exit 127
EOF
  chmod +x "$OUT_DIR/$target"
done
