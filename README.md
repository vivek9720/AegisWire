# AegisWire

AegisWire is a dependency-free Java security inspection toolkit for teams that need to parse and evaluate telemetry before it reaches a SIEM or case-management workflow. It reads common boundary formats used around network controls and identity systems, normalizes them into typed events, and evaluates those events against local policy bundles.

## What It Inspects

- HTTP/1.x request blocks, including folded headers, cookies, query parameters, chunked bodies, and multipart boundary indexes.
- DNS wire messages, including compressed names, question records, and common resource records.
- TLS ClientHello records, including SNI, ALPN, supported groups, signature schemes, and extension metadata.
- Line-oriented security logs in key-value, JSON-like, and syslog-inspired layouts.
- Local policy bundles that combine event selectors, string predicates, CIDR checks, thresholds, and scoring actions.

## CLI Usage

Compile the sources with any recent JDK:

```bash
javac -d build/classes $(find src/main/java -name '*.java')
```

Run the inspector:

```bash
java -cp build/classes io.aegiswire.cli.AegisWireCli inspect --format http --input request.txt
java -cp build/classes io.aegiswire.cli.AegisWireCli inspect --format dns --input query.bin --report json
java -cp build/classes io.aegiswire.cli.AegisWireCli policy --bundle policy.awp --event event.log
```

The CLI writes a text report by default. Use `--report json` for a structured report suitable for automation.

## Library Workflow

```java
HttpRequest request = new HttpRequestParser().parse(bytes);
ScanContext context = ScanContext.forHttp(request);
PolicyBundle bundle = PolicyParser.parse(policyBytes);
PolicyResult result = new PolicyEvaluator(bundle).evaluate(context);
```

All parsers report malformed ordinary input with `ParseException`. Programming errors and corrupted internal state are left visible so callers can distinguish bad telemetry from defects that need attention.

## Policy Bundle Format

```text
rule suspicious-admin-probe
when http.path contains /admin
when http.header.user-agent contains scanner
score high
severity high
tag reconnaissance
note administrative probing pattern
end
```

Conditions support `equals`, `contains`, `prefix`, `suffix`, `matches-cidr`, `exists`, numeric comparisons, and negation with `not`.
