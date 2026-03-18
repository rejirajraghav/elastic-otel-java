# sca-extension — Software Composition Analysis for EDOT Java

Automatically discovers every JAR loaded by the JVM at runtime, extracts library metadata, and
emits one OpenTelemetry log event per unique JAR to Elasticsearch via OTLP. Events land in the
`logs-generic.otel-default` data stream (via EDOT Collector) where they can be enriched with CVE
data from the OSV database.

## How it works

1. **Startup classpath scan** — before the transformer registers, `java.class.path`,
   `ManagementFactory`, and the JPMS module layer are scanned so JARs loaded very early are not
   missed. Controlled by `ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH` (default: true).

2. **ClassFileTransformer hook** — for every loaded class, `ProtectionDomain.getCodeSource().getLocation()`
   yields the owning JAR path. This never transforms bytecode and never blocks the class-loading thread.

3. **URLClassLoader scan** — all known `URLClassLoader` instances are scanned for URLs that were
   not seen via ProtectionDomain, including Spring Boot `BOOT-INF/lib/` nested JARs
   (`jar:nested:` protocol, Spring Boot 3.2+).

4. **Class-Path manifest following** — when `ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH=true`,
   `Class-Path` entries in each JAR's `MANIFEST.MF` are followed one level deep.

5. **Deduplication** — a `ConcurrentHashMap` keyed on JAR path ensures each JAR is processed exactly once.

6. **Async metadata extraction** — JAR paths are placed in a bounded queue (capacity 500). A single
   daemon thread reads from the queue, opens each JAR, and extracts metadata using five sources
   in priority order:
   - `META-INF/maven/*/*/pom.properties` — groupId, artifactId, version (most reliable)
   - `META-INF/MANIFEST.MF` — Bundle-SymbolicName, Implementation-Title/Version, Automatic-Module-Name, Implementation-Vendor-Id
   - `META-INF/gradle/*.module` — Gradle module metadata JSON (group/module/version)
   - Filename pattern `name-version.jar` — best-effort parse
   - License detection — Bundle-License manifest attribute or META-INF/LICENSE* file content

7. **Shaded JAR detection** — when multiple `pom.properties` entries are found in a single JAR, the
   JAR is classified as a shaded/uber-JAR and one event is emitted per embedded library
   (`library.shaded=true`, `library.module_type=shaded-entry`). Controlled by
   `ELASTIC_OTEL_SCA_DETECT_SHADED_JARS` (default: true).

8. **Checksums** — SHA-256 and SHA-1 are both computed from JAR bytes in a single read pass.
   SHA-1 is used for Maven Central matching; SHA-256 for CVE fingerprinting.

9. **Rate-limited emission** — log records are emitted at a configurable rate (default: 50 JARs/s)
   using a token-bucket style sleep on the background thread.

10. **Periodic re-harvest** — a `ScheduledExecutorService` rescans known classloaders and the
    classpath every `ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS` seconds (default: 60) to pick up
    dynamically loaded JARs (OSGi bundle installs, servlet hot-deploy). Set to 0 to disable.

## Emitted log record

| Field | OTel attribute | Example |
|---|---|---|
| Body | — | `JAR loaded: com.google.guava:guava:32.1.3-jre path=...` |
| Library name | `library.name` | `guava` |
| Library version | `library.version` | `32.1.3-jre` |
| Maven groupId | `library.group_id` | `com.google.guava` |
| Package URL | `library.purl` | `pkg:maven/com.google.guava/guava@32.1.3-jre` |
| JAR path | `library.path` | `/app/lib/guava-32.1.3-jre.jar` |
| SHA-256 | `library.sha256` | `a1b2c3...` (64-char hex) |
| SHA-256 (duplicate) | `library.checksum.sha256` | same |
| SHA-1 | `library.sha1` | `d4e5f6...` (40-char hex) |
| SHA-1 (duplicate) | `library.checksum.sha1` | same |
| SPDX license | `library.license` | `Apache-2.0` (omitted if not detected) |
| Shaded flag | `library.shaded` | `true` for uber-JAR entries |
| Module type | `library.module_type` | `jar` / `nested-jar` / `shaded-entry` / `jpms-module` |
| Classloader | `library.classloader` | `jdk.internal.loader.ClassLoaders$AppClassLoader` |
| Event name | `event.name` | `co.elastic.otel.sca.library.loaded` |
| Event domain | `event.domain` | `sca` |

The instrumentation scope is `co.elastic.otel.sca`.

## Configuration

All properties can be set as JVM system properties (`-Dproperty=value`) or environment variables.
System properties take precedence.

| System property | Env var | Default | Description |
|---|---|---|---|
| `elastic.otel.sca.enabled` | `ELASTIC_OTEL_SCA_ENABLED` | `true` | Enable / disable the extension |
| `elastic.otel.sca.jars_per_second` | `ELASTIC_OTEL_SCA_JARS_PER_SECOND` | `10` | Maximum JAR events emitted per second |
| `elastic.otel.sca.max_jars_total` | `ELASTIC_OTEL_SCA_MAX_JARS_TOTAL` | `5000` | Hard cap on total unique JARs per JVM lifetime |
| `elastic.otel.sca.skip_temp_jars` | `ELASTIC_OTEL_SCA_SKIP_TEMP_JARS` | `true` | Skip JARs under `java.io.tmpdir` |
| `elastic.otel.sca.skip_test_jars` | `ELASTIC_OTEL_SCA_SKIP_TEST_JARS` | `true` | Skip `*-tests.jar` and `*-test.jar`. Note: `-sources.jar` and `-javadoc.jar` are always skipped |
| `elastic.otel.sca.scan_startup_classpath` | `ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH` | `true` | Eagerly scan `java.class.path` and ManagementFactory classpath at startup |
| `elastic.otel.sca.follow_manifest_classpath` | `ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH` | `true` | Follow `Class-Path` entries in `MANIFEST.MF` one level deep |
| `elastic.otel.sca.detect_shaded_jars` | `ELASTIC_OTEL_SCA_DETECT_SHADED_JARS` | `true` | Detect shaded/uber-JARs and emit one event per embedded library |
| `elastic.otel.sca.reharvest_interval_seconds` | `ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS` | `60` | Re-scan interval in seconds. Set to `0` to disable periodic re-harvest |

Example:

```bash
java -javaagent:elastic-otel-javaagent.jar \
     -Delastic.otel.sca.enabled=true \
     -Delastic.otel.sca.jars_per_second=50 \
     -Delastic.otel.sca.reharvest_interval_seconds=60 \
     -jar myapp.jar
```

## Build & packaging

The module is built with `elastic-otel.library-packaging-conventions` and is included in the agent
as an `implementation` dependency of the `custom` module. No changes to agent packaging are required.

```
agent (elastic-otel-javaagent.jar)
  └── custom  (javaagentLibs)
        └── sca-extension  (transitive implementation dep)
```

The two SPI registrations in `META-INF/services/` are merged into `inst/META-INF/services/` inside
the agent JAR by the `mergeServiceFiles()` step in `elastic-otel.agent-packaging-conventions`.

## Downstream enrichment

The recommended Elasticsearch ingest pipeline uses an enrich processor that joins `library.purl`
with an OSV-sourced enrich index:

```json
{
  "enrich": {
    "policy_name": "osv-cve-by-purl",
    "field": "library.purl",
    "target_field": "vulnerability",
    "ignore_missing": true
  }
}
```

This adds `vulnerability.cve`, `vulnerability.severity`, and `vulnerability.fix_available` fields
to each log document, enabling a full library inventory with CVE status visible in Kibana.

## Docker demo

A production-ready demo lives in `sca-extension/docker/`. See `SCA_EXTENSION.md` for the complete
deployment guide including Docker quick-start, ES|QL queries, and troubleshooting.
