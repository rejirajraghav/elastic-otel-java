# Elastic SCA Extension for EDOT Java Agent

**Software Composition Analysis (SCA) extension** for the Elastic Distribution of OpenTelemetry Java
agent (`elastic-otel-javaagent`). It intercepts every JAR loaded by the JVM at runtime, extracts
library metadata, and emits one OTel log event per unique JAR to Elasticsearch via OTLP for
downstream CVE enrichment.

---

## Table of Contents

1. [What It Does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [Module Structure](#3-module-structure)
4. [Source Files](#4-source-files)
5. [Configuration Reference](#5-configuration-reference)
6. [OTel Log Record Schema](#6-otel-log-record-schema)
7. [Metadata Extraction Priority](#7-metadata-extraction-priority)
8. [How It Integrates Into the Agent](#8-how-it-integrates-into-the-agent)
9. [Build and Run](#9-build-and-run)
10. [OTLP → Elasticsearch Data Flow](#10-otlp--elasticsearch-data-flow)
11. [Performance Characteristics](#11-performance-characteristics)
12. [Known Limitations and Design Decisions](#12-known-limitations-and-design-decisions)

---

## 1. What It Does

When a Java application runs with the EDOT Java agent:

1. Every `.jar` file loaded by any classloader is intercepted.
2. Metadata is extracted from each JAR: `groupId`, `artifactId`, `version`, SHA-256 checksum, pURL.
3. One OTel log event is emitted per unique JAR path, carrying 25 structured attributes.
4. Events are sent via OTLP (HTTP/protobuf) to the APM server or directly to Elasticsearch.
5. Elasticsearch indexes them into the `logs-*` pipeline where they can be queried for CVE matching.

The extension is **observe-only** — it never modifies bytecode, never blocks class loading, and adds
less than 1 MB of heap overhead.

---

## 2. Architecture

```
JVM class loading event
        │
        ▼
ClassFileTransformer.transform()    ← always returns null (no bytecode change)
        │  extracts JAR path from ProtectionDomain.getCodeSource()
        │  deduplicates via ConcurrentHashMap
        │  non-blocking offer() to bounded queue (capacity 500)
        │
        ▼
LinkedBlockingQueue<PendingJar>     ← decouples class-loading thread from I/O
        │
        ▼
Background daemon thread            ← single thread, MIN_PRIORITY
        │  pulls one PendingJar at a time
        │  applies token-bucket rate limiter (default 10 JARs/s)
        │  calls JarMetadataExtractor.extract()
        │
        ▼
JarMetadataExtractor                ← reads pom.properties → MANIFEST.MF → filename
        │  computes SHA-256 of the JAR file
        │
        ▼
OTel Logger (co.elastic.otel.sca)   ← logsBridge + BatchLogRecordProcessor
        │  emits one LogRecord with 25 attributes
        │
        ▼
OTLP HTTP/protobuf exporter
        │
        ▼
APM Server → Elasticsearch → logs-* data stream
```

**Key design constraints:**
- `transform()` always returns `null` — bytecode is never modified.
- Class-loading threads are **never blocked**. All file I/O and network I/O happen on a dedicated
  background daemon thread.
- `ProtectionDomain.getCodeSource().getLocation()` is used (not `ClassLoader.getResource()`) to
  avoid acquiring the classloader monitor, preventing deadlocks.
- `jrt:/` and other non-`file:` URLs are silently ignored (JDK classes, JRT modules).
- Already-loaded classes are back-filled once at startup via `Instrumentation.getAllLoadedClasses()`.
- The queue is bounded (500 entries). A full queue drops the entry and removes it from `seenJarPaths`
  so the next class load from the same JAR gets another chance.
- `seenJarPaths` is capped at `max_jars_total` (default 5000) to prevent unbounded memory growth in
  very large applications.

---

## 3. Module Structure

```
sca-extension/
├── build.gradle.kts
└── src/
    ├── main/
    │   ├── java/co/elastic/otel/sca/
    │   │   ├── SCAExtension.java          Entry point — OTel SPI hooks
    │   │   ├── SCAConfiguration.java      Config reader (sys props + env vars)
    │   │   ├── JarCollectorService.java   Core service — transformer + background thread
    │   │   ├── JarMetadataExtractor.java  JAR inspection — pom.properties, MANIFEST, filename
    │   │   └── JarMetadata.java           Immutable value object
    │   └── resources/META-INF/services/
    │       ├── io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider
    │       └── io.opentelemetry.javaagent.extension.AgentListener
    └── test/
        └── java/co/elastic/otel/sca/
            └── JarMetadataExtractorTest.java   12 unit tests
```

The module is wired into the agent via `custom/build.gradle.kts`:

```kotlin
implementation(project(":sca-extension"))
```

And registered in `settings.gradle.kts`:

```kotlin
include("sca-extension")
```

---

## 4. Source Files

### `SCAExtension.java`

Registered as both `AutoConfigurationCustomizerProvider` and `AgentListener` via the two
`META-INF/services/` files.

**Phase 1 — `customize()`** (called *before* the SDK is built):
Registers default values for all `elastic.otel.sca.*` config keys into the OTel config pipeline
so they appear in any config-dump tooling.

**Phase 2 — `afterAgent()`** (called *after* the SDK is fully initialised):
1. Reads `SCAConfiguration` — returns early if `elastic.otel.sca.enabled=false`.
2. Obtains the JVM `Instrumentation` object via reflection on
   `io.opentelemetry.javaagent.bootstrap.InstrumentationHolder.getInstrumentation()`.
3. Builds `JarCollectorService.ResourceContext` — extracts all per-JVM context once at startup
   (hostname, PID, service name, agent version, container/k8s fields).
4. Constructs and starts `JarCollectorService`.

`EPHEMERAL_ID` is a `UUID.randomUUID()` generated once per JVM process — lets operators correlate
all SCA events from this agent instance across log streams.

### `SCAConfiguration.java`

Reads configuration from system properties (priority) then environment variables. Default values
are also registered in the OTel config pipeline by `SCAExtension.customize()`.

| System property | Env var | Default | Description |
|---|---|---|---|
| `elastic.otel.sca.enabled` | `ELASTIC_OTEL_SCA_ENABLED` | `true` | Enable/disable the extension |
| `elastic.otel.sca.skip_temp_jars` | `ELASTIC_OTEL_SCA_SKIP_TEMP_JARS` | `true` | Skip JARs under `/tmp` |
| `elastic.otel.sca.jars_per_second` | `ELASTIC_OTEL_SCA_JARS_PER_SECOND` | `10` | Emit rate limit |
| `elastic.otel.sca.max_jars_total` | `ELASTIC_OTEL_SCA_MAX_JARS_TOTAL` | `5000` | Hard cap on total JARs |

### `JarCollectorService.java`

Core service. Implements `ClassFileTransformer`. Contains:

- **`ResourceContext`** inner class — pre-extracts all context identical for every log record
  (service name, host, PID, agent version, container/k8s fields). Built once at startup.
- **`transform()`** — observe-only hook. Extracts JAR path from `ProtectionDomain`, deduplicates,
  offers to bounded queue.
- **`scanAlreadyLoadedClasses()`** — back-fill on startup.
- **`processQueue()`** — background daemon thread loop. Applies rate limiter, calls
  `JarMetadataExtractor.extract()`, calls `emitLogRecord()`.
- **`emitLogRecord()`** — builds OTel `LogRecord` with all 25 attributes and correct wall-clock
  timestamp.
- **`locationToJarPath()`** — handles `file:` and `jar:file:` URL protocols, URI-decodes paths,
  filters out JDK `jrt:/` entries.

### `JarMetadataExtractor.java`

Extracts library metadata from a JAR file using three sources in priority order:

1. `META-INF/maven/[groupId]/[artifactId]/pom.properties` — most reliable; provides groupId,
   artifactId, version.
2. `META-INF/MANIFEST.MF` — `Implementation-Title`, `Implementation-Version`,
   `Specification-Version`, `Bundle-SymbolicName` (OSGi). Used when pom.properties is absent or
   incomplete.
3. Filename pattern `^(.+?)[-_](\d[\w.\-]*)$` — best-effort version extraction. Used as last
   resort for name when no pom.properties and filename matches the version pattern.

Also computes the SHA-256 digest of the entire JAR file using an 8 KB streaming buffer.

Builds the pURL in `pkg:maven/groupId/artifactId@version` format.

### `JarMetadata.java`

Immutable value object holding: `name`, `version`, `groupId`, `purl`, `jarPath`, `sha256`,
`classloaderName`.

---

## 5. Configuration Reference

### Enabling / disabling

```bash
# Disable SCA entirely (e.g. in production until validated)
-Delastic.otel.sca.enabled=false
# or
export ELASTIC_OTEL_SCA_ENABLED=false
```

### Rate limiting

```bash
# Emit at most 5 JARs per second (default: 10)
-Delastic.otel.sca.jars_per_second=5
```

The rate limiter uses a token-bucket style sleep: the background thread sleeps
`1_000_000_000 / jars_per_second` nanoseconds between emissions.

### Hard cap

```bash
# Stop scanning after 1000 unique JARs (default: 5000)
-Delastic.otel.sca.max_jars_total=1000
```

### Temp JAR skipping

```bash
# Report JARs extracted to /tmp (e.g. Spring Boot, JRuby — disabled by default)
-Delastic.otel.sca.skip_temp_jars=false
```

### Full OTLP configuration for production

```bash
java \
  -javaagent:elastic-otel-javaagent-<VERSION>.jar \
  -Dotel.service.name=my-service \
  -Dotel.service.version=1.2.3 \
  -Dotel.deployment.environment=production \
  -Dotel.exporter.otlp.endpoint=https://<apm-server>:443 \
  -Dotel.exporter.otlp.headers="Authorization=Bearer <token>" \
  -Dotel.exporter.otlp.protocol=http/protobuf \
  -Dotel.logs.exporter=otlp \
  -jar my-app.jar
```

---

## 6. OTel Log Record Schema

Every JAR emits exactly one `LogRecord` in instrumentation scope `co.elastic.otel.sca` with schema
URL `https://opentelemetry.io/schemas/1.21.0`.

### Log body

```
JAR loaded: com.google.guava:guava:33.4.6-jre path=/app/lib/guava-33.4.6-jre.jar
```

Format: `JAR loaded: <groupId>:<artifactId>:<version> path=<jarPath>`
(when no groupId: `JAR loaded: <name>:<version> path=<jarPath>`)

### Attributes (25 fields)

| Attribute | Example value | Description |
|---|---|---|
| `library.name` | `guava` | Artifact name / best-effort basename |
| `library.version` | `33.4.6-jre` | Artifact version |
| `library.group_id` | `com.google.guava` | Maven groupId (empty if unknown) |
| `library.id` | `com.google.guava:guava:33.4.6-jre` | Maven coordinate for CVE matching |
| `library.type` | `jar` | Always `jar` |
| `library.language` | `java` | Always `java` |
| `library.path` | `/app/lib/guava-33.4.6-jre.jar` | Absolute filesystem path |
| `library.purl` | `pkg:maven/com.google.guava/guava@33.4.6-jre` | Package URL (PURL spec) |
| `library.sha256` | `958a035b...` | SHA-256 hex digest of JAR file |
| `library.checksum.sha256` | `958a035b...` | Same SHA-256 (OTel semconv duplicate) |
| `library.classloader` | `jdk.internal.loader.ClassLoaders$AppClassLoader` | Classloader that loaded the class |
| `event.name` | `co.elastic.otel.sca.library.loaded` | OTel event name |
| `event.domain` | `sca` | Event domain |
| `event.action` | `library-loaded` | ECS event.action |
| `service.name` | `my-service` | From `otel.service.name` |
| `service.version` | `1.2.3` | From `otel.service.version` |
| `deployment.environment.name` | `production` | From `otel.deployment.environment` |
| `host.name` | `prod-server-01` | From `InetAddress.getLocalHost()` |
| `process.pid` | `12345` | JVM process ID |
| `process.runtime.name` | `OpenJDK Runtime Environment` | From `java.runtime.name` |
| `process.runtime.version` | `21.0.3+9` | From `java.runtime.version` |
| `agent.name` | `elastic-otel-java` | Always `elastic-otel-java` |
| `agent.type` | `opentelemetry` | Always `opentelemetry` |
| `agent.version` | `1.9.1-SNAPSHOT` | EDOT agent version |
| `agent.ephemeral_id` | `f6110f7b-...` | Random UUID per JVM startup |

**Conditionally emitted** (only when non-empty — populated by OTel resource detectors in k8s):

| Attribute | Example value | Description |
|---|---|---|
| `container.id` | `abc123def456` | Docker container ID |
| `k8s.pod.name` | `my-service-6d8f9b-xkr2p` | Kubernetes pod name |
| `k8s.namespace.name` | `production` | Kubernetes namespace |
| `k8s.node.name` | `gke-node-01` | Kubernetes node |

---

## 7. Metadata Extraction Priority

```
JAR file
├── META-INF/maven/<groupId>/<artifactId>/pom.properties   → groupId, artifactId, version  [Priority 1]
├── META-INF/MANIFEST.MF                                   → version, artifactId (fallback) [Priority 2]
│   ├── Implementation-Version
│   ├── Specification-Version
│   ├── Implementation-Title
│   └── Bundle-SymbolicName (OSGi — stripped of directives)
└── Filename pattern: name-X.Y.Z.jar                       → name, version (best effort)   [Priority 3]

Name resolution (in order):
  artifactId (pom.properties / OSGi) > Implementation-Title (MANIFEST) > filename basename
```

The pURL is only built when `artifactId` is non-empty:
- With groupId: `pkg:maven/com.google.guava/guava@33.4.6-jre`
- Without groupId: `pkg:maven/guava@33.4.6-jre`

`library.id` (Maven coordinate) follows the same pattern:
- With groupId: `com.google.guava:guava:33.4.6-jre`
- Without groupId: `guava:33.4.6-jre`

---

## 8. How It Integrates Into the Agent

The extension participates in the OTel Java agent's autoconfigure lifecycle:

```
JVM starts
    │
    ▼
premain() — OTel Java agent bootstraps
    │
    ▼
AutoConfigurationCustomizerProvider.customize()        ← SCAExtension.customize()
    │  Registers elastic.otel.sca.* defaults
    │
    ▼
OTel SDK built (TracerProvider, MeterProvider, LoggerProvider, OTLP exporters)
    │
    ▼
AgentListener.afterAgent()                             ← SCAExtension.afterAgent()
    │  1. Read SCAConfiguration
    │  2. Get Instrumentation via InstrumentationHolder (reflection)
    │  3. Build ResourceContext (hostname, PID, k8s fields, etc.)
    │  4. Construct JarCollectorService
    │  5. service.start():
    │       - Register ClassFileTransformer
    │       - Back-fill already-loaded classes
    │       - Start background daemon thread
    │       - Register shutdown hook
    │
    ▼
Application runs
    │   Every class load → transform() → enqueue JAR path
    │
    ▼
Background thread drains queue → extract metadata → emit OTel LogRecord
    │
    ▼
BatchLogRecordProcessor → OTLP HTTP exporter → APM Server → Elasticsearch
```

**SPI registration** (manual, not `@AutoService`):

`META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider`:
```
co.elastic.otel.sca.SCAExtension
```

`META-INF/services/io.opentelemetry.javaagent.extension.AgentListener`:
```
co.elastic.otel.sca.SCAExtension
```

**Obtaining `Instrumentation`** — the OTel Java agent stores the `Instrumentation` it receives in
`premain()` inside `io.opentelemetry.javaagent.bootstrap.InstrumentationHolder`, a class in the
bootstrap classloader. The extension accesses it via:

```java
Class<?> holder = Class.forName("io.opentelemetry.javaagent.bootstrap.InstrumentationHolder");
Method getter = holder.getMethod("getInstrumentation");
return (Instrumentation) getter.invoke(null);
```

This avoids a compile-time dependency on agent-internal classes.

---

## 9. Build and Run

### Build the agent JAR

```bash
# From the repo root (skips JNI cross-compilation which requires Docker)
./gradlew :agent:assemble -x test -x compileJni

# Output:
# agent/build/libs/elastic-otel-javaagent-<VERSION>.jar   (~31 MB)
```

### Run unit tests

```bash
./gradlew :sca-extension:test
# Expected: 12 tests, 0 failures
```

### Run with logging exporter (local smoke test)

```bash
java \
  -javaagent:agent/build/libs/elastic-otel-javaagent-1.9.1-SNAPSHOT.jar \
  -Delastic.otel.sca.enabled=true \
  -Dotel.service.name=my-app \
  -Dotel.traces.exporter=none \
  -Dotel.metrics.exporter=none \
  -Dotel.logs.exporter=logging \
  -jar my-app.jar
```

Look for lines containing `JAR loaded:` in stderr — one per unique JAR on the classpath.

### Run with live APM server (Elastic Cloud)

```bash
java \
  -javaagent:agent/build/libs/elastic-otel-javaagent-1.9.1-SNAPSHOT.jar \
  -Delastic.otel.sca.enabled=true \
  -Dotel.service.name=my-service \
  -Dotel.service.version=1.0.0 \
  -Dotel.deployment.environment=production \
  -Dotel.exporter.otlp.endpoint=https://<apm-server-id>.apm.<region>.gcp.elastic-cloud.com:443 \
  -Dotel.exporter.otlp.headers="Authorization=Bearer <secret-token>" \
  -Dotel.exporter.otlp.protocol=http/protobuf \
  -Dotel.traces.exporter=none \
  -Dotel.metrics.exporter=none \
  -Dotel.logs.exporter=otlp \
  -jar my-app.jar
```

The APM endpoint and bearer token are available in Kibana under:
**APM → Add data → OpenTelemetry → Configure OpenTelemetry in your application**.

---

## 10. OTLP → Elasticsearch Data Flow

```
Java app with EDOT agent
        │ OTLP HTTP/protobuf  POST /v1/logs
        ▼
APM Server (Elastic Cloud)
        │ parses OTLP LogRecord
        │ maps attributes to ECS fields automatically
        ▼
Elasticsearch  →  logs-* data stream
        │
        ▼
Kibana → Discover / Lens / Alerting for CVE matching
```

The APM server endpoint is at:
```
https://<apm-id>.apm.<region>.gcp.elastic-cloud.com:443
```

The OTel SDK appends `/v1/logs` automatically when `otel.exporter.otlp.protocol=http/protobuf`
is set and `otel.logs.exporter=otlp`.

**Note on ECS mapping:** Elastic's OTLP ingest pipeline translates OTel attribute names to ECS
field names automatically. Do not use ECS field names in application code — always use the OTel
semantic convention names (e.g. `service.name` not `service_name`).

### Querying in Kibana with ES|QL

All libraries loaded by a service:
```esql
FROM logs-*
| WHERE event.name == "co.elastic.otel.sca.library.loaded"
| WHERE service.name == "my-service"
| KEEP library.name, library.version, library.group_id, library.purl, library.sha256
| SORT library.name ASC
```

Library inventory across all services (production):
```esql
FROM logs-*
| WHERE event.name == "co.elastic.otel.sca.library.loaded"
| WHERE deployment.environment.name == "production"
| STATS services = COUNT_DISTINCT(service.name) BY library.id, library.purl
| SORT services DESC
```

Find a specific library by SHA-256 (for CVE investigation):
```esql
FROM logs-*
| WHERE event.name == "co.elastic.otel.sca.library.loaded"
| WHERE library.sha256 == "958a035b74ff6c7d0cdff9c384524b645eb618f7117b60e1ee915f9cffd0e716"
| KEEP service.name, library.name, library.version, library.path, agent.ephemeral_id
```

---

## 11. Performance Characteristics

Benchmarks run against `elastic-otel-javaagent-1.9.1-SNAPSHOT.jar` (31 MB), Java 25, Apple
Silicon M-series, measuring the impact of the SCA extension on a real application workload.

### Startup overhead

| Scenario | Time (avg of 5 runs) | Delta |
|---|---|---|
| No agent (baseline) | 74 ms | — |
| Agent, SCA disabled | 1,342 ms | +1,268 ms (agent bootstrap) |
| Agent, SCA enabled | 1,330 ms | **-12 ms vs SCA-disabled (noise)** |

SCA adds **zero measurable startup overhead** beyond the base agent bootstrap.

### Memory overhead

| Scenario | Heap used (after GC) |
|---|---|
| Agent, SCA disabled | 20,556 KB |
| Agent, SCA enabled | 20,620 KB |
| Delta | **+64 KB (+0.06 MB)** |

Well below the 5 MB target.

### Throughput / rate limiting

The background thread emits at the configured `jars_per_second` rate (default 10/s).
For a typical Spring Boot application with ~150 JARs, complete scanning takes ~15 seconds after
startup. Class-loading threads are never affected — they only do a non-blocking `offer()` to the
queue.

---

## 12. Known Limitations and Design Decisions

### JARs without pom.properties

Libraries packaged without Maven metadata (e.g. hand-rolled JARs, OSGi bundles) will have an
empty `library.group_id`. The `library.purl` will omit the namespace component:
`pkg:maven/commons-codec@1.18.0`. This is valid per the PURL spec.

### Spring Boot executable JARs

Spring Boot's `BOOT-INF/lib/*.jar` entries use the `jar:file:` URL protocol, which
`locationToJarPath()` handles by stripping the `!/` suffix to obtain the outer JAR path. The
inner JARs are reported as a single entry for the outer fat JAR.

### Agent JAR self-exclusion

The extension always skips JARs whose filename contains `elastic-otel-javaagent` or
`opentelemetry-javaagent` to prevent the agent from reporting itself. Additionally, the agent JAR
path is resolved from `sun.java.command` as a secondary check.

### `AutoConfiguredOpenTelemetrySdk.getResource()` access

`getResource()` is package-private in the OTel SDK. The extension accesses it via
`getDeclaredMethod("getResource") + setAccessible(true)` as a best-effort approach to read
container and k8s resource attributes detected by the OTel resource providers. If the method
becomes inaccessible in a future SDK version, container/k8s fields silently fall back to empty
strings — all other fields are read from system properties and environment variables directly.

### Rate limiter and JVM shutdown

The `BatchLogRecordProcessor` has a 30-second export timeout. The shutdown hook sets `stopped=true`
and interrupts the background thread, which then drains the remaining queue before stopping. If the
JVM exits before the exporter flushes, some records may be dropped. This is acceptable for SCA
events (they are idempotent — the same JARs will be reported on the next restart).

### Java 8 compatibility

All source code compiles to Java 8 bytecode (`options.release.set(8)`) to support the full range
of JVM deployments. No Java 9+ APIs are used (no `ProcessHandle.current().pid()`, no `StackWalker`,
etc.).

---

## Repository

Branch: `feature/sca-extension`
Fork: `https://github.com/rejirajraghav/elastic-otel-java`
