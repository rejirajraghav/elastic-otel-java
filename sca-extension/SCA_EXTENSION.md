# Elastic SCA Extension for EDOT Java Agent

**Software Composition Analysis (SCA) extension** for the Elastic Distribution of OpenTelemetry Java
agent (`elastic-otel-javaagent`). It intercepts every JAR loaded by the JVM at runtime, extracts
library metadata, and emits one OTel log event per unique JAR to Elasticsearch via OTLP for
downstream CVE enrichment.

---

## Table of Contents

1. [What It Does](#1-what-it-does)
2. [Packaging and Distribution](#2-packaging-and-distribution)
3. [Architecture](#3-architecture)
4. [Module Structure](#4-module-structure)
5. [Source Files](#5-source-files)
6. [Configuration Reference](#6-configuration-reference)
7. [OTel Log Record Schema](#7-otel-log-record-schema)
8. [Metadata Extraction Priority](#8-metadata-extraction-priority)
9. [How It Integrates Into the Agent](#9-how-it-integrates-into-the-agent)
10. [Build and Run](#10-build-and-run)
11. [OTLP → Elasticsearch Data Flow](#11-otlp--elasticsearch-data-flow)
12. [Performance Characteristics](#12-performance-characteristics)
13. [Known Limitations and Design Decisions](#13-known-limitations-and-design-decisions)

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

## 2. Packaging and Distribution

The `sca-extension` Gradle module is a library that is **not distributed standalone**. It is wired
into the `custom` module and from there flows into two distributable artifacts:

```
sca-extension  (library module)
      │
      └──► custom/build.gradle.kts
                 implementation(project(":sca-extension"))
                      │
              ┌───────┴────────────────────────┐
              ▼                                ▼
   elastic-otel-javaagent.jar      elastic-otel-agentextension.jar
   (EDOT full agent)               (extension-only JAR for vanilla OTel agent)
```

### Distribution mode 1 — EDOT full agent (current default)

SCA classes are shaded and **baked directly into** `elastic-otel-javaagent.jar` under the `inst/`
prefix (the agent's instrumentation classloader). Confirmed by inspecting the JAR:

```
inst/co/elastic/otel/sca/JarCollectorService.classdata
inst/co/elastic/otel/sca/JarMetadataExtractor.classdata
inst/co/elastic/otel/sca/SCAExtension.classdata
...
```

**Usage** — single JAR, nothing extra required:

```bash
java -javaagent:elastic-otel-javaagent-<VERSION>.jar \
     -Dotel.service.name=my-service \
     -jar my-app.jar
```

### Distribution mode 2 — standalone extension for the vanilla OTel agent

The `agentextension` module shadows the `custom` module (which includes `sca-extension`) into a
separate fat JAR: `elastic-otel-agentextension.jar`. This is intended for teams already running
the **upstream OpenTelemetry Java agent** who want Elastic extensions (including SCA) without
switching to the full EDOT agent.

```
agentextension/build.gradle.kts:
  shadowDependencies(project(":custom"))   ← custom already includes sca-extension
```

**Usage** — two JARs loaded together:

```bash
java -javaagent:opentelemetry-javaagent-<VERSION>.jar \
     -Dotel.javaagent.extensions=elastic-otel-agentextension-<VERSION>.jar \
     -Dotel.service.name=my-service \
     -jar my-app.jar
```

### Summary

| Artifact | Contains SCA? | Use case |
|---|---|---|
| `elastic-otel-javaagent.jar` | Yes — baked in via `custom` | Default EDOT deployment |
| `elastic-otel-agentextension.jar` | Yes — shaded in via `custom` | Add Elastic extensions to vanilla OTel agent |
| `elastic-otel-sca-extension.jar` | N/A — does not exist yet | Future: standalone SCA-only extension |

### Alternative: fully standalone SCA extension (not yet implemented)

If you want to deploy SCA independently — for example, to add it to an existing EDOT deployment
without rebuilding the agent — you would:

1. Remove `implementation(project(":sca-extension"))` from `custom/build.gradle.kts`.
2. Build `sca-extension` as its own shadow JAR with all OTel dependencies as `compileOnly`.
3. Deploy as:

```bash
java -javaagent:elastic-otel-javaagent-<VERSION>.jar \
     -Dotel.javaagent.extensions=elastic-otel-sca-extension-<VERSION>.jar \
     -jar my-app.jar
```

This gives teams the flexibility to upgrade the SCA extension independently of the base agent.

---

## 3. Architecture

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

## 4. Module Structure

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

## 5. Source Files

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

## 6. Configuration Reference

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

## 7. OTel Log Record Schema

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

## 8. Metadata Extraction Priority

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

## 9. How It Integrates Into the Agent

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

## 10. Build and Run

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

## 11. OTLP → Elasticsearch Data Flow

There are **two distinct ingestion paths**, each producing a different index pattern and field
structure. Which one you use determines how to write your ES|QL queries.

---

### Path A — Direct to APM Server (standalone Java agent, no Kubernetes collector)

```
Java app + EDOT agent
        │ OTLP HTTP/protobuf  POST /v1/logs
        ▼
APM Server  (https://<id>.apm.<region>.gcp.elastic-cloud.com:443)
        │ ECS mapping: custom OTel attributes → labels.* (dots → underscores)
        │ event.name dropped (conflicts with reserved ECS event object)
        ▼
logs-apm.app.<service_name>-default
```

The OTel SDK appends `/v1/logs` automatically when `otel.exporter.otlp.protocol=http/protobuf`
is set and `otel.logs.exporter=otlp`. The APM endpoint and Bearer token are found in Kibana under
**APM → Add data → OpenTelemetry → Configure OpenTelemetry in your application**.

---

### Path B — Via EDOT Collector / kube-stack (Kubernetes deployments)

```
Java app + EDOT agent
        │ OTLP gRPC  → daemon collector (port 4317)
        ▼
EDOT Collector (opentelemetry-kube-stack)
        │ elasticsearch/otel exporter
        │ Native OTel data model — NO ECS flattening
        │ Attributes preserved as attributes.* and resource.attributes.*
        ▼
logs-generic.otel-default
```

This path is used when the kube-stack Helm chart is deployed. The collector receives OTLP from
the agent and forwards to Elasticsearch using the `elasticsearch/otel` exporter, which writes the
native OpenTelemetry data model without ECS transformation.

**This is the recommended path for Kubernetes deployments** — all fields are preserved exactly
as emitted, including `event.name`.

---

### Field mapping comparison

| OTel attribute | Path A (APM Server) | Path B (EDOT Collector) |
|---|---|---|
| `library.name` | `labels.library_name` | `attributes.library.name` |
| `library.version` | `labels.library_version` | `attributes.library.version` |
| `library.group_id` | `labels.library_group_id` | `attributes.library.group_id` |
| `library.id` | `labels.library_id` | `attributes.library.id` |
| `library.purl` | `labels.library_purl` | `attributes.library.purl` |
| `library.sha256` | `labels.library_sha256` | `attributes.library.sha256` |
| `event.name` | **dropped** (ECS conflict) | `attributes.event.name` ✓ |
| `event.action` | `labels.event_action` | `attributes.event.action` |
| `service.name` | `service.name` (top-level ECS) | `resource.attributes.service.name` |
| `host.name` | `host.name` (top-level ECS) | `resource.attributes.host.name` |
| `k8s.pod.name` | `labels.k8s_pod_name` | `resource.attributes.k8s.pod.name` ✓ |
| Index | `logs-apm.app.<svc>-default` | `logs-generic.otel-default` |

### APM server ECS field mapping

The APM server maps OTel log record attributes to ECS. Fields with known ECS equivalents (e.g.
`service.name`, `host.name`, `process.pid`) are stored at their natural ECS paths. All other
custom attributes — including all `library.*`, `agent.*`, and `event.*` SCA fields — are stored
flat under the `labels` object with **dots replaced by underscores**:

| OTel attribute emitted by SCA | Stored in Elasticsearch as |
|---|---|
| `library.name` | `labels.library_name` |
| `library.version` | `labels.library_version` |
| `library.group_id` | `labels.library_group_id` |
| `library.id` | `labels.library_id` |
| `library.purl` | `labels.library_purl` |
| `library.sha256` | `labels.library_sha256` |
| `library.checksum.sha256` | `labels.library_checksum_sha256` |
| `library.path` | `labels.library_path` |
| `library.type` | `labels.library_type` |
| `library.language` | `labels.library_language` |
| `library.classloader` | `labels.library_classloader` |
| `event.name` | *(dropped — conflicts with reserved ECS `event` object)* |
| `event.action` | `labels.event_action` |
| `event.domain` | `labels.event_domain` |
| `agent.ephemeral_id` | `labels.agent_ephemeral_id` |
| `service.name` | `service.name` *(native ECS — top-level)* |
| `host.name` | `host.name` *(native ECS — top-level)* |
| `process.pid` | `process.pid` *(native ECS — top-level)* |

The data stream is `logs-apm.app.<service-name>-default` (hyphens in service name become
underscores). For a service named `sca-phase2-test` it is `logs-apm.app.sca_phase2_test-default`.

### Querying in Kibana with ES|QL

**Important:** `library.*` and `event.*` SCA attributes are stored under `labels.*` with dots
replaced by underscores. The cleanest filter for SCA events is `service.framework.name`, which
is a top-level ECS field set to `co.elastic.otel.sca` on every library event (the OTel
instrumentation scope name). This is the recommended filter — more reliable than `labels.event_action`
which sits under the flattened labels object.

All libraries loaded by a service:
```esql
FROM logs-apm.app.*
| WHERE service.framework.name == "co.elastic.otel.sca"
| WHERE service.name == "my-service"
| KEEP labels.library_name, labels.library_version, labels.library_group_id,
        labels.library_purl, labels.library_sha256, labels.library_id
| SORT labels.library_name ASC
| LIMIT 50
```

Library inventory across all services (production):
```esql
FROM logs-apm.app.*
| WHERE service.framework.name == "co.elastic.otel.sca"
| WHERE labels.deployment_environment_name == "production"
| STATS services = COUNT_DISTINCT(service.name) BY labels.library_id, labels.library_purl
| SORT services DESC
```

Find a specific library by SHA-256 (for CVE investigation):
```esql
FROM logs-apm.app.*
| WHERE service.framework.name == "co.elastic.otel.sca"
| WHERE labels.library_sha256 == "958a035b74ff6c7d0cdff9c384524b645eb618f7117b60e1ee915f9cffd0e716"
| KEEP service.name, labels.library_name, labels.library_version,
        labels.library_path, labels.agent_ephemeral_id
```

Find all services running a specific library version (e.g. for CVE blast radius):
```esql
FROM logs-apm.app.*
| WHERE service.framework.name == "co.elastic.otel.sca"
| WHERE labels.library_name == "guava" AND labels.library_version == "33.4.6-jre"
| STATS instances = COUNT(*) BY service.name
| SORT instances DESC
```

### ES|QL queries — Path B (EDOT Collector → logs-generic.otel-*)

When data flows through the EDOT Collector, all attributes are preserved in their native OTel
paths. Use `attributes.event\.name` (escape the dot) or the message body filter:

All libraries loaded by a service:
```esql
FROM logs-generic.otel-*
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE resource.attributes.`service.name` == "my-service"
| KEEP attributes.`library.name`, attributes.`library.version`,
        attributes.`library.purl`, attributes.`library.id`,
        attributes.`library.sha256`
| SORT attributes.`library.name` ASC
| LIMIT 50
```

CVE blast radius across all services:
```esql
FROM logs-generic.otel-*
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| STATS services = COUNT_DISTINCT(resource.attributes.`service.name`)
        BY attributes.`library.id`, attributes.`library.purl`
| SORT services DESC
```

---

### Live-validated document structure (APM server 9.3.1)

A confirmed real document from the pipeline (`slf4j-api` event, tested 2026-03-18):

```json
{
  "service.framework.name": "co.elastic.otel.sca",
  "service.framework.version": "1.9.1-SNAPSHOT",
  "service.name": "sca-phase2-test",
  "message": "JAR loaded: org.slf4j:slf4j-api:2.0.17 path=.../slf4j-api-2.0.17.jar",
  "labels": {
    "library_name": "slf4j-api",
    "library_version": "2.0.17",
    "library_group_id": "org.slf4j",
    "library_id": "org.slf4j:slf4j-api:2.0.17",
    "library_purl": "pkg:maven/org.slf4j/slf4j-api@2.0.17",
    "library_sha256": "7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832",
    "library_checksum_sha256": "7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832",
    "library_type": "jar",
    "library_language": "java",
    "library_path": ".../slf4j-api-2.0.17.jar",
    "library_classloader": "jdk.internal.loader.ClassLoaders$AppClassLoader",
    "event_action": "library-loaded",
    "agent_name": "elastic-otel-java",
    "agent_type": "opentelemetry",
    "agent_version": "1.9.1-SNAPSHOT",
    "agent_ephemeral_id": "478f6fe3-7db1-41f3-95dd-1223297ba027",
    "service_name": "sca-phase2-test",
    "host_name": "Rajirajs-MacBook",
    "process_pid": "20748",
    "process_runtime_name": "OpenJDK Runtime Environment",
    "process_runtime_version": "25"
  }
}
```

---

## 12. Performance Characteristics

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

### Stress test: 14 classes → 12 JAR events (expected)

The 14-class stress test produced 12 log events, not 14. This is correct behaviour — the extension
deduplicates by **JAR path**, not by class. Three of the 14 classes come from the same `guava` JAR:

| Class loaded | JAR | Event emitted? |
|---|---|---|
| `ImmutableList` | `guava-33.4.6-jre.jar` | Yes — first class from this JAR |
| `ImmutableMap` | `guava-33.4.6-jre.jar` | No — JAR already in `seenJarPaths` |
| `Preconditions` | `guava-33.4.6-jre.jar` | No — JAR already in `seenJarPaths` |
| `ObjectMapper` | `jackson-databind-2.16.1.jar` | Yes |
| `JsonFactory` | `jackson-core-2.16.1.jar` | Yes |
| … 9 more single-class JARs | … | Yes (×9) |

**14 class loads → 12 unique JAR paths → 12 OTel log events.** The two "missing" events are
guava duplicate class loads — not a detection failure.

---

## 13. Known Limitations and Design Decisions

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
