# Elastic SCA Extension for EDOT Java Agent

**Software Composition Analysis (SCA) extension** for the Elastic Distribution of OpenTelemetry Java
agent (`elastic-otel-javaagent`). It intercepts every JAR loaded by the JVM at runtime, extracts
library metadata, and emits one OTel log event per unique JAR (or per embedded library in shaded
JARs) to Elasticsearch via OTLP for downstream CVE enrichment.

Branch: `sca-production-improvements`

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
9. [License Detection](#9-license-detection)
10. [How It Integrates Into the Agent](#10-how-it-integrates-into-the-agent)
11. [Build and Run](#11-build-and-run)
12. [OTLP → Elasticsearch Data Flow](#12-otlp--elasticsearch-data-flow)
13. [Performance Characteristics](#13-performance-characteristics)
14. [Known Limitations and Design Decisions](#14-known-limitations-and-design-decisions)
15. [Docker Deployment Reference](#15-docker-deployment-reference)
16. [P1–P8 Feature Summary](#16-p1p8-feature-summary)

---

## 1. What It Does

When a Java application runs with the EDOT Java agent:

1. Every `.jar` file loaded by any classloader is intercepted.
2. Metadata is extracted: `groupId`, `artifactId`, `version`, SHA-256, SHA-1, SPDX license, pURL.
3. One OTel log event is emitted per unique JAR path (or per embedded library in shaded JARs).
4. Events are sent via OTLP (HTTP/protobuf) to an EDOT Collector → Elasticsearch.
5. Elasticsearch indexes events into `logs-generic.otel-default` for CVE matching via ES|QL.

The extension is **observe-only** — it never modifies bytecode, never blocks class loading, and adds
less than 1 MB of heap overhead.

---

## 2. Packaging and Distribution

The `sca-extension` Gradle module is a library wired into the `custom` module, which flows into two
distributable artifacts:

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

SCA classes are shaded and baked into `elastic-otel-javaagent.jar` under the `inst/` prefix.

```bash
java -javaagent:elastic-otel-javaagent-<VERSION>.jar \
     -Dotel.service.name=my-service \
     -jar my-app.jar
```

### Distribution mode 2 — standalone extension for the vanilla OTel agent

```bash
java -javaagent:opentelemetry-javaagent-<VERSION>.jar \
     -Dotel.javaagent.extensions=elastic-otel-agentextension-<VERSION>.jar \
     -Dotel.service.name=my-service \
     -jar my-app.jar
```

| Artifact | Contains SCA? | Use case |
|---|---|---|
| `elastic-otel-javaagent.jar` | Yes — baked in via `custom` | Default EDOT deployment |
| `elastic-otel-agentextension.jar` | Yes — shaded in via `custom` | Add Elastic extensions to vanilla OTel agent |

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
JarMetadataExtractor                ← 5-source extraction pipeline:
        │  1. pom.properties (groupId / artifactId / version)
        │  2. MANIFEST.MF (Bundle-* / Implementation-* / Automatic-Module-Name)
        │  3. Gradle module metadata (META-INF/gradle/*.module)
        │  4. Filename pattern (name-version.jar)
        │  5. License detection (Bundle-License or META-INF/LICENSE* content)
        │  Computes SHA-256 + SHA-1 in a single file read pass
        │
        ▼
OTel Logger (co.elastic.otel.sca)   ← logsBridge + BatchLogRecordProcessor
        │  emits one LogRecord per JAR (multiple for shaded JARs)
        │
        ▼
OTLP HTTP/protobuf exporter (:4318)
        │
        ▼
EDOT Collector → Elasticsearch → logs-generic.otel-default

Additional discovery paths (run at startup and on re-harvest schedule):
  ┌─ Startup classpath scan ──── java.class.path + ManagementFactory classpath
  ├─ URLClassLoader.getURLs() ── discovers Spring Boot BOOT-INF/lib/ nested JARs
  ├─ Class-Path manifest follow ─ MANIFEST.MF Class-Path entries (1 level deep)
  └─ JPMS module layer scan ──── ModuleLayer.boot() for Java 9+ named modules
```

**Key design constraints:**
- `transform()` always returns `null` — bytecode is never modified.
- Class-loading threads are **never blocked**. All I/O happens on a dedicated background daemon thread.
- `ProtectionDomain.getCodeSource().getLocation()` is used (not `ClassLoader.getResource()`) to
  avoid acquiring the classloader monitor, preventing deadlocks.
- `jrt:/` and other non-`file:` URLs are silently ignored (JDK classes, JRT modules).
- The queue is bounded (500 entries). A full queue drops the entry and removes it from `seenJarPaths`
  so the next class load from the same JAR gets another chance.
- `seenJarPaths` is capped at `max_jars_total` (default 5000) to prevent unbounded memory growth.
- Shaded JARs emit multiple events (one per embedded `pom.properties`); rate limiting applies per
  emitted event, not per outer JAR.

---

## 4. Module Structure

```
sca-extension/
├── build.gradle.kts
├── README.md                                  Quick reference
├── SCA_EXTENSION.md                           This file — full reference
├── docker/                                    Production-ready Docker demo
│   ├── Dockerfile.java-app                    Spring PetClinic + EDOT agent
│   ├── Dockerfile.collector                   elastic/elastic-agent in OTel gateway mode
│   ├── otel-collector-config.yaml             Collector pipeline config
│   ├── docker-compose.yml                     Orchestrates all services
│   ├── .env.example                           Credential template
│   └── .env                                   Credentials (git-ignored)
└── src/
    ├── main/
    │   ├── java/co/elastic/otel/sca/
    │   │   ├── SCAExtension.java          Entry point — OTel SPI hooks
    │   │   ├── SCAConfiguration.java      Config reader (sys props + env vars)
    │   │   ├── JarCollectorService.java   Core service — transformer + background thread
    │   │   ├── JarMetadataExtractor.java  JAR inspection — 5-source pipeline
    │   │   └── JarMetadata.java           Immutable value object
    │   └── resources/META-INF/services/
    │       ├── io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider
    │       └── io.opentelemetry.javaagent.extension.AgentListener
    └── test/
        └── java/co/elastic/otel/sca/
            └── JarMetadataExtractorTest.java   38 unit tests
```

---

## 5. Source Files

### `SCAExtension.java`

Registered as both `AutoConfigurationCustomizerProvider` and `AgentListener` via two
`META-INF/services/` files.

**Phase 1 — `customize()`** (called *before* the SDK is built):
Registers default values for all 9 `elastic.otel.sca.*` config keys into the OTel config pipeline.

**Phase 2 — `afterAgent()`** (called *after* the SDK is fully initialised):
1. Reads `SCAConfiguration` — returns early if `elastic.otel.sca.enabled=false`.
2. Obtains the JVM `Instrumentation` object via reflection on
   `io.opentelemetry.javaagent.bootstrap.InstrumentationHolder.getInstrumentation()`.
3. Builds `JarCollectorService.ResourceContext` — extracts all per-JVM context once at startup
   (hostname, PID, service name, agent version, container/k8s fields).
4. Constructs `JarCollectorService`, then calls (in order):
   - `service.scanStartupClasspath()` — eager scan before transformer registers
   - `service.scanModuleLayer()` — JPMS named modules
   - `service.start()` — registers transformer, back-fills loaded classes, starts background thread
   - `service.startReharvest(config.getReharvestIntervalSeconds())` — schedules periodic re-harvest

`EPHEMERAL_ID` is a `UUID.randomUUID()` generated once per JVM process — lets operators correlate
all SCA events from this agent instance across log streams.

### `SCAConfiguration.java`

Reads configuration from system properties (priority) then environment variables. All 9 keys:

| Field | System property | Env var | Default |
|---|---|---|---|
| enabled | `elastic.otel.sca.enabled` | `ELASTIC_OTEL_SCA_ENABLED` | `true` |
| jarsPerSecond | `elastic.otel.sca.jars_per_second` | `ELASTIC_OTEL_SCA_JARS_PER_SECOND` | `10` |
| maxJarsTotal | `elastic.otel.sca.max_jars_total` | `ELASTIC_OTEL_SCA_MAX_JARS_TOTAL` | `5000` |
| skipTempJars | `elastic.otel.sca.skip_temp_jars` | `ELASTIC_OTEL_SCA_SKIP_TEMP_JARS` | `true` |
| skipTestJars | `elastic.otel.sca.skip_test_jars` | `ELASTIC_OTEL_SCA_SKIP_TEST_JARS` | `true` |
| scanStartupClasspath | `elastic.otel.sca.scan_startup_classpath` | `ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH` | `true` |
| followManifestClasspath | `elastic.otel.sca.follow_manifest_classpath` | `ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH` | `true` |
| detectShadedJars | `elastic.otel.sca.detect_shaded_jars` | `ELASTIC_OTEL_SCA_DETECT_SHADED_JARS` | `true` |
| reharvestIntervalSeconds | `elastic.otel.sca.reharvest_interval_seconds` | `ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS` | `60` |

`readIntNonNegative()` is used for `reharvestIntervalSeconds` — value 0 is valid and disables
periodic re-harvest.

### `JarCollectorService.java`

Core service. Implements `ClassFileTransformer`. Contains:

- **`ResourceContext`** — pre-extracts all context identical for every log record (service name,
  host, PID, agent version, container/k8s fields). Built once at startup.
- **`transform()`** — observe-only. Extracts JAR path from `ProtectionDomain`, applies skip filters
  (`skipTempJars`, `skipTestJars`, agent self-exclusion), deduplicates, offers to bounded queue.
- **`scanStartupClasspath()`** — scans `java.class.path` system property and
  `ManagementFactory.getRuntimeMXBean().getClassPath()` before the transformer registers.
- **`scanModuleLayer()`** — scans `ModuleLayer.boot()` to discover JPMS named modules; emits with
  `library.module_type=jpms-module`.
- **`scanAlreadyLoadedClasses()`** — back-fills already-loaded classes via
  `Instrumentation.getAllLoadedClasses()`.
- **`scanUrlClassLoaders()`** — scans all known `URLClassLoader` instances for URLs not yet seen,
  including `jar:nested:` Spring Boot URLs.
- **`followManifestClasspath()`** — opens each seen JAR, reads `MANIFEST.MF Class-Path`, enqueues
  referenced JARs one level deep.
- **`startReharvest(int intervalSeconds)`** — creates a single-thread `ScheduledExecutorService`
  (daemon) that calls `scanUrlClassLoaders()` + `followManifestClasspath()` on the configured
  interval. Ignored when `intervalSeconds == 0`.
- **`processQueue()`** — background daemon thread loop. Applies rate limiter, calls
  `JarMetadataExtractor.extract()` or `extractFromUrl()` as appropriate, calls `emitLogRecord()`.
- **`emitLogRecord()`** — builds OTel `LogRecord` with all attributes and correct wall-clock
  timestamp. Conditionally appends `library.license` and `library.shaded` only when non-empty/true.
- **`locationToJarPath()`** — handles `file:` and `jar:file:` URL protocols, URI-decodes paths,
  filters out JDK `jrt:/` entries.

### `JarMetadataExtractor.java`

Extracts library metadata from a JAR using five sources in priority order (see §8). New in P1–P8:

- **`extract(String jarPath, String classloaderName)`** — returns `List<JarMetadata>` (multiple
  entries for shaded JARs).
- **`extractFromUrl(URL jarUrl, String classloaderName)`** — handles `jar:nested:` (Spring Boot
  3.2+) and `jar:file:` protocols. Reads pom.properties + MANIFEST from the inner JAR byte stream.
- **`computeChecksums(File)`** / **`computeChecksumsFromStream(InputStream)`** — computes SHA-256
  and SHA-1 in a single read pass. Returns a `Checksums` value object.
- **`findAllPomProperties(JarFile)`** — returns all `META-INF/maven/*/pom.properties` entries.
  Size > 1 → shaded JAR.
- **`findGradleModuleMetadata(JarFile)`** — scans `META-INF/gradle/*.module` and extracts
  `group`, `module`, `version` fields using simple string scanning (no JSON library dependency).
- **`extractLicense(JarFile)`** → `String` SPDX identifier or empty. Checks Bundle-License first,
  then known license file paths.
- **`normalizeLicense(String raw)`** — maps Bundle-License values (URLs or text) to SPDX
  identifiers: Apache-2.0, MIT, GPL-3.0/2.0, LGPL-3.0/2.1, BSD-3/2-Clause, EPL-2.0/1.0, MPL-2.0.
- **`detectSpdxIdentifier(String content)`** — detects from license file text: explicit
  `SPDX-License-Identifier:` tag (highest priority), then common license text fingerprints.

`jar:nested:` URL parsing handles all three Spring Boot formats:
- `jar:nested:/path/outer.jar/!BOOT-INF/lib/inner.jar` (1 slash, most common)
- `jar:nested:///path/outer.jar/!BOOT-INF/lib/inner.jar` (3 slashes, some versions)
- `jar:nested:/path/outer.jar/!BOOT-INF/lib/inner.jar!/` (trailing `!/`)

### `JarMetadata.java`

Immutable value object. Fields:

| Field | Type | Description |
|---|---|---|
| `name` | String | Artifact name (artifactId, or Implementation-Title, or filename) |
| `version` | String | Version string, empty if unknown |
| `groupId` | String | Maven groupId, empty if unknown |
| `purl` | String | Package URL, empty if name unknown |
| `jarPath` | String | Absolute filesystem path or URL string for nested JARs |
| `sha256` | String | 64-char hex SHA-256, empty on I/O error |
| `sha1` | String | 40-char hex SHA-1, empty on I/O error |
| `classloaderName` | String | Class name of the classloader |
| `shaded` | boolean | true for entries extracted from shaded/uber-JARs |
| `license` | String | SPDX identifier, empty if not detected |
| `moduleType` | String | `jar` / `nested-jar` / `shaded-entry` / `jpms-module` |

---

## 6. Configuration Reference

All 9 properties can be set as JVM system properties or environment variables. System properties
take precedence.

| System property | Env var | Default | Description |
|---|---|---|---|
| `elastic.otel.sca.enabled` | `ELASTIC_OTEL_SCA_ENABLED` | `true` | Enable / disable the extension entirely |
| `elastic.otel.sca.jars_per_second` | `ELASTIC_OTEL_SCA_JARS_PER_SECOND` | `10` | Maximum JAR events emitted per second (token-bucket rate limiter) |
| `elastic.otel.sca.max_jars_total` | `ELASTIC_OTEL_SCA_MAX_JARS_TOTAL` | `5000` | Hard cap: stop processing new JARs after this many unique paths per JVM lifetime |
| `elastic.otel.sca.skip_temp_jars` | `ELASTIC_OTEL_SCA_SKIP_TEMP_JARS` | `true` | Skip JARs under `java.io.tmpdir` (e.g. JRuby, Groovy bytecode JARs, Spring Boot temp extract) |
| `elastic.otel.sca.skip_test_jars` | `ELASTIC_OTEL_SCA_SKIP_TEST_JARS` | `true` | Skip `*-tests.jar`, `*-test.jar`, `*-test-*.jar` — no executable library code |
| `elastic.otel.sca.scan_startup_classpath` | `ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH` | `true` | Eagerly scan `java.class.path` and ManagementFactory classpath before the ClassFileTransformer registers |
| `elastic.otel.sca.follow_manifest_classpath` | `ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH` | `true` | Follow `Class-Path` entries in each JAR's `MANIFEST.MF` one level deep |
| `elastic.otel.sca.detect_shaded_jars` | `ELASTIC_OTEL_SCA_DETECT_SHADED_JARS` | `true` | When a JAR contains multiple `pom.properties`, emit one event per embedded library (`library.shaded=true`) |
| `elastic.otel.sca.reharvest_interval_seconds` | `ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS` | `60` | Rescan known classloaders and classpath every N seconds. `0` = disabled |

### Tuning guidance

```bash
# Production: conservative rate to avoid log pipeline pressure
-Delastic.otel.sca.jars_per_second=10

# CI/CD scan: burst at max speed
-Delastic.otel.sca.jars_per_second=200

# Disable periodic re-harvest (stable production app, no dynamic deploys)
-Delastic.otel.sca.reharvest_interval_seconds=0

# Disable entirely (toggle off without redeployment)
export ELASTIC_OTEL_SCA_ENABLED=false

# Large application with many JARs
-Delastic.otel.sca.max_jars_total=10000

# Full disable of shaded JAR detection (reduces event count for uber-JARs)
-Delastic.otel.sca.detect_shaded_jars=false
```

---

## 7. OTel Log Record Schema

Every JAR emits exactly one `LogRecord` in instrumentation scope `co.elastic.otel.sca` with schema
URL `https://opentelemetry.io/schemas/1.21.0`. Shaded JARs emit multiple records (one per embedded
library), each sharing the outer JAR's `library.path`, `library.sha256`, and `library.sha1`.

### Log body

```
JAR loaded: com.google.guava:guava:33.4.6-jre path=/app/lib/guava-33.4.6-jre.jar
```

Format: `JAR loaded: <groupId>:<artifactId>:<version> path=<jarPath>`
(when no groupId: `JAR loaded: <name>:<version> path=<jarPath>`)

### Attributes

#### Library identity attributes (always emitted)

| Attribute | Example value | Description |
|---|---|---|
| `library.name` | `guava` | Artifact name |
| `library.version` | `33.4.6-jre` | Artifact version (empty if unknown) |
| `library.group_id` | `com.google.guava` | Maven groupId (empty if unknown) |
| `library.id` | `com.google.guava:guava:33.4.6-jre` | Maven coordinate for CVE matching |
| `library.type` | `jar` | Always `jar` |
| `library.language` | `java` | Always `java` |
| `library.path` | `/app/lib/guava-33.4.6-jre.jar` | Absolute filesystem path or URL |
| `library.purl` | `pkg:maven/com.google.guava/guava@33.4.6-jre` | Package URL (PURL spec) |
| `library.sha256` | `958a035b...` | SHA-256 hex digest (64 chars) |
| `library.checksum.sha256` | `958a035b...` | Same SHA-256 (OTel semconv duplicate) |
| `library.sha1` | `d4e5f678...` | SHA-1 hex digest (40 chars) — for Maven Central matching |
| `library.checksum.sha1` | `d4e5f678...` | Same SHA-1 (OTel semconv duplicate) |
| `library.module_type` | `jar` | How the library was discovered (see below) |
| `library.classloader` | `jdk.internal.loader.ClassLoaders$AppClassLoader` | Classloader that loaded the JAR |

#### `library.module_type` values

| Value | When emitted |
|---|---|
| `jar` | Regular filesystem JAR loaded via ProtectionDomain or startup classpath scan |
| `nested-jar` | Inner JAR discovered via URLClassLoader.getURLs() (`jar:nested:` or `jar:file:`) |
| `shaded-entry` | Library embedded inside a shaded/uber-JAR (multiple pom.properties) |
| `jpms-module` | Named module from the Java 9+ module layer (JPMS) |

#### Conditionally emitted library attributes

| Attribute | Type | When present |
|---|---|---|
| `library.shaded` | boolean | `true` only for `shaded-entry` entries |
| `library.license` | string | SPDX identifier (e.g. `Apache-2.0`) — only when detected from Bundle-License or LICENSE file |

#### Event identity attributes

| Attribute | Example value | Description |
|---|---|---|
| `event.name` | `co.elastic.otel.sca.library.loaded` | OTel event name |
| `event.domain` | `sca` | Event domain |
| `event.action` | `library-loaded` | ECS event.action |

#### Runtime context attributes

| Attribute | Example value | Source |
|---|---|---|
| `service.name` | `my-service` | `otel.service.name` |
| `service.version` | `1.2.3` | `otel.service.version` |
| `deployment.environment.name` | `production` | `otel.deployment.environment` |
| `host.name` | `prod-server-01` | `InetAddress.getLocalHost()` |
| `process.pid` | `12345` | JVM process ID |
| `process.runtime.name` | `OpenJDK Runtime Environment` | `java.runtime.name` |
| `process.runtime.version` | `21.0.3+9` | `java.runtime.version` |
| `agent.name` | `elastic-otel-java` | Always `elastic-otel-java` |
| `agent.type` | `opentelemetry` | Always `opentelemetry` |
| `agent.version` | `1.9.1-SNAPSHOT` | EDOT agent version |
| `agent.ephemeral_id` | `f6110f7b-...` | Random UUID per JVM startup |

#### Conditionally emitted runtime attributes (k8s/container)

| Attribute | Example value | Description |
|---|---|---|
| `container.id` | `abc123def456` | Docker container ID (from OTel resource detector) |
| `k8s.pod.name` | `my-service-6d8f9b-xkr2p` | Kubernetes pod name |
| `k8s.namespace.name` | `production` | Kubernetes namespace |
| `k8s.node.name` | `gke-node-01` | Kubernetes node |

---

## 8. Metadata Extraction Priority

Five sources, tried in order. Later sources fill gaps left by earlier ones.

```
JAR file
├── 1. META-INF/maven/<groupId>/<artifactId>/pom.properties   → groupId, artifactId, version
│      If multiple entries found → shaded JAR; emit one event per entry
│
├── 2. META-INF/MANIFEST.MF                                    → fills remaining gaps
│      Fields tried (in order for each field):
│        name:    Bundle-Name > Implementation-Title
│        version: Implementation-Version > Bundle-Version > Specification-Version
│        groupId: Implementation-Vendor-Id (if looks like Java package)
│                 Automatic-Module-Name → split at last dot
│        artId:   Bundle-SymbolicName → strip directives, take last segment
│
├── 3. META-INF/gradle/*.module                                → group, module, version (JSON)
│      Parsed with simple string scanning (no JSON library dependency)
│
├── 4. Filename pattern: name-X.Y.Z.jar                        → name, version (best effort)
│      Regex: ^(.+?)[-_](\d[\w.\-]*?)(?:[-_](?:sources|javadoc|tests?|all|shadow|shaded|uber))?$
│      Handles: .Final, .RELEASE, .GA suffixes
│      Strips: -sources, -javadoc, -tests, -all, -shadow, -shaded, -uber classifiers
│
└── 5. License detection                                        → library.license (SPDX string)
       Checked after all identity fields; see §9
```

**Name resolution (in order):**
`artifactId` (from pom.properties or Bundle-SymbolicName) → `Implementation-Title` → filename basename

**pURL construction:**
- With groupId: `pkg:maven/com.google.guava/guava@33.4.6-jre`
- Without groupId: `pkg:maven/guava@33.4.6-jre`
- Without artifactId: empty string (pURL not emitted)

**`library.id` follows the same pattern:**
- With groupId: `com.google.guava:guava:33.4.6-jre`
- Without groupId: `guava:33.4.6-jre`

---

## 9. License Detection

License detection runs after identity extraction for regular JARs. It is skipped for shaded JAR
entries (too expensive to read per-embedded-library).

### Step 1 — MANIFEST.MF `Bundle-License`

Read from the JAR manifest. The value may be:
- A URL: `https://www.apache.org/licenses/LICENSE-2.0.txt`
- A plain text expression: `Apache-2.0`, `MIT`, `GPL-3.0-or-later`

`normalizeLicense(String)` maps to SPDX identifiers:

| Detected pattern | SPDX identifier |
|---|---|
| `apache` or `www.apache.org/licenses/license-2` | `Apache-2.0` |
| `mit` (not `limited`) | `MIT` |
| `gpl-3` or (`gpl` + `3.0`) | `GPL-3.0` |
| `gpl-2` or (`gpl` + `2.0`) | `GPL-2.0` |
| `lgpl-3` or (`lgpl` + `3.0`) | `LGPL-3.0` |
| `lgpl-2` or (`lgpl` + `2.1`) | `LGPL-2.1` |
| `bsd-3` or `bsd 3-clause` | `BSD-3-Clause` |
| `bsd-2` or `bsd 2-clause` | `BSD-2-Clause` |
| `eclipse` + `2.0` | `EPL-2.0` |
| `eclipse` | `EPL-1.0` |
| `mozilla` or `mpl` | `MPL-2.0` |
| already SPDX format `[A-Za-z0-9.\-+]+` | returned as-is |

### Step 2 — LICENSE file content

License file paths checked in order:
1. `META-INF/LICENSE`
2. `META-INF/LICENSE.txt`
3. `META-INF/LICENSE.md`
4. `META-INF/license.txt`
5. `LICENSE`
6. `LICENSE.txt`

At most 8192 bytes are read. `detectSpdxIdentifier(String)` applies:

1. Explicit `SPDX-License-Identifier: <id>` line (highest priority)
2. Text fingerprints: `Apache License, Version 2.0`, `MIT License`, `Permission is hereby granted`,
   `GNU General Public License` (+ version), `GNU Lesser General Public`, `BSD 3-Clause`,
   `Eclipse Public License`, `Mozilla Public License`

If neither source produces a recognisable identifier, `library.license` is omitted from the event.

---

## 10. How It Integrates Into the Agent

```
JVM starts
    │
    ▼
premain() — OTel Java agent bootstraps
    │
    ▼
AutoConfigurationCustomizerProvider.customize()        ← SCAExtension.customize()
    │  Registers all 9 elastic.otel.sca.* defaults
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
    │  5. service.scanStartupClasspath()   — java.class.path + ManagementFactory classpath
    │  6. service.scanModuleLayer()        — JPMS named modules
    │  7. service.start():
    │       - Register ClassFileTransformer
    │       - scanAlreadyLoadedClasses()
    │       - Start background daemon thread (processQueue)
    │       - Register JVM shutdown hook
    │  8. service.startReharvest(N)        — ScheduledExecutorService every N seconds
    │
    ▼
Application runs
    │   Every class load → transform() → enqueue JAR path
    │   Every N seconds  → rescan URLClassLoaders + follow manifest Class-Path
    │
    ▼
Background thread drains queue → extract metadata → emit OTel LogRecord
    │
    ▼
BatchLogRecordProcessor → OTLP HTTP exporter → EDOT Collector → Elasticsearch
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

**Obtaining `Instrumentation`** via reflection on `InstrumentationHolder`:

```java
Class<?> holder = Class.forName("io.opentelemetry.javaagent.bootstrap.InstrumentationHolder");
Method getter = holder.getMethod("getInstrumentation");
return (Instrumentation) getter.invoke(null);
```

---

## 11. Build and Run

### Build the agent JAR

```bash
# From repo root (skip tests and JNI cross-compilation)
./gradlew build -x test

# Output: agent/build/libs/elastic-otel-javaagent-<VERSION>.jar
```

### Run unit tests

```bash
./gradlew :sca-extension:test
# Expected: 38 tests, 0 failures
```

Tests cover: pom.properties parsing, MANIFEST fallback, Gradle module metadata, filename version
patterns (`.Final`, `.RELEASE`, `.GA` suffixes), shaded JAR detection, module type values,
nested JAR URL extraction, license detection (Bundle-License + file content), SPDX normalization,
deduplication, SHA-256/SHA-1 computation.

### Local smoke test (logging exporter)

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

Look for `JAR loaded:` lines in stderr — one per unique JAR on the classpath.

### Production run with EDOT Collector

```bash
java \
  -javaagent:agent/build/libs/elastic-otel-javaagent-1.9.1-SNAPSHOT.jar \
  -Dotel.service.name=my-service \
  -Dotel.service.version=1.0.0 \
  -Dotel.deployment.environment=production \
  -Dotel.exporter.otlp.endpoint=http://collector:4318 \
  -Delastic.otel.sca.enabled=true \
  -Delastic.otel.sca.jars_per_second=50 \
  -Delastic.otel.sca.reharvest_interval_seconds=60 \
  -jar my-app.jar
```

---

## 12. OTLP → Elasticsearch Data Flow

### Recommended path — EDOT Collector → `logs-generic.otel-default`

```
Java app + EDOT agent
    │ OTLP HTTP/protobuf  POST /v1/logs  →  :4318
    ▼
EDOT Collector  (elastic/elastic-agent in OTel mode, ELASTIC_AGENT_OTEL=true)
    │ elasticsearch/otel exporter
    │ mapping: mode: otel  (native OTel data model, no ECS flattening)
    ▼
logs-generic.otel-default
    attributes.<key>           — all SCA library.* attributes
    resource.attributes.<key>  — service.name, host.name, etc.
```

**This is the recommended path.** All attributes are preserved exactly as emitted, including
`event.name`. Use the `elastic/elastic-agent` image, not `otel/opentelemetry-collector-contrib` —
the `elasticapm` connector and processor are Elastic extensions required for Kibana service maps.

### Alternative path — Direct to APM Server (not recommended for SCA)

```
Java app + EDOT agent
    │ OTLP HTTP/protobuf  →  APM Server :8200 or :443
    ▼
APM Server (ECS mapping)
    │ library.* → labels.library_*  (dots → underscores)
    │ event.name DROPPED (ECS conflict)
    ▼
logs-apm.app.<service_name>-default
```

`event.name` is dropped by the APM Server ECS mapper. All `library.*` attributes land at
`labels.library_*`. SHA-1, module_type, shaded, and license attributes are supported but renamed.

### Field mapping comparison

| OTel attribute | EDOT Collector path | APM Server path |
|---|---|---|
| `library.name` | `attributes.library.name` | `labels.library_name` |
| `library.version` | `attributes.library.version` | `labels.library_version` |
| `library.group_id` | `attributes.library.group_id` | `labels.library_group_id` |
| `library.purl` | `attributes.library.purl` | `labels.library_purl` |
| `library.sha256` | `attributes.library.sha256` | `labels.library_sha256` |
| `library.sha1` | `attributes.library.sha1` | `labels.library_sha1` |
| `library.license` | `attributes.library.license` | `labels.library_license` |
| `library.shaded` | `attributes.library.shaded` | `labels.library_shaded` |
| `library.module_type` | `attributes.library.module_type` | `labels.library_module_type` |
| `event.name` | `attributes.event.name` ✓ | **dropped** (ECS conflict) |
| `service.name` | `resource.attributes.service.name` | `service.name` (ECS top-level) |
| Index | `logs-generic.otel-default` | `logs-apm.app.<svc>-default` |

### ES|QL queries — EDOT Collector path

All SCA events (library inventory):
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE resource.attributes.`service.name` == "spring-petclinic"
| KEEP attributes.`library.name`,
        attributes.`library.version`,
        attributes.`library.group_id`,
        attributes.`library.purl`,
        attributes.`library.sha256`,
        attributes.`library.sha1`,
        attributes.`library.license`,
        attributes.`library.shaded`,
        attributes.`library.module_type`,
        attributes.`library.path`
| SORT attributes.`library.name` ASC
```

Shaded/uber-JAR entries only:
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE attributes.`library.shaded` == true
| KEEP attributes.`library.name`, attributes.`library.version`,
        attributes.`library.group_id`, attributes.`library.purl`
| SORT attributes.`library.name` ASC
```

License inventory:
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE attributes.`library.license` IS NOT NULL
| STATS count = COUNT(*) BY attributes.`library.license`
| SORT count DESC
```

Libraries with empty group_id (incomplete pURL — diagnostics):
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE attributes.`library.group_id` == ""
| KEEP attributes.`library.name`, attributes.`library.version`,
        attributes.`library.purl`, attributes.`library.module_type`
```

Library count by module type:
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| STATS count = COUNT(*) BY attributes.`library.module_type`
| SORT count DESC
```

CVE blast radius — which services use a specific library version:
```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE attributes.`library.name` == "guava"
  AND attributes.`library.version` == "33.4.6-jre"
| STATS instances = COUNT(*) BY resource.attributes.`service.name`
| SORT instances DESC
```

---

## 13. Performance Characteristics

Benchmarks: `elastic-otel-javaagent-1.9.1-SNAPSHOT.jar`, Java 25, Apple Silicon.

### Startup overhead

| Scenario | Time (avg 5 runs) | Delta |
|---|---|---|
| No agent (baseline) | 74 ms | — |
| Agent, SCA disabled | 1,342 ms | +1,268 ms (agent bootstrap) |
| Agent, SCA enabled | 1,330 ms | **-12 ms vs SCA-disabled (noise)** |

SCA adds zero measurable startup overhead beyond base agent bootstrap.

### Memory overhead

| Scenario | Heap used (after GC) |
|---|---|
| Agent, SCA disabled | 20,556 KB |
| Agent, SCA enabled | 20,620 KB |
| Delta | **+64 KB (+0.06 MB)** |

Well below the 5 MB target.

### Throughput

The background thread emits at the configured `jars_per_second` rate (default 10/s). For a typical
Spring Boot application with ~150 JARs, complete scanning takes ~15 seconds at the default rate, or
~3 seconds at 50/s. Class-loading threads are never affected — they only do a non-blocking
`offer()` to the bounded queue.

The re-harvest scheduler runs on a separate single-thread `ScheduledExecutorService` (daemon). For
stable applications with no dynamic deploys, re-harvest completes in milliseconds since all JARs
are already in `seenJarPaths`.

---

## 14. Known Limitations and Design Decisions

### JARs without pom.properties

Libraries packaged without Maven metadata (e.g. hand-rolled JARs) will have an empty
`library.group_id`. The pURL omits the namespace: `pkg:maven/commons-codec@1.18.0`. This is valid
per the PURL spec.

### Spring Boot fat JAR (jar:nested: protocol)

Spring Boot packages dependencies as nested JARs. When running `java -jar app.jar` without
extraction, the JVM exposes dependencies via `jar:nested:` URLs (Spring Boot 3.2+) or
`jar:file:` URLs. The SCA extension handles these via `extractFromUrl()`.

However, the most reliable approach for full metadata coverage is to extract the fat JAR first
so each dependency becomes a real file on disk with a `file://` URL:

```bash
# Spring Boot 3.3+ (jarmode=tools)
java -Djarmode=tools -jar app.jar extract --destination extracted
java -jar extracted/app.jar
```

In Docker:
```dockerfile
COPY app.jar .
RUN java -Djarmode=tools -jar app.jar extract --destination extracted
CMD ["java", "-jar", "/app/extracted/app.jar"]
```

After extraction, Spring PetClinic (~150 JARs) produces ~150 SCA events with `module_type=jar`,
full SHA-1/SHA-256, and pom.properties metadata for all Maven-managed dependencies.

### Agent JAR self-exclusion

The extension always skips JARs whose filename contains `elastic-otel-javaagent` or
`opentelemetry-javaagent` to prevent the agent from reporting itself.

### `AutoConfiguredOpenTelemetrySdk.getResource()` access

`getResource()` is package-private. The extension accesses it via reflection (`setAccessible(true)`)
to read container and k8s resource attributes. If the method becomes inaccessible in a future SDK
version, container/k8s fields silently fall back to empty strings.

### Rate limiter and JVM shutdown

The `BatchLogRecordProcessor` has a 30-second export timeout. The shutdown hook sets `stopped=true`
and interrupts the background thread, which drains the remaining queue before stopping. If the JVM
exits before the exporter flushes, some records may be dropped. SCA events are idempotent — the
same JARs will be reported on the next restart.

### Java 8 compatibility

All source code compiles to Java 8 bytecode (`options.release.set(8)`). No Java 9+ APIs are used
directly. JPMS module layer scanning uses reflection so it degrades gracefully on Java 8.

---

## 15. Docker Deployment Reference

A production-ready Docker demo lives in `sca-extension/docker/`. It runs Spring PetClinic
instrumented with the EDOT Java agent, an EDOT Collector, and a load generator.

### Correct EDOT architecture

```
EDOT Java SDK (spring-petclinic) — OTLP/HTTP :4318
    ▼
EDOT Collector (elastic/elastic-agent, ELASTIC_AGENT_OTEL=true)
    ├─ traces/fromsdk  [resourcedetection, elasticapm, batch] → elasticapm connector
    │                                                         → elasticsearch/otel
    ├─ metrics/fromsdk [resourcedetection, batch]             → elasticsearch/otel
    ├─ metrics/aggregated-metrics [batch]                     → elasticsearch/otel
    └─ logs/fromsdk    [resourcedetection, batch]             → elasticsearch/otel
                                                              → debug (stdout)
    ▼
Elasticsearch (mapping: mode: otel)
    traces-generic.otel-default    ← Kibana Observability → Services
    metrics-generic.otel-default   ← Kibana Observability → Infrastructure
    logs-generic.otel-default      ← SCA library events + application logs
```

### Why `elastic/elastic-agent`, not `otel/opentelemetry-collector-contrib`

The `elasticapm` connector and processor are **Elastic extensions** not in the upstream contrib
image. Without them:
- Kibana `Observability → Services` shows no service map or topology
- APM metrics (transaction duration, error rate, throughput) are not generated

### Files

```
sca-extension/docker/
├── Dockerfile.java-app          Spring PetClinic + EDOT agent (fat JAR extracted via jarmode=tools)
├── Dockerfile.collector         elastic/elastic-agent in OTel gateway mode
├── otel-collector-config.yaml   Collector pipeline: resourcedetection + batch + elasticapm + debug
├── docker-compose.yml           collector + petclinic + load-generator
├── .env.example                 Credential template (copy to .env)
└── .env                         Credentials (git-ignored)
```

### Quick start

```bash
# 1. Build the agent JAR
./gradlew build -x test

# 2. Fill in credentials
cp sca-extension/docker/.env.example sca-extension/docker/.env
# Edit .env: set ELASTIC_ENDPOINT and ELASTIC_API_KEY

# 3. Start all services
docker compose \
  --project-directory . \
  -f sca-extension/docker/docker-compose.yml \
  --env-file sca-extension/docker/.env \
  up --build

# 4. Follow collector logs to confirm SCA events flowing
docker logs -f edot-collector

# 5. Follow load generator
docker logs -f edot-load-generator
```

> **Important:** Run from the repo root with `--project-directory .` and `--env-file` flags.
> Without `--project-directory .`, Docker Compose treats the compose file's directory as the
> project root and build context paths resolve incorrectly.
> Without `--env-file`, credentials are read from the current directory (repo root) and
> `ELASTIC_ENDPOINT` / `ELASTIC_API_KEY` come through blank.

### `.env` file

```bash
# Copy and edit:
cp sca-extension/docker/.env.example sca-extension/docker/.env

# Required:
ELASTIC_ENDPOINT=https://<cluster-id>.es.<region>.gcp.elastic-cloud.com
ELASTIC_API_KEY=YourBase64ApiKeyHere==
```

**Required API key privileges** (create in Kibana → Stack Management → API Keys):
- `logs-generic.otel-*` — `auto_configure`, `create_doc`
- `traces-generic.otel-*` — `auto_configure`, `create_doc`
- `metrics-generic.otel-*` — `auto_configure`, `create_doc`

### Collector config highlights (`otel-collector-config.yaml`)

Key design decisions:

| Component | Purpose |
|---|---|
| `batch` processor | `send_batch_size: 200, timeout: 5s` — critical for SCA startup burst (150+ events) |
| `resourcedetection` processor | Enriches all signals with `host.name`, `host.arch`, `os.type` from the collector host |
| `elasticapm` processor | Enriches spans with APM-specific fields for Kibana service map |
| `elasticapm` connector | Generates aggregated APM metrics from traces/logs (transaction histograms, error rates) |
| `elasticsearch/otel` exporter | `mapping: mode: otel` — preserves native OTel structure, no ECS flattening |
| `debug` exporter | `verbosity: basic` on `logs/fromsdk` — prints one line per SCA event to collector stdout |
| `retry` block | `enabled: true, initial_interval: 1s, max_interval: 30s` — handles transient Elasticsearch errors |

> **Note:** `max_elapsed_time` is **not** a valid key in the `retry` block for this collector
> version. Only `enabled`, `initial_interval`, and `max_interval` are supported.

### Petclinic container (`Dockerfile.java-app`)

Key steps:

```dockerfile
# Stage 1: Build Spring PetClinic from source
FROM maven:3.9-eclipse-temurin-21 AS petclinic-build
RUN git clone --depth 1 https://github.com/spring-projects/spring-petclinic.git .
RUN mvn package -DskipTests -q

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-jammy
COPY --from=petclinic-build /src/target/spring-petclinic-*.jar app.jar
COPY agent/build/libs/elastic-otel-javaagent-*.jar elastic-otel-javaagent.jar

# Extract fat JAR so BOOT-INF/lib/*.jar become real file:// paths
# Required for full SCA coverage — jar:nested: URLs give incomplete metadata
RUN java -Djarmode=tools -jar app.jar extract --destination extracted

ENV JAVA_TOOL_OPTIONS="-javaagent:/app/elastic-otel-javaagent.jar"

# All 9 SCA config options set explicitly:
ENV OTEL_SERVICE_NAME="spring-petclinic" \
    OTEL_EXPORTER_OTLP_ENDPOINT="http://collector:4318" \
    ELASTIC_OTEL_SCA_ENABLED="true" \
    ELASTIC_OTEL_SCA_JARS_PER_SECOND="50" \
    ELASTIC_OTEL_SCA_MAX_JARS_TOTAL="5000" \
    ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH="true" \
    ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH="true" \
    ELASTIC_OTEL_SCA_DETECT_SHADED_JARS="true" \
    ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS="60" \
    ELASTIC_OTEL_SCA_SKIP_TEMP_JARS="true" \
    ELASTIC_OTEL_SCA_SKIP_TEST_JARS="true"

CMD ["java", "-jar", "/app/extracted/app.jar"]
```

### Validation in Kibana (ES|QL)

After startup, verify clean events in Elasticsearch:

```esql
FROM logs-generic.otel-default
| WHERE attributes.`event.name` == "co.elastic.otel.sca.library.loaded"
| WHERE resource.attributes.`service.name` == "spring-petclinic"
| KEEP attributes.`library.name`,
        attributes.`library.version`,
        attributes.`library.group_id`,
        attributes.`library.sha1`,
        attributes.`library.module_type`
| SORT @timestamp DESC
| LIMIT 20
```

Expected: `module_type=jar`, 40-char `sha1` for all entries.

### Key lessons learned

1. **Fat JAR extraction is mandatory** — `jarmode=tools extract` converts Spring Boot's
   `jar:nested:` URLs to real `file://` paths, enabling full pom.properties metadata for all ~150
   dependencies.

2. **Use `elastic/elastic-agent`** — the contrib image lacks `elasticapm` connector. Without it the
   Kibana service map does not render.

3. **`max_elapsed_time` is invalid** in the collector's `retry` block — using it crashes the
   collector at startup. Use only `enabled`, `initial_interval`, `max_interval`.

4. **Run docker compose from repo root** with `--project-directory .` and `--env-file
   sca-extension/docker/.env`. Without these, build contexts and credentials resolve incorrectly.

5. **Do not set `OTEL_TRACES_EXPORTER` / `OTEL_METRICS_EXPORTER` / `OTEL_LOGS_EXPORTER`** — EDOT
   defaults are already correct. Setting them overrides the defaults unnecessarily.

6. **Point `OTEL_EXPORTER_OTLP_ENDPOINT` to port `4318`** (HTTP), not `4317` (gRPC), unless you
   also set `OTEL_EXPORTER_OTLP_PROTOCOL=grpc`.

7. **Use `Observability → Services`**, not `APM → Services` — EDOT data lands in
   `traces-generic.otel-*`. The legacy APM view reads `traces-apm.*` and appears empty.

---

## 16. P1–P8 Feature Summary

| Feature | Config / attribute | Default |
|---|---|---|
| **P1**: pom.properties + extended MANIFEST (Bundle-*, Vendor-Id, Module-Name) + Gradle .module metadata + SHA-1 | `library.sha1`, `library.checksum.sha1` | always on |
| **P2**: URLClassLoader.getURLs() scan + `jar:nested:` Spring Boot 3.2+ URL support | automatic (runs in processQueue) | always on |
| **P3**: Shaded/uber-JAR detection — one event per embedded library | `ELASTIC_OTEL_SCA_DETECT_SHADED_JARS` / `library.shaded` / `library.module_type=shaded-entry` | `true` |
| **P4**: JPMS module layer scan (Java 9+) | `library.module_type=jpms-module` | always on |
| **P5**: Periodic re-harvest for dynamically loaded JARs | `ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS` | `60` |
| **P6**: MANIFEST `Class-Path` entry following (one level deep) | `ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH` | `true` |
| **P7**: Test JAR skip (`*-tests.jar`, `*-test.jar`) + temp JAR skip | `ELASTIC_OTEL_SCA_SKIP_TEST_JARS` / `ELASTIC_OTEL_SCA_SKIP_TEMP_JARS` | `true` / `true` |
| **P8**: SPDX license detection from Bundle-License + LICENSE* files | `library.license` | always on when detectable |
| **New**: Startup classpath eager scan | `ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH` | `true` |
| **New**: `library.module_type` attribute | `jar` / `nested-jar` / `shaded-entry` / `jpms-module` | always on |
