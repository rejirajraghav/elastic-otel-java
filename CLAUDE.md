# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Elastic Distribution of OpenTelemetry Java (EDOT Java)** is a customized JVM agent that wraps the upstream OpenTelemetry Java instrumentation agent with additional Elastic-specific features: inferred spans, span stacktraces, and Universal Profiling integration. The agent is distributed as a single shaded JAR applied via `-javaagent`.

## Build Commands

```bash
# Build (no tests)
./gradlew build testClasses -x test

# Run all tests
./gradlew test

# Run tests on a specific Java version (8, 11, 17, 21)
./gradlew test -PtestJavaVersion=17

# Run tests with OpenJ9 JVM
./gradlew test -PtestJavaVM=openj9

# Run a single test class
./gradlew :module-name:test --tests "fully.qualified.TestClass"

# Check code formatting
./gradlew spotlessCheck

# Apply code formatting
./gradlew spotlessApply

# Run muzzle checks (instrumentation library version compatibility)
./gradlew clean :instrumentation:muzzle

# Print current version
./gradlew currentVersion
```

**Output artifacts:**
- Main agent: `agent/build/libs/elastic-otel-javaagent-<VERSION>.jar`
- Extension JAR: `agentextension/build/libs/elastic-otel-agentextension-<VERSION>.jar`

Java toolchains are downloaded automatically via the Foojay resolver — no manual JDK setup needed.

## Architecture

### Module Structure

The project is a multi-module Gradle build (Kotlin DSL). Key modules:

| Module | Role |
|--------|------|
| `agent` | Packages the final shaded agent JAR for distribution |
| `agent/entrypoint` | Agent entry point / launcher |
| `agentextension` | Additional Elastic extensions packaged as a separate JAR |
| `bootstrap` | Classes that must run in the bootstrap classloader |
| `common` | Shared utilities |
| `custom` | Elastic-specific OpenTelemetry customizations |
| `instrumentation` | Library-specific auto-instrumentations (e.g., OpenAI client) |
| `inferred-spans` | Wraps the OTel contrib inferred-spans library |
| `internal-logging` | Internal logging implementation |
| `resources` | Resource provider implementations |
| `universal-profiling-integration` | Integration with Elastic Universal Profiling |
| `jvmti-access` | JVM TI access for native code |
| `runtime-attach` | Tech Preview: runtime agent attach without `-javaagent` flag |

### Testing Modules

| Module | Role |
|--------|------|
| `testing/agent-for-testing` | Pre-built agent JAR used by integration tests |
| `testing/integration-tests/*` | Integration tests for specific features |
| `testing-common` | Shared test utilities |
| `smoke-tests` | End-to-end smoke tests (JAR and WAR apps) |

### Build Conventions (buildSrc)

Custom Gradle plugins in `buildSrc/src/main/kotlin/` define shared build logic:

- `elastic-otel.java-conventions` — Java compilation (targets Java 8), JUnit 5 setup, artifact config
- `elastic-otel.instrumentation-conventions` — Shadow JAR + muzzle for instrumentation modules
- `elastic-otel.agent-packaging-conventions` — Agent JAR shading and packaging
- `elastic-otel.spotless-conventions` — Spotless formatting + Checkstyle + license headers
- `elastic-otel.test-with-agent-conventions` — Integration tests that run with the agent on the JVM

### Key Design Points

- **All Java code targets Java 8 bytecode** (`options.release.set(8)`) for broad compatibility.
- **Shadow/shading** is used extensively to avoid classpath conflicts; classes are relocated inside the agent JAR.
- **Muzzle** checks verify instrumentation bytecode against multiple versions of the target library.
- **Version** is managed solely in `version.properties` — do not update it elsewhere.
- **Dependency versions** are centralized in `gradle/libs.versions.toml`.

## Code Style

- Spotless enforces formatting. Run `./gradlew spotlessApply` before committing.
- Checkstyle rules are in `buildscripts/checkstyle.xml`.
- All source files must carry the license header defined in `buildscripts/spotless.license.java`.
