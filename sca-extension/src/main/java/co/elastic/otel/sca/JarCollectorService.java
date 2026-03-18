/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package co.elastic.otel.sca;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;

/**
 * Core SCA service that intercepts class loading, extracts JAR metadata asynchronously, and emits
 * one OTel log event per unique JAR to the {@code co.elastic.otel.sca} instrumentation scope.
 *
 * <p>Design constraints:
 *
 * <ul>
 *   <li>The {@link ClassFileTransformer#transform} method always returns {@code null} — bytecode is
 *       never modified.
 *   <li>Class-loading threads are never blocked; all I/O happens on a single daemon background
 *       thread.
 *   <li>Discovery uses {@link ProtectionDomain#getCodeSource()} rather than {@code
 *       ClassLoader.getResource()} to avoid holding the classloader monitor.
 * </ul>
 */
public final class JarCollectorService implements ClassFileTransformer {

  private static final java.util.logging.Logger log =
      java.util.logging.Logger.getLogger(JarCollectorService.class.getName());

  // ---- OTel schema / instrumentation metadata ----------------------------

  private static final String OTEL_SCHEMA_URL = "https://opentelemetry.io/schemas/1.21.0";

  // ---- OTel attribute keys -----------------------------------------------

  // Library identity
  private static final AttributeKey<String> ATTR_LIBRARY_NAME =
      AttributeKey.stringKey("library.name");
  private static final AttributeKey<String> ATTR_LIBRARY_VERSION =
      AttributeKey.stringKey("library.version");
  private static final AttributeKey<String> ATTR_LIBRARY_GROUP_ID =
      AttributeKey.stringKey("library.group_id");
  private static final AttributeKey<String> ATTR_LIBRARY_TYPE =
      AttributeKey.stringKey("library.type");
  private static final AttributeKey<String> ATTR_LIBRARY_LANGUAGE =
      AttributeKey.stringKey("library.language");
  private static final AttributeKey<String> ATTR_LIBRARY_PATH =
      AttributeKey.stringKey("library.path");
  private static final AttributeKey<String> ATTR_LIBRARY_PURL =
      AttributeKey.stringKey("library.purl");
  private static final AttributeKey<String> ATTR_LIBRARY_SHA256 =
      AttributeKey.stringKey("library.sha256");
  private static final AttributeKey<String> ATTR_LIBRARY_CHECKSUM_SHA256 =
      AttributeKey.stringKey("library.checksum.sha256");
  private static final AttributeKey<String> ATTR_LIBRARY_CLASSLOADER =
      AttributeKey.stringKey("library.classloader");

  // Event identity (FIX 4)
  private static final AttributeKey<String> ATTR_EVENT_NAME =
      AttributeKey.stringKey("event.name");
  private static final AttributeKey<String> ATTR_EVENT_DOMAIN =
      AttributeKey.stringKey("event.domain");
  private static final AttributeKey<String> ATTR_EVENT_ACTION =
      AttributeKey.stringKey("event.action");

  // Service identity (FIX 3)
  private static final AttributeKey<String> ATTR_SERVICE_NAME =
      AttributeKey.stringKey("service.name");
  private static final AttributeKey<String> ATTR_SERVICE_VERSION =
      AttributeKey.stringKey("service.version");

  // Deployment (FIX 2)
  private static final AttributeKey<String> ATTR_DEPLOYMENT_ENV =
      AttributeKey.stringKey("deployment.environment.name");

  // Host and process (FIX 3)
  private static final AttributeKey<String> ATTR_HOST_NAME =
      AttributeKey.stringKey("host.name");
  private static final AttributeKey<String> ATTR_PROCESS_PID =
      AttributeKey.stringKey("process.pid");
  private static final AttributeKey<String> ATTR_PROCESS_RUNTIME_NAME =
      AttributeKey.stringKey("process.runtime.name");
  private static final AttributeKey<String> ATTR_PROCESS_RUNTIME_VERSION =
      AttributeKey.stringKey("process.runtime.version");

  // Agent identity (FIX 7)
  private static final AttributeKey<String> ATTR_AGENT_NAME =
      AttributeKey.stringKey("agent.name");
  private static final AttributeKey<String> ATTR_AGENT_TYPE =
      AttributeKey.stringKey("agent.type");
  private static final AttributeKey<String> ATTR_AGENT_VERSION =
      AttributeKey.stringKey("agent.version");
  private static final AttributeKey<String> ATTR_AGENT_EPHEMERAL_ID =
      AttributeKey.stringKey("agent.ephemeral_id");

  // Container / k8s (FIX 8)
  private static final AttributeKey<String> ATTR_CONTAINER_ID =
      AttributeKey.stringKey("container.id");
  private static final AttributeKey<String> ATTR_K8S_POD_NAME =
      AttributeKey.stringKey("k8s.pod.name");
  private static final AttributeKey<String> ATTR_K8S_NAMESPACE =
      AttributeKey.stringKey("k8s.namespace.name");
  private static final AttributeKey<String> ATTR_K8S_NODE_NAME =
      AttributeKey.stringKey("k8s.node.name");

  // ---- Internal state ----------------------------------------------------

  /** Maximum number of pending JAR paths that can queue before drops begin. */
  private static final int QUEUE_CAPACITY = 500;

  private final OpenTelemetrySdk openTelemetry;
  private final Instrumentation instrumentation;
  private final SCAConfiguration config;
  private final ResourceContext resourceCtx;

  /** Paths already enqueued or processed — prevents duplicate work. */
  private final Set<String> seenJarPaths = ConcurrentHashMap.newKeySet();

  /** Total number of JARs admitted (enqueued or processed). Capped at maxJarsTotal. */
  private final AtomicInteger totalJarsAdmitted = new AtomicInteger(0);

  /**
   * Bounded queue of JARs waiting for metadata extraction. Offer is non-blocking; full queue drops
   * the entry (class loading must never block).
   */
  private final LinkedBlockingQueue<PendingJar> pendingJars =
      new LinkedBlockingQueue<>(QUEUE_CAPACITY);

  private final AtomicBoolean started = new AtomicBoolean(false);
  private final AtomicBoolean stopped = new AtomicBoolean(false);

  /** Names/patterns to identify JARs that should never be reported. */
  private final String agentJarPath;

  private final String tmpDir;

  JarCollectorService(
      OpenTelemetrySdk openTelemetry,
      Instrumentation instrumentation,
      SCAConfiguration config,
      ResourceContext resourceCtx) {
    this.openTelemetry = openTelemetry;
    this.instrumentation = instrumentation;
    this.config = config;
    this.resourceCtx = resourceCtx;
    this.agentJarPath = resolveAgentJarPath();
    this.tmpDir = normalise(System.getProperty("java.io.tmpdir", "/tmp"));
  }

  // ---- Lifecycle ---------------------------------------------------------

  void start() {
    if (!started.compareAndSet(false, true)) {
      return;
    }

    // Register transformer — returns null always, observes only
    instrumentation.addTransformer(this, /* canRetransform= */ false);

    // Back-fill classes already loaded before our transformer registered
    scanAlreadyLoadedClasses();

    // Single daemon thread handles all I/O off the class-loading path
    Thread worker = new Thread(this::processQueue, "elastic-sca-jar-collector");
    worker.setDaemon(true);
    worker.setPriority(Thread.MIN_PRIORITY);
    worker.start();

    // Drain remaining queue on JVM shutdown before the OTLP exporter shuts down
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  stopped.set(true);
                  worker.interrupt();
                },
                "elastic-sca-shutdown"));

    log.fine("SCA: JarCollectorService started");
  }

  // ---- ClassFileTransformer ----------------------------------------------

  /**
   * Called by the JVM on every class load. We extract the JAR path from the {@link
   * ProtectionDomain}, deduplicate, and offer to the background queue. We never transform the
   * bytecode.
   */
  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    // Skip bootstrap classloader (null) and already-stopped state
    if (loader == null || className == null || stopped.get()) {
      return null;
    }
    try {
      enqueueFromProtectionDomain(loader, protectionDomain);
    } catch (Exception ignored) {
      // Must never propagate out of transform()
    }
    return null;
  }

  // ---- Discovery helpers -------------------------------------------------

  private void enqueueFromProtectionDomain(ClassLoader loader, ProtectionDomain pd) {
    if (pd == null) {
      return;
    }
    CodeSource cs = pd.getCodeSource();
    if (cs == null) {
      return;
    }
    URL location = cs.getLocation();
    if (location == null) {
      return;
    }
    String jarPath = locationToJarPath(location);
    if (jarPath == null || !jarPath.endsWith(".jar")) {
      return;
    }
    if (shouldSkip(jarPath)) {
      return;
    }
    // Cap total JARs to prevent unbounded seenJarPaths growth in long-running apps
    if (totalJarsAdmitted.get() >= config.getMaxJarsTotal()) {
      return;
    }
    if (!seenJarPaths.add(jarPath)) {
      return; // already seen
    }
    totalJarsAdmitted.incrementAndGet();

    String classloaderName = loader.getClass().getName();
    // Non-blocking offer: if the queue is full we drop this JAR rather than stall a class-loading
    // thread. Remove from seen-set so a future class load from the same JAR gets another chance.
    if (!pendingJars.offer(new PendingJar(jarPath, classloaderName))) {
      seenJarPaths.remove(jarPath);
      totalJarsAdmitted.decrementAndGet();
      log.fine("SCA: queue full, dropping JAR (will retry on next class load): " + jarPath);
    }
  }

  /**
   * Converts a {@link CodeSource} location URL to an absolute filesystem path. Handles the common
   * {@code file:/path/to/foo.jar} form produced by most classloaders.
   */
  static String locationToJarPath(URL location) {
    try {
      if ("file".equals(location.getProtocol())) {
        // Use URI to correctly handle spaces (%20) and other encoded chars
        return new File(location.toURI()).getAbsolutePath();
      }
      // jar:file:/path/to/outer.jar!/  — nested JAR (Spring Boot, etc.)
      if ("jar".equals(location.getProtocol())) {
        String path = location.getPath(); // file:/path/to/outer.jar!/
        int bang = path.indexOf('!');
        if (bang >= 0) {
          path = path.substring(0, bang);
        }
        return new File(new URI(path)).getAbsolutePath();
      }
    } catch (Exception ignored) {
      // Malformed URL — skip silently
    }
    return null;
  }

  private void scanAlreadyLoadedClasses() {
    try {
      for (Class<?> cls : instrumentation.getAllLoadedClasses()) {
        ClassLoader loader = cls.getClassLoader();
        if (loader == null) {
          continue; // bootstrap
        }
        enqueueFromProtectionDomain(loader, cls.getProtectionDomain());
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: error scanning already-loaded classes", e);
    }
  }

  // ---- Background processing ---------------------------------------------

  private void processQueue() {
    // FIX 5: set schemaUrl and instrumentationVersion on the OTel logger
    Logger otelLogger = openTelemetry
        .getLogsBridge()
        .loggerBuilder("co.elastic.otel.sca")
        .setSchemaUrl(OTEL_SCHEMA_URL)
        .setInstrumentationVersion(resourceCtx.agentVersion)
        .build();

    // Token-bucket style rate limiter: track the earliest time the next JAR may be emitted
    long nextEmitNanos = System.nanoTime();
    long intervalNanos =
        config.getJarsPerSecond() > 0 ? (1_000_000_000L / config.getJarsPerSecond()) : 0L;

    while (!stopped.get()) {
      PendingJar pending;
      try {
        pending = pendingJars.poll(1L, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
      if (pending == null) {
        continue;
      }

      // Rate limit: wait until the next emission slot is available
      if (intervalNanos > 0) {
        long now = System.nanoTime();
        long delay = nextEmitNanos - now;
        if (delay > 0) {
          try {
            TimeUnit.NANOSECONDS.sleep(delay);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            break;
          }
        }
        nextEmitNanos = Math.max(System.nanoTime(), nextEmitNanos) + intervalNanos;
      }

      processJar(pending, otelLogger);
    }

    // Drain remaining entries during shutdown
    PendingJar remaining;
    while ((remaining = pendingJars.poll()) != null) {
      processJar(remaining, otelLogger);
    }
    log.fine("SCA: processing thread stopped");
  }

  private void processJar(PendingJar pending, Logger otelLogger) {
    try {
      JarMetadata meta = JarMetadataExtractor.extract(pending.jarPath, pending.classloaderName);
      if (meta != null) {
        emitLogRecord(meta, otelLogger);
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: error processing JAR: " + pending.jarPath, e);
    }
  }

  private void emitLogRecord(JarMetadata meta, Logger otelLogger) {
    // FIX 6: descriptive body format
    String coords = meta.groupId.isEmpty()
        ? meta.name + ":" + meta.version
        : meta.groupId + ":" + meta.name + ":" + meta.version;
    String body = "JAR loaded: " + coords + " path=" + meta.jarPath;

    AttributesBuilder attrs = Attributes.builder()
        // Library identity (FIX 1)
        .put(ATTR_LIBRARY_NAME, meta.name)
        .put(ATTR_LIBRARY_VERSION, meta.version)
        .put(ATTR_LIBRARY_GROUP_ID, meta.groupId)
        .put(ATTR_LIBRARY_TYPE, "jar")
        .put(ATTR_LIBRARY_LANGUAGE, "java")
        .put(ATTR_LIBRARY_PATH, meta.jarPath)
        .put(ATTR_LIBRARY_PURL, meta.purl)
        .put(ATTR_LIBRARY_SHA256, meta.sha256)
        .put(ATTR_LIBRARY_CHECKSUM_SHA256, meta.sha256)
        .put(ATTR_LIBRARY_CLASSLOADER, meta.classloaderName)
        // Event identity (FIX 4)
        .put(ATTR_EVENT_NAME, "co.elastic.otel.sca.library.loaded")
        .put(ATTR_EVENT_DOMAIN, "sca")
        .put(ATTR_EVENT_ACTION, "library-loaded")
        // Service identity (FIX 3)
        .put(ATTR_SERVICE_NAME, resourceCtx.serviceName)
        .put(ATTR_SERVICE_VERSION, resourceCtx.serviceVersion)
        // Deployment (FIX 2)
        .put(ATTR_DEPLOYMENT_ENV, resourceCtx.deploymentEnv)
        // Host and process (FIX 1 + 3)
        .put(ATTR_HOST_NAME, resourceCtx.hostName)
        .put(ATTR_PROCESS_PID, resourceCtx.processPid)
        .put(ATTR_PROCESS_RUNTIME_NAME, resourceCtx.processRuntimeName)
        .put(ATTR_PROCESS_RUNTIME_VERSION, resourceCtx.processRuntimeVersion)
        // Agent identity (FIX 7)
        .put(ATTR_AGENT_NAME, "elastic-otel-java")
        .put(ATTR_AGENT_TYPE, "opentelemetry")
        .put(ATTR_AGENT_VERSION, resourceCtx.agentVersion)
        .put(ATTR_AGENT_EPHEMERAL_ID, resourceCtx.ephemeralId);

    // Container / k8s — only emit when present (FIX 8)
    if (!resourceCtx.containerId.isEmpty()) {
      attrs.put(ATTR_CONTAINER_ID, resourceCtx.containerId);
    }
    if (!resourceCtx.k8sPodName.isEmpty()) {
      attrs.put(ATTR_K8S_POD_NAME, resourceCtx.k8sPodName);
      attrs.put(ATTR_K8S_NAMESPACE, resourceCtx.k8sNamespace);
      attrs.put(ATTR_K8S_NODE_NAME, resourceCtx.k8sNodeName);
    }

    otelLogger
        .logRecordBuilder()
        .setTimestamp(System.currentTimeMillis(), TimeUnit.MILLISECONDS)
        .setBody(body)
        .setAllAttributes(attrs.build())
        .emit();
  }

  // ---- Filtering ---------------------------------------------------------

  private boolean shouldSkip(String jarPath) {
    // Always skip the EDOT / upstream OTel agent JAR
    String fileName = new File(jarPath).getName();
    if (fileName.contains("elastic-otel-javaagent") || fileName.contains("opentelemetry-javaagent")) {
      return true;
    }
    if (agentJarPath != null && agentJarPath.equals(jarPath)) {
      return true;
    }
    // Skip temp JARs (e.g. JRuby, Groovy, or Spring Boot's exploded cache)
    if (config.isSkipTempJars()) {
      String normPath = normalise(jarPath);
      if (normPath.startsWith(tmpDir) || normPath.contains("/tmp/")) {
        return true;
      }
    }
    return false;
  }

  // ---- Utilities ---------------------------------------------------------

  /**
   * Best-effort: resolve the path of the agent JAR so we can exclude it from reporting. The test
   * harness in {@code custom} sets {@code elastic.otel.agent.jar.path}; in production we scan
   * the command line.
   */
  private static String resolveAgentJarPath() {
    String path = System.getProperty("elastic.otel.agent.jar.path");
    if (path != null) {
      return normalise(path);
    }
    // Fallback: parse -javaagent flag from the JVM command line
    String cmd = System.getProperty("sun.java.command", "");
    for (String token : cmd.split("\\s+")) {
      if (token.contains("elastic-otel-javaagent") || token.contains("opentelemetry-javaagent")) {
        return normalise(token);
      }
    }
    return null;
  }

  private static String normalise(String path) {
    return path.replace('\\', '/');
  }

  // ---- Inner types -------------------------------------------------------

  /** Lightweight holder placed in the pending queue. */
  private static final class PendingJar {
    final String jarPath;
    final String classloaderName;

    PendingJar(String jarPath, String classloaderName) {
      this.jarPath = jarPath;
      this.classloaderName = classloaderName;
    }
  }

  /**
   * Pre-extracted context attributes that are identical for every log record emitted by this
   * service instance. Built once at startup in {@link SCAExtension#afterAgent} and passed into
   * the constructor, avoiding repeated system-property lookups on the hot path.
   */
  static final class ResourceContext {
    final String deploymentEnv;
    final String serviceName;
    final String serviceVersion;
    final String hostName;
    final String processPid;
    final String processRuntimeName;
    final String processRuntimeVersion;
    final String agentVersion;
    final String ephemeralId;
    final String containerId;
    final String k8sPodName;
    final String k8sNamespace;
    final String k8sNodeName;

    private ResourceContext(
        String deploymentEnv, String serviceName, String serviceVersion,
        String hostName, String processPid, String processRuntimeName,
        String processRuntimeVersion, String agentVersion, String ephemeralId,
        String containerId, String k8sPodName, String k8sNamespace, String k8sNodeName) {
      this.deploymentEnv = deploymentEnv;
      this.serviceName = serviceName;
      this.serviceVersion = serviceVersion;
      this.hostName = hostName;
      this.processPid = processPid;
      this.processRuntimeName = processRuntimeName;
      this.processRuntimeVersion = processRuntimeVersion;
      this.agentVersion = agentVersion;
      this.ephemeralId = ephemeralId;
      this.containerId = containerId;
      this.k8sPodName = k8sPodName;
      this.k8sNamespace = k8sNamespace;
      this.k8sNodeName = k8sNodeName;
    }

    /**
     * Builds the context by reading system properties, environment variables, and best-effort
     * reflection on the SDK resource for container / k8s fields.
     */
    static ResourceContext build(AutoConfiguredOpenTelemetrySdk sdk, String ephemeralId) {
      String deploymentEnv = resolveDeploymentEnv();
      String serviceName = coalesce(
          System.getProperty("otel.service.name"),
          System.getenv("OTEL_SERVICE_NAME"),
          "unknown_service");
      String serviceVersion = coalesce(
          System.getProperty("otel.service.version"),
          System.getenv("OTEL_SERVICE_VERSION"),
          "");
      String hostName = resolveHostName();
      String processPid = resolveProcessPid();
      String processRuntimeName = coalesce(System.getProperty("java.runtime.name"), "");
      String processRuntimeVersion = coalesce(System.getProperty("java.runtime.version"), "");
      String agentVersion = resolveAgentVersion();

      // Best-effort: extract container / k8s context from the SDK resource via reflection.
      // AutoConfiguredOpenTelemetrySdk.getResource() is package-private; we use reflection so
      // the extension continues to work if the internal API changes.
      String containerId = "";
      String k8sPodName = "";
      String k8sNamespace = "";
      String k8sNodeName = "";
      try {
        java.lang.reflect.Method getResource =
            sdk.getClass().getDeclaredMethod("getResource");
        getResource.setAccessible(true);
        Resource resource = (Resource) getResource.invoke(sdk);
        containerId = resourceAttr(resource, "container.id");
        k8sPodName = resourceAttr(resource, "k8s.pod.name");
        k8sNamespace = resourceAttr(resource, "k8s.namespace.name");
        k8sNodeName = resourceAttr(resource, "k8s.node.name");
      } catch (Exception ignored) {
        // Resource not accessible — container/k8s fields remain empty
      }

      return new ResourceContext(
          deploymentEnv, serviceName, serviceVersion, hostName, processPid,
          processRuntimeName, processRuntimeVersion, agentVersion, ephemeralId,
          containerId, k8sPodName, k8sNamespace, k8sNodeName);
    }

    private static String resourceAttr(Resource resource, String key) {
      Object val = resource.getAttribute(AttributeKey.stringKey(key));
      String s = val != null ? val.toString() : "";
      return "null".equals(s) ? "" : s;
    }

    /**
     * Reads deployment.environment.name from (in priority order):
     * system property, env var, then the {@code otel.resource.attributes} bag.
     */
    private static String resolveDeploymentEnv() {
      String v = System.getProperty("deployment.environment.name");
      if (v != null && !v.isEmpty()) return v;
      v = System.getenv("DEPLOYMENT_ENVIRONMENT_NAME");
      if (v != null && !v.isEmpty()) return v;
      // Fallback: try older OTel key
      v = System.getProperty("deployment.environment");
      if (v != null && !v.isEmpty()) return v;
      v = System.getenv("DEPLOYMENT_ENVIRONMENT");
      if (v != null && !v.isEmpty()) return v;
      // Last resort: parse otel.resource.attributes
      return parseResourceAttribute("deployment.environment.name",
          parseResourceAttribute("deployment.environment", ""));
    }

    /** Parses a single key from the {@code key1=val1,key2=val2} resource attributes string. */
    private static String parseResourceAttribute(String key, String defaultValue) {
      String bag = coalesce(
          System.getProperty("otel.resource.attributes"),
          System.getenv("OTEL_RESOURCE_ATTRIBUTES"),
          "");
      for (String pair : bag.split(",")) {
        int eq = pair.indexOf('=');
        if (eq > 0 && pair.substring(0, eq).trim().equals(key)) {
          return pair.substring(eq + 1).trim();
        }
      }
      return defaultValue;
    }

    private static String resolveHostName() {
      try {
        return InetAddress.getLocalHost().getHostName();
      } catch (Exception e) {
        return coalesce(System.getenv("HOSTNAME"), "");
      }
    }

    private static String resolveProcessPid() {
      try {
        // ManagementFactory name format: "pid@hostname"
        String name = ManagementFactory.getRuntimeMXBean().getName();
        int at = name.indexOf('@');
        return at > 0 ? name.substring(0, at) : name;
      } catch (Exception e) {
        return "";
      }
    }

    /**
     * Reads the EDOT / OTel agent version via reflection on
     * {@code io.opentelemetry.javaagent.tooling.AgentVersion}, which lives in the agent
     * classloader at runtime even though it is not a compile-time dependency.
     */
    private static String resolveAgentVersion() {
      try {
        Class<?> cls = Class.forName("io.opentelemetry.javaagent.tooling.AgentVersion");
        Object v = cls.getField("VERSION").get(null);
        return v != null && !v.toString().isEmpty() ? v.toString() : "";
      } catch (Exception e) {
        return "";
      }
    }

    private static String coalesce(String... values) {
      for (String v : values) {
        if (v != null && !v.isEmpty()) return v;
      }
      return "";
    }
  }
}
