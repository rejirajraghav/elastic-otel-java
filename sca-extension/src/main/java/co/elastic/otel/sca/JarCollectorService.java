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
import java.net.URLClassLoader;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.logging.Level;

/**
 * Core SCA service that intercepts class loading, extracts JAR metadata asynchronously, and emits
 * one OTel log event per unique JAR (or per embedded library in shaded JARs) to the {@code
 * co.elastic.otel.sca} instrumentation scope.
 *
 * <p>Design constraints:
 *
 * <ul>
 *   <li>The {@link ClassFileTransformer#transform} method always returns {@code null} — bytecode is
 *       never modified.
 *   <li>Class-loading threads are never blocked; all I/O happens on a single daemon background
 *       thread.
 *   <li>Discovery uses {@link ProtectionDomain#getCodeSource()} for filesystem JARs and {@link
 *       URLClassLoader#getURLs()} for nested JAR detection (Spring Boot fat JARs).
 *   <li>Startup classpath and JPMS module layer are eagerly scanned before the transformer
 *       registers so no JARs are missed.
 *   <li>Periodic re-harvest rescans known classloaders and the classpath for dynamic deployments
 *       (OSGi bundle installs, servlet hot-deploy).
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
  private static final AttributeKey<String> ATTR_LIBRARY_MODULE_TYPE =
      AttributeKey.stringKey("library.module_type");
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
  private static final AttributeKey<String> ATTR_LIBRARY_SHA1 =
      AttributeKey.stringKey("library.sha1");
  private static final AttributeKey<String> ATTR_LIBRARY_CHECKSUM_SHA1 =
      AttributeKey.stringKey("library.checksum.sha1");
  private static final AttributeKey<String> ATTR_LIBRARY_ID = AttributeKey.stringKey("library.id");
  private static final AttributeKey<String> ATTR_LIBRARY_CLASSLOADER =
      AttributeKey.stringKey("library.classloader");
  private static final AttributeKey<Boolean> ATTR_LIBRARY_SHADED =
      AttributeKey.booleanKey("library.shaded");
  private static final AttributeKey<String> ATTR_LIBRARY_LICENSE =
      AttributeKey.stringKey("library.license");

  // Event identity
  private static final AttributeKey<String> ATTR_EVENT_NAME = AttributeKey.stringKey("event.name");
  private static final AttributeKey<String> ATTR_EVENT_DOMAIN =
      AttributeKey.stringKey("event.domain");
  private static final AttributeKey<String> ATTR_EVENT_ACTION =
      AttributeKey.stringKey("event.action");

  // Service identity
  private static final AttributeKey<String> ATTR_SERVICE_NAME =
      AttributeKey.stringKey("service.name");
  private static final AttributeKey<String> ATTR_SERVICE_VERSION =
      AttributeKey.stringKey("service.version");

  // Deployment
  private static final AttributeKey<String> ATTR_DEPLOYMENT_ENV =
      AttributeKey.stringKey("deployment.environment.name");

  // Host and process
  private static final AttributeKey<String> ATTR_HOST_NAME = AttributeKey.stringKey("host.name");
  private static final AttributeKey<String> ATTR_PROCESS_PID =
      AttributeKey.stringKey("process.pid");
  private static final AttributeKey<String> ATTR_PROCESS_RUNTIME_NAME =
      AttributeKey.stringKey("process.runtime.name");
  private static final AttributeKey<String> ATTR_PROCESS_RUNTIME_VERSION =
      AttributeKey.stringKey("process.runtime.version");

  // Agent identity
  private static final AttributeKey<String> ATTR_AGENT_NAME = AttributeKey.stringKey("agent.name");
  private static final AttributeKey<String> ATTR_AGENT_TYPE = AttributeKey.stringKey("agent.type");
  private static final AttributeKey<String> ATTR_AGENT_VERSION =
      AttributeKey.stringKey("agent.version");
  private static final AttributeKey<String> ATTR_AGENT_EPHEMERAL_ID =
      AttributeKey.stringKey("agent.ephemeral_id");

  // Container / k8s
  private static final AttributeKey<String> ATTR_CONTAINER_ID =
      AttributeKey.stringKey("container.id");
  private static final AttributeKey<String> ATTR_K8S_POD_NAME =
      AttributeKey.stringKey("k8s.pod.name");
  private static final AttributeKey<String> ATTR_K8S_NAMESPACE =
      AttributeKey.stringKey("k8s.namespace.name");
  private static final AttributeKey<String> ATTR_K8S_NODE_NAME =
      AttributeKey.stringKey("k8s.node.name");

  // ---- Internal state ----------------------------------------------------

  private static final int QUEUE_CAPACITY = 500;

  private final OpenTelemetrySdk openTelemetry;
  private final Instrumentation instrumentation;
  private final SCAConfiguration config;
  private final ResourceContext resourceCtx;

  /** Dedup set for both filesystem paths and URL strings. */
  private final Set<String> seenJarPaths = ConcurrentHashMap.newKeySet();

  /**
   * Classloaders already scanned for URL-based JAR discovery. Prevents rescanning the same
   * URLClassLoader on every class load from it.
   */
  final Set<ClassLoader> seenClassLoaders = ConcurrentHashMap.newKeySet();

  private final AtomicInteger totalJarsAdmitted = new AtomicInteger(0);

  private final LinkedBlockingQueue<PendingJar> pendingJars =
      new LinkedBlockingQueue<>(QUEUE_CAPACITY);

  private final AtomicBoolean started = new AtomicBoolean(false);
  private final AtomicBoolean stopped = new AtomicBoolean(false);

  /**
   * Rate limiter state shared across the single background thread: earliest time the next emit slot
   * is available (nanoseconds). Accessed only by the background worker thread.
   */
  private long nextEmitNanos = System.nanoTime();

  private final String agentJarPath;
  private final String tmpDir;

  /** Daemon scheduler for periodic re-harvest. Null when re-harvest is disabled. */
  private ScheduledExecutorService reharvestScheduler;

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

    instrumentation.addTransformer(this, /* canRetransform= */ false);
    scanAlreadyLoadedClasses();

    Thread worker = new Thread(this::processQueue, "elastic-sca-jar-collector");
    worker.setDaemon(true);
    worker.setPriority(Thread.MIN_PRIORITY);
    worker.start();

    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  stopped.set(true);
                  worker.interrupt();
                  if (reharvestScheduler != null) {
                    reharvestScheduler.shutdown();
                  }
                },
                "elastic-sca-shutdown"));

    log.fine("SCA: JarCollectorService started");
  }

  // ---- Periodic re-harvest -----------------------------------------------

  /**
   * Starts a daemon thread that periodically rescans known classloaders and the startup classpath
   * for newly added JARs (OSGi bundle installs, servlet hot-deploy, dynamic classpath additions).
   *
   * @param intervalSeconds seconds between re-harvest runs; 0 or negative disables the scheduler
   */
  void startReharvest(int intervalSeconds) {
    if (intervalSeconds <= 0) {
      return;
    }
    reharvestScheduler =
        Executors.newSingleThreadScheduledExecutor(
            r -> {
              Thread t = new Thread(r, "elastic-sca-reharvest");
              t.setDaemon(true);
              return t;
            });
    reharvestScheduler.scheduleAtFixedRate(
        this::reharvest, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    log.fine("SCA: re-harvest scheduled every " + intervalSeconds + "s");
  }

  private void reharvest() {
    if (stopped.get()) {
      return;
    }
    log.fine("SCA: running periodic re-harvest");
    // Re-scan all known URLClassLoaders for any new URLs
    for (ClassLoader loader : seenClassLoaders) {
      if (loader instanceof URLClassLoader) {
        enqueueClassLoaderUrls((URLClassLoader) loader);
      }
    }
    // Re-check startup classpath in case entries were added dynamically
    if (config.isScanStartupClasspath()) {
      scanStartupClasspath();
    }
  }

  // ---- Startup scanning --------------------------------------------------

  /**
   * Eagerly enqueues JARs declared on the JVM classpath before the ClassFileTransformer registers.
   * This catches JARs whose classes may never be loaded (optional dependencies) and ensures Spring
   * Boot fat JARs delegating to system classloaders are discovered.
   */
  void scanStartupClasspath() {
    enqueueClasspathString(System.getProperty("java.class.path", ""));

    try {
      enqueueClasspathString(ManagementFactory.getRuntimeMXBean().getClassPath());
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: could not read runtime classpath from ManagementFactory", e);
    }

    ClassLoader systemCl = ClassLoader.getSystemClassLoader();
    if (systemCl instanceof URLClassLoader) {
      enqueueClassLoaderUrls((URLClassLoader) systemCl);
    }
  }

  private void enqueueClasspathString(String classpath) {
    if (classpath == null || classpath.isEmpty()) {
      return;
    }
    for (String entry : classpath.split(File.pathSeparator)) {
      if (entry.endsWith(".jar")) {
        enqueueJarPath(entry, "classpath");
      }
    }
  }

  /**
   * Scans the JPMS module layer (Java 9+) to discover module-path JARs. Uses reflection for Java 8
   * source compatibility.
   */
  void scanModuleLayer() {
    try {
      Class<?> moduleLayerClass = Class.forName("java.lang.ModuleLayer");
      Object bootLayer = moduleLayerClass.getMethod("boot").invoke(null);
      Set<?> modules = (Set<?>) moduleLayerClass.getMethod("modules").invoke(bootLayer);
      Class<?> moduleClass = Class.forName("java.lang.Module");

      for (Object module : modules) {
        try {
          // Discover via classloader if it is a URLClassLoader
          ClassLoader cl = (ClassLoader) moduleClass.getMethod("getClassLoader").invoke(module);
          if (cl instanceof URLClassLoader && seenClassLoaders.add(cl)) {
            enqueueClassLoaderUrls((URLClassLoader) cl);
          }

          // Discover via module descriptor name + location
          Object descriptor = moduleClass.getMethod("getDescriptor").invoke(module);
          if (descriptor == null) {
            continue;
          }
          Class<?> descClass = Class.forName("java.lang.module.ModuleDescriptor");
          String moduleName = (String) descClass.getMethod("name").invoke(descriptor);

          // Skip JDK built-in modules
          if (moduleName.startsWith("java.")
              || moduleName.startsWith("jdk.")
              || moduleName.startsWith("sun.")) {
            continue;
          }

          // Try to get the JAR location via ModuleLayer.configuration()
          Object configuration = moduleLayerClass.getMethod("configuration").invoke(bootLayer);
          Class<?> configClass = Class.forName("java.lang.module.Configuration");
          java.util.Optional<?> moduleRef =
              (java.util.Optional<?>)
                  configClass
                      .getMethod("findModule", String.class)
                      .invoke(configuration, moduleName);
          if (!moduleRef.isPresent()) {
            continue;
          }
          Class<?> resolvedModuleClass = Class.forName("java.lang.module.ResolvedModule");
          Object resolvedModule = moduleRef.get();
          Object reference = resolvedModuleClass.getMethod("reference").invoke(resolvedModule);
          Class<?> moduleRefClass = Class.forName("java.lang.module.ModuleReference");
          java.util.Optional<?> locationOpt =
              (java.util.Optional<?>) moduleRefClass.getMethod("location").invoke(reference);
          if (!locationOpt.isPresent()) {
            continue;
          }
          java.net.URI moduleUri = (java.net.URI) locationOpt.get();
          String scheme = moduleUri.getScheme();
          if ("file".equals(scheme)) {
            File jarFile = new File(moduleUri);
            if (jarFile.getName().endsWith(".jar")) {
              enqueueJarPath(jarFile.getAbsolutePath(), "jpms-module");
            }
          }
        } catch (Exception ignored) {
        }
      }
    } catch (ClassNotFoundException e) {
      // Java 8: no module system — nothing to do
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: module layer scan failed (non-critical)", e);
    }
  }

  // ---- ClassFileTransformer ----------------------------------------------

  @Override
  public byte[] transform(
      ClassLoader loader,
      String className,
      Class<?> classBeingRedefined,
      ProtectionDomain protectionDomain,
      byte[] classfileBuffer) {
    if (loader == null || className == null || stopped.get()) {
      return null;
    }
    try {
      enqueueFromProtectionDomain(loader, protectionDomain);

      if (loader instanceof URLClassLoader && seenClassLoaders.add(loader)) {
        enqueueClassLoaderUrls((URLClassLoader) loader);
      }
    } catch (Exception ignored) {
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

    String urlStr = location.toString();
    if (urlStr.startsWith("jar:nested:")) {
      enqueueUrl(location, loader.getClass().getName());
      return;
    }

    String jarPath = locationToJarPath(location);
    if (jarPath == null || !jarPath.endsWith(".jar")) {
      return;
    }
    enqueueJarPath(jarPath, loader.getClass().getName());
  }

  private void enqueueClassLoaderUrls(URLClassLoader loader) {
    try {
      URL[] urls = loader.getURLs();
      String classloaderName = loader.getClass().getName();
      for (URL url : urls) {
        String urlStr = url.toString();
        if (isJarUrl(urlStr)) {
          if (urlStr.startsWith("file:") && urlStr.endsWith(".jar")) {
            try {
              String path = new File(url.toURI()).getAbsolutePath();
              enqueueJarPath(path, classloaderName);
              continue;
            } catch (Exception ignored) {
            }
          }
          enqueueUrl(url, classloaderName);
        }
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: failed to scan classloader URLs", e);
    }
  }

  private boolean isJarUrl(String urlStr) {
    return (urlStr.endsWith(".jar")
            || urlStr.endsWith(".jar!/")
            || urlStr.contains(".jar!/")
            || urlStr.contains(".jar/!"))
        && !shouldSkipKey(urlStr);
  }

  void enqueueJarPath(String jarPath, String classloaderName) {
    if (shouldSkip(jarPath)) {
      return;
    }
    admitAndOffer(jarPath, new PendingJar(jarPath, classloaderName));
  }

  private void enqueueUrl(URL url, String classloaderName) {
    String key = url.toString();
    if (shouldSkipKey(key)) {
      return;
    }
    admitAndOffer(key, new PendingJar(url, classloaderName));
  }

  private void admitAndOffer(String key, PendingJar jar) {
    if (totalJarsAdmitted.get() >= config.getMaxJarsTotal()) {
      return;
    }
    if (!seenJarPaths.add(key)) {
      return;
    }
    totalJarsAdmitted.incrementAndGet();
    if (!pendingJars.offer(jar)) {
      seenJarPaths.remove(key);
      totalJarsAdmitted.decrementAndGet();
      log.fine("SCA: queue full, dropping: " + key);
    }
  }

  /**
   * Converts a {@link CodeSource} location URL to an absolute filesystem path. Handles {@code
   * file://}, {@code jar:file://}, and {@code jar:nested://} (Spring Boot 3.2+).
   */
  static String locationToJarPath(URL location) {
    try {
      if ("file".equals(location.getProtocol())) {
        return new File(location.toURI()).getAbsolutePath();
      }
      if ("jar".equals(location.getProtocol())) {
        String path = location.getPath();
        if (path.startsWith("nested:")) {
          int separator = path.indexOf("/!");
          String outerPart =
              (separator > 0) ? path.substring("nested://".length(), separator) : path;
          if (outerPart.endsWith("/")) {
            outerPart = outerPart.substring(0, outerPart.length() - 1);
          }
          return outerPart;
        }
        int bang = path.indexOf('!');
        if (bang >= 0) {
          path = path.substring(0, bang);
        }
        return new File(new URI(path)).getAbsolutePath();
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  private void scanAlreadyLoadedClasses() {
    try {
      Set<ClassLoader> seen = ConcurrentHashMap.newKeySet();
      for (Class<?> cls : instrumentation.getAllLoadedClasses()) {
        ClassLoader loader = cls.getClassLoader();
        if (loader == null) {
          continue;
        }
        enqueueFromProtectionDomain(loader, cls.getProtectionDomain());
        if (loader instanceof URLClassLoader && seen.add(loader)) {
          enqueueClassLoaderUrls((URLClassLoader) loader);
        }
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: error scanning already-loaded classes", e);
    }
  }

  // ---- Background processing ---------------------------------------------

  private void processQueue() {
    Logger otelLogger =
        openTelemetry
            .getLogsBridge()
            .loggerBuilder("co.elastic.otel.sca")
            .setSchemaUrl(OTEL_SCHEMA_URL)
            .setInstrumentationVersion(resourceCtx.agentVersion)
            .build();

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
      processJar(pending, otelLogger);
    }

    PendingJar remaining;
    while ((remaining = pendingJars.poll()) != null) {
      processJar(remaining, otelLogger);
    }
    log.fine("SCA: processing thread stopped");
  }

  private void processJar(PendingJar pending, Logger otelLogger) {
    try {
      List<JarMetadata> metas;
      if (pending.jarUrl != null) {
        JarMetadata meta =
            JarMetadataExtractor.extractFromUrl(pending.jarUrl, pending.classloaderName);
        metas = java.util.Collections.singletonList(meta);
      } else {
        metas = JarMetadataExtractor.extract(pending.jarPath, pending.classloaderName);
        // Honour detect_shaded_jars flag: if disabled, use only the first entry
        if (!config.isDetectShadedJars() && metas.size() > 1) {
          metas = metas.subList(0, 1);
        }
      }

      for (JarMetadata meta : metas) {
        // Apply rate limiting per emitted event (important for shaded JARs with many entries)
        applyRateLimit();
        if (stopped.get()) {
          break;
        }
        emitLogRecord(meta, otelLogger);
      }

      // Priority 6: Follow MANIFEST Class-Path entries (one level deep)
      if (config.isFollowManifestClasspath() && pending.jarPath != null) {
        followClassPathEntries(pending.jarPath);
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: error processing JAR: " + pending.dedupeKey, e);
    }
  }

  /**
   * Applies per-event rate limiting. Must be called only from the single background worker thread.
   */
  private void applyRateLimit() {
    if (config.getJarsPerSecond() <= 0) {
      return;
    }
    long intervalNanos = 1_000_000_000L / config.getJarsPerSecond();
    long now = System.nanoTime();
    long delay = nextEmitNanos - now;
    if (delay > 0) {
      try {
        TimeUnit.NANOSECONDS.sleep(delay);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    nextEmitNanos = Math.max(System.nanoTime(), nextEmitNanos) + intervalNanos;
  }

  /**
   * Reads the {@code Class-Path} manifest attribute of the given JAR and enqueues any referenced
   * JARs that exist on the filesystem. Only one level deep — no recursive following.
   */
  private void followClassPathEntries(String jarPath) {
    File jarFile = new File(jarPath);
    if (!jarFile.exists()) {
      return;
    }
    try (JarFile jar = new JarFile(jarFile, /* verify= */ false)) {
      Manifest manifest = jar.getManifest();
      if (manifest == null) {
        return;
      }
      String classPath = manifest.getMainAttributes().getValue("Class-Path");
      if (classPath == null || classPath.isEmpty()) {
        return;
      }
      String jarDir = jarFile.getParent();
      if (jarDir == null) {
        return;
      }
      for (String entry : classPath.split("\\s+")) {
        if (entry.endsWith(".jar")) {
          File resolved = new File(jarDir, entry);
          if (resolved.exists() && resolved.isFile()) {
            enqueueJarPath(resolved.getAbsolutePath(), "manifest-classpath");
          }
        }
      }
    } catch (Exception e) {
      log.log(Level.FINE, "SCA: Class-Path follow failed for " + jarPath, e);
    }
  }

  private void emitLogRecord(JarMetadata meta, Logger otelLogger) {
    String coords =
        meta.groupId.isEmpty()
            ? meta.name + ":" + meta.version
            : meta.groupId + ":" + meta.name + ":" + meta.version;
    String body = "JAR loaded: " + coords + " path=" + meta.jarPath;

    String libraryId =
        meta.groupId.isEmpty()
            ? meta.name + ":" + meta.version
            : meta.groupId + ":" + meta.name + ":" + meta.version;

    AttributesBuilder attrs =
        Attributes.builder()
            .put(ATTR_LIBRARY_NAME, meta.name)
            .put(ATTR_LIBRARY_VERSION, meta.version)
            .put(ATTR_LIBRARY_GROUP_ID, meta.groupId)
            .put(ATTR_LIBRARY_ID, libraryId)
            .put(ATTR_LIBRARY_TYPE, "jar")
            .put(ATTR_LIBRARY_MODULE_TYPE, meta.moduleType)
            .put(ATTR_LIBRARY_LANGUAGE, "java")
            .put(ATTR_LIBRARY_PATH, meta.jarPath)
            .put(ATTR_LIBRARY_PURL, meta.purl)
            .put(ATTR_LIBRARY_SHA256, meta.sha256)
            .put(ATTR_LIBRARY_CHECKSUM_SHA256, meta.sha256)
            .put(ATTR_LIBRARY_SHA1, meta.sha1)
            .put(ATTR_LIBRARY_CHECKSUM_SHA1, meta.sha1)
            .put(ATTR_LIBRARY_CLASSLOADER, meta.classloaderName)
            .put(ATTR_LIBRARY_SHADED, meta.shaded)
            .put(ATTR_EVENT_NAME, "co.elastic.otel.sca.library.loaded")
            .put(ATTR_EVENT_DOMAIN, "sca")
            .put(ATTR_EVENT_ACTION, "library-loaded")
            .put(ATTR_SERVICE_NAME, resourceCtx.serviceName)
            .put(ATTR_SERVICE_VERSION, resourceCtx.serviceVersion)
            .put(ATTR_DEPLOYMENT_ENV, resourceCtx.deploymentEnv)
            .put(ATTR_HOST_NAME, resourceCtx.hostName)
            .put(ATTR_PROCESS_PID, resourceCtx.processPid)
            .put(ATTR_PROCESS_RUNTIME_NAME, resourceCtx.processRuntimeName)
            .put(ATTR_PROCESS_RUNTIME_VERSION, resourceCtx.processRuntimeVersion)
            .put(ATTR_AGENT_NAME, "elastic-otel-java")
            .put(ATTR_AGENT_TYPE, "opentelemetry")
            .put(ATTR_AGENT_VERSION, resourceCtx.agentVersion)
            .put(ATTR_AGENT_EPHEMERAL_ID, resourceCtx.ephemeralId);

    // Emit license only when detected
    if (!meta.license.isEmpty()) {
      attrs.put(ATTR_LIBRARY_LICENSE, meta.license);
    }

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
    if (jarPath == null) {
      return true;
    }
    String fileName = new File(jarPath).getName();
    String lower = fileName.toLowerCase();

    // Always skip agent JARs
    if (lower.contains("elastic-otel-javaagent") || lower.contains("opentelemetry-javaagent")) {
      return true;
    }
    if (agentJarPath != null && agentJarPath.equals(normalise(jarPath))) {
      return true;
    }

    // Always skip source and javadoc JARs (no executable code)
    if (lower.endsWith("-sources.jar")
        || lower.endsWith("-javadoc.jar")
        || lower.endsWith("-sources-tests.jar")) {
      return true;
    }

    // Optionally skip test JARs
    if (config.isSkipTestJars()) {
      if (lower.endsWith("-tests.jar") || lower.endsWith("-test.jar")) {
        return true;
      }
    }

    // Skip IDE and build tool internals
    String normPath = normalise(jarPath);
    if (normPath.contains("/.gradle/daemon/")
        || normPath.contains("/gradle/wrapper/")
        || normPath.contains("/.m2/wrapper/")) {
      return true;
    }

    // Skip temp directories
    if (config.isSkipTempJars()) {
      if (normPath.startsWith(tmpDir)
          || normPath.contains("/tmp/")
          || normPath.contains("/temp/")) {
        return true;
      }
    }

    return false;
  }

  /** Applies skip rules to a URL or key string (for nested/classpath-derived entries). */
  private boolean shouldSkipKey(String key) {
    if (key == null) {
      return true;
    }
    String lower = key.toLowerCase();
    if (lower.contains("elastic-otel-javaagent") || lower.contains("opentelemetry-javaagent")) {
      return true;
    }
    if (lower.endsWith("-sources.jar")
        || lower.endsWith("-javadoc.jar")
        || lower.endsWith("-sources-tests.jar")) {
      return true;
    }
    if (config.isSkipTestJars()) {
      if (lower.endsWith("-tests.jar") || lower.endsWith("-test.jar")) {
        return true;
      }
    }
    if (config.isSkipTempJars()) {
      String norm = normalise(key);
      if (norm.contains("/tmp/") || norm.contains("/temp/")) {
        return true;
      }
    }
    return false;
  }

  // ---- Utilities ---------------------------------------------------------

  private static String resolveAgentJarPath() {
    String path = System.getProperty("elastic.otel.agent.jar.path");
    if (path != null) {
      return normalise(path);
    }
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

  private static final class PendingJar {
    final String dedupeKey;
    final String jarPath;
    final URL jarUrl;
    final String classloaderName;

    PendingJar(String jarPath, String classloaderName) {
      this.dedupeKey = jarPath;
      this.jarPath = jarPath;
      this.jarUrl = null;
      this.classloaderName = classloaderName;
    }

    PendingJar(URL jarUrl, String classloaderName) {
      this.dedupeKey = jarUrl.toString();
      this.jarPath = null;
      this.jarUrl = jarUrl;
      this.classloaderName = classloaderName;
    }
  }

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
        String deploymentEnv,
        String serviceName,
        String serviceVersion,
        String hostName,
        String processPid,
        String processRuntimeName,
        String processRuntimeVersion,
        String agentVersion,
        String ephemeralId,
        String containerId,
        String k8sPodName,
        String k8sNamespace,
        String k8sNodeName) {
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

    static ResourceContext build(AutoConfiguredOpenTelemetrySdk sdk, String ephemeralId) {
      String deploymentEnv = resolveDeploymentEnv();
      String serviceName =
          coalesce(
              System.getProperty("otel.service.name"),
              System.getenv("OTEL_SERVICE_NAME"),
              "unknown_service");
      String serviceVersion =
          coalesce(
              System.getProperty("otel.service.version"),
              System.getenv("OTEL_SERVICE_VERSION"),
              "");
      String hostName = resolveHostName();
      String processPid = resolveProcessPid();
      String processRuntimeName = coalesce(System.getProperty("java.runtime.name"), "");
      String processRuntimeVersion = coalesce(System.getProperty("java.runtime.version"), "");
      String agentVersion = resolveAgentVersion();

      String containerId = "";
      String k8sPodName = "";
      String k8sNamespace = "";
      String k8sNodeName = "";
      try {
        java.lang.reflect.Method getResource = sdk.getClass().getDeclaredMethod("getResource");
        getResource.setAccessible(true);
        Resource resource = (Resource) getResource.invoke(sdk);
        containerId = resourceAttr(resource, "container.id");
        k8sPodName = resourceAttr(resource, "k8s.pod.name");
        k8sNamespace = resourceAttr(resource, "k8s.namespace.name");
        k8sNodeName = resourceAttr(resource, "k8s.node.name");
      } catch (Exception ignored) {
      }

      return new ResourceContext(
          deploymentEnv,
          serviceName,
          serviceVersion,
          hostName,
          processPid,
          processRuntimeName,
          processRuntimeVersion,
          agentVersion,
          ephemeralId,
          containerId,
          k8sPodName,
          k8sNamespace,
          k8sNodeName);
    }

    private static String resourceAttr(Resource resource, String key) {
      Object val = resource.getAttribute(AttributeKey.stringKey(key));
      String s = val != null ? val.toString() : "";
      return "null".equals(s) ? "" : s;
    }

    private static String resolveDeploymentEnv() {
      String v = System.getProperty("deployment.environment.name");
      if (v != null && !v.isEmpty()) return v;
      v = System.getenv("DEPLOYMENT_ENVIRONMENT_NAME");
      if (v != null && !v.isEmpty()) return v;
      v = System.getProperty("deployment.environment");
      if (v != null && !v.isEmpty()) return v;
      v = System.getenv("DEPLOYMENT_ENVIRONMENT");
      if (v != null && !v.isEmpty()) return v;
      return parseResourceAttribute(
          "deployment.environment.name", parseResourceAttribute("deployment.environment", ""));
    }

    private static String parseResourceAttribute(String key, String defaultValue) {
      String bag =
          coalesce(
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
        String name = ManagementFactory.getRuntimeMXBean().getName();
        int at = name.indexOf('@');
        return at > 0 ? name.substring(0, at) : name;
      } catch (Exception e) {
        return "";
      }
    }

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
