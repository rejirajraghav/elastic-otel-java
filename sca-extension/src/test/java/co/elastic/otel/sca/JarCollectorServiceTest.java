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

import static org.assertj.core.api.Assertions.assertThat;

import io.opentelemetry.sdk.OpenTelemetrySdk;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JarCollectorServiceTest {

  @TempDir File tempDir;

  private final List<String> setProperties = new ArrayList<>();

  @AfterEach
  void clearSysProps() {
    setProperties.forEach(System::clearProperty);
    setProperties.clear();
  }

  private void set(String key, String value) {
    System.setProperty(key, value);
    setProperties.add(key);
  }

  // ---- locationToJarPath ---------------------------------------------------

  @Test
  void fileUrlConvertsToAbsolutePath() throws Exception {
    File f = new File(tempDir, "app.jar");
    assertThat(f.createNewFile()).isTrue();
    URL url = f.toURI().toURL();
    assertThat(JarCollectorService.locationToJarPath(url)).isEqualTo(f.getAbsolutePath());
  }

  @Test
  void jarFileUrlStripsEntryPart() throws Exception {
    File f = new File(tempDir, "app.jar");
    assertThat(f.createNewFile()).isTrue();
    URL url = new URL("jar:file:" + f.getAbsolutePath() + "!/");
    assertThat(JarCollectorService.locationToJarPath(url)).isEqualTo(f.getAbsolutePath());
  }

  @Test
  void fileUrlWithSpacesDecoded() throws Exception {
    File dir = new File(tempDir, "my libs");
    assertThat(dir.mkdirs()).isTrue();
    File f = new File(dir, "app.jar");
    assertThat(f.createNewFile()).isTrue();
    URL url = f.toURI().toURL();
    assertThat(JarCollectorService.locationToJarPath(url)).isEqualTo(f.getAbsolutePath());
  }

  @Test
  void httpUrlReturnsNull() throws Exception {
    URL url = new URL("http://example.com/app.jar");
    assertThat(JarCollectorService.locationToJarPath(url)).isNull();
  }

  // ---- shouldSkip ----------------------------------------------------------

  @Test
  void agentJarByNameIsSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/elastic-otel-javaagent-1.0.jar")).isTrue();
  }

  @Test
  void openTelemetryAgentJarIsSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/opentelemetry-javaagent-1.0.jar")).isTrue();
  }

  @Test
  void sourcesJarIsAlwaysSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/guava-32.0-sources.jar")).isTrue();
  }

  @Test
  void javadocJarIsAlwaysSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/guava-32.0-javadoc.jar")).isTrue();
  }

  @Test
  void sourcesTestsJarIsAlwaysSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/lib-1.0-sources-tests.jar")).isTrue();
  }

  @Test
  void testJarSkippedWhenSkipTestJarsEnabled() throws Exception {
    // default: skipTestJars=true
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/my-service-1.0-tests.jar")).isTrue();
    assertThat(shouldSkip(svc, "/app/my-service-1.0-test.jar")).isTrue();
  }

  @Test
  void testJarNotSkippedWhenSkipTestJarsDisabled() throws Exception {
    set(SCAConfiguration.SKIP_TEST_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/my-service-1.0-tests.jar")).isFalse();
    assertThat(shouldSkip(svc, "/app/my-service-1.0-test.jar")).isFalse();
  }

  @Test
  void gradleWrapperJarIsSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/home/user/gradle/wrapper/dists/gradle-8.0/lib.jar")).isTrue();
  }

  @Test
  void gradleDaemonJarIsSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/home/user/.gradle/daemon/8.0/lib.jar")).isTrue();
  }

  @Test
  void tempJarSkippedWhenSkipTempJarsEnabled() throws Exception {
    // default: skipTempJars=true; /tmp/ is always in path
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/opt/app/tmp/work.jar")).isTrue();
  }

  @Test
  void tempJarNotSkippedWhenSkipTempJarsDisabled() throws Exception {
    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/opt/app/tmp/work.jar")).isFalse();
  }

  @Test
  void normalJarInAppLibIsNotSkipped() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    assertThat(shouldSkip(svc, "/app/lib/guava-32.0.jar")).isFalse();
  }

  // ---- Deduplication -------------------------------------------------------

  @Test
  void samePathEnqueuedOnlyOnce() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.enqueueJarPath("/app/lib/guava.jar", "testloader");
    svc.enqueueJarPath("/app/lib/guava.jar", "testloader");
    assertThat(seenJarPaths(svc)).hasSize(1);
    assertThat(totalJarsAdmitted(svc)).isEqualTo(1);
  }

  @Test
  void differentPathsEnqueuedSeparately() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.enqueueJarPath("/app/lib/guava.jar", "testloader");
    svc.enqueueJarPath("/app/lib/jackson.jar", "testloader");
    assertThat(seenJarPaths(svc)).hasSize(2);
    assertThat(totalJarsAdmitted(svc)).isEqualTo(2);
  }

  @Test
  void maxJarsTotalCapStopsAdmission() throws Exception {
    set(SCAConfiguration.MAX_JARS_TOTAL_KEY, "2");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.enqueueJarPath("/app/lib/a.jar", "testloader");
    svc.enqueueJarPath("/app/lib/b.jar", "testloader");
    svc.enqueueJarPath("/app/lib/c.jar", "testloader"); // should be dropped
    assertThat(totalJarsAdmitted(svc)).isEqualTo(2);
    assertThat(seenJarPaths(svc)).doesNotContain("/app/lib/c.jar");
  }

  // ---- startReharvest ------------------------------------------------------

  @Test
  void reharvestNotStartedWhenIntervalIsZero() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.startReharvest(0);
    assertThat(reharvestScheduler(svc)).isNull();
  }

  @Test
  void reharvestNotStartedWhenIntervalIsNegative() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.startReharvest(-1);
    assertThat(reharvestScheduler(svc)).isNull();
  }

  @Test
  void reharvestStartedWhenIntervalIsPositive() throws Exception {
    JarCollectorService svc = buildService(SCAConfiguration.get());
    svc.startReharvest(60);
    ScheduledExecutorService scheduler = reharvestScheduler(svc);
    assertThat(scheduler).isNotNull();
    scheduler.shutdownNow();
  }

  // ---- followClassPathEntries -----------------------------------------------

  @Test
  void manifestClassPathEntryEnqueuesReferencedJar() throws Exception {
    File depJar = new File(tempDir, "dep.jar");
    buildMinimalJar(depJar);
    File mainJar = new File(tempDir, "main.jar");
    buildJarWithClassPath(mainJar, "dep.jar");

    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    followClassPathEntries(svc, mainJar.getAbsolutePath());

    assertThat(seenJarPaths(svc)).contains(depJar.getAbsolutePath());
  }

  @Test
  void manifestClassPathMissingFileIsIgnored() throws Exception {
    File mainJar = new File(tempDir, "main.jar");
    buildJarWithClassPath(mainJar, "nonexistent.jar");

    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    followClassPathEntries(svc, mainJar.getAbsolutePath()); // must not throw
    assertThat(seenJarPaths(svc)).isEmpty();
  }

  @Test
  void jarWithNoClassPathEntryProducesNoEnqueues() throws Exception {
    File mainJar = new File(tempDir, "main.jar");
    buildMinimalJar(mainJar);

    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    followClassPathEntries(svc, mainJar.getAbsolutePath());
    assertThat(seenJarPaths(svc)).isEmpty();
  }

  @Test
  void nonExistentJarPathIsIgnored() throws Exception {
    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    JarCollectorService svc = buildService(SCAConfiguration.get());
    followClassPathEntries(svc, "/nonexistent/path/app.jar"); // must not throw
    assertThat(seenJarPaths(svc)).isEmpty();
  }

  // ---- Helpers ------------------------------------------------------------

  private JarCollectorService buildService(SCAConfiguration config) throws Exception {
    return new JarCollectorService(
        OpenTelemetrySdk.builder().build(), stubInstrumentation(), config, testResourceContext());
  }

  private static JarCollectorService.ResourceContext testResourceContext() throws Exception {
    Constructor<JarCollectorService.ResourceContext> ctor =
        JarCollectorService.ResourceContext.class.getDeclaredConstructor(
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class,
            String.class);
    ctor.setAccessible(true);
    return ctor.newInstance(
        "test-env",
        "test-service",
        "1.0",
        "localhost",
        "1234",
        "OpenJDK",
        "21",
        "1.9.1-SNAPSHOT",
        "ephemeral-123",
        "",
        "",
        "",
        "");
  }

  private static boolean shouldSkip(JarCollectorService svc, String path) throws Exception {
    Method m = JarCollectorService.class.getDeclaredMethod("shouldSkip", String.class);
    m.setAccessible(true);
    return (boolean) m.invoke(svc, path);
  }

  private static void followClassPathEntries(JarCollectorService svc, String path)
      throws Exception {
    Method m = JarCollectorService.class.getDeclaredMethod("followClassPathEntries", String.class);
    m.setAccessible(true);
    m.invoke(svc, path);
  }

  @SuppressWarnings("unchecked")
  private static Set<String> seenJarPaths(JarCollectorService svc) throws Exception {
    Field f = JarCollectorService.class.getDeclaredField("seenJarPaths");
    f.setAccessible(true);
    return (Set<String>) f.get(svc);
  }

  private static int totalJarsAdmitted(JarCollectorService svc) throws Exception {
    Field f = JarCollectorService.class.getDeclaredField("totalJarsAdmitted");
    f.setAccessible(true);
    return ((AtomicInteger) f.get(svc)).get();
  }

  private static ScheduledExecutorService reharvestScheduler(JarCollectorService svc)
      throws Exception {
    Field f = JarCollectorService.class.getDeclaredField("reharvestScheduler");
    f.setAccessible(true);
    return (ScheduledExecutorService) f.get(svc);
  }

  @SuppressWarnings("rawtypes")
  private static Instrumentation stubInstrumentation() {
    return new Instrumentation() {
      @Override
      public void addTransformer(ClassFileTransformer t, boolean r) {}

      @Override
      public void addTransformer(ClassFileTransformer t) {}

      @Override
      public boolean removeTransformer(ClassFileTransformer t) {
        return true;
      }

      @Override
      public boolean isRetransformClassesSupported() {
        return false;
      }

      @Override
      public void retransformClasses(Class<?>... c) throws UnmodifiableClassException {}

      @Override
      public boolean isRedefineClassesSupported() {
        return false;
      }

      @Override
      public void redefineClasses(ClassDefinition... d)
          throws ClassNotFoundException, UnmodifiableClassException {}

      @Override
      public boolean isModifiableClass(Class<?> c) {
        return false;
      }

      @Override
      public Class[] getAllLoadedClasses() {
        return new Class[0];
      }

      @Override
      public Class[] getInitiatedClasses(ClassLoader l) {
        return new Class[0];
      }

      @Override
      public long getObjectSize(Object o) {
        return 0;
      }

      @Override
      public void appendToBootstrapClassLoaderSearch(JarFile j) {}

      @Override
      public void appendToSystemClassLoaderSearch(JarFile j) {}

      @Override
      public boolean isNativeMethodPrefixSupported() {
        return false;
      }

      @Override
      public void setNativeMethodPrefix(ClassFileTransformer t, String p) {}
    };
  }

  private static void buildMinimalJar(File jarFile) throws IOException {
    try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jarFile))) {
      out.putNextEntry(new JarEntry("dummy.class"));
      out.closeEntry();
    }
  }

  private static void buildJarWithClassPath(File jarFile, String classPathEntry)
      throws IOException {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Class-Path", classPathEntry);
    try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jarFile), manifest)) {
      out.putNextEntry(new JarEntry("dummy.class"));
      out.closeEntry();
    }
  }
}
