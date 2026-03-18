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

/**
 * Reads SCA extension configuration from system properties and environment variables.
 *
 * <p>System properties take precedence over environment variables. Default values are also
 * registered in the OTel autoconfigure pipeline by {@link SCAExtension#customize} so they appear in
 * any config-dump tooling that inspects OTel properties.
 */
public final class SCAConfiguration {

  // ---- Config keys ---------------------------------------------------------

  static final String ENABLED_KEY = "elastic.otel.sca.enabled";
  static final String ENABLED_ENV = "ELASTIC_OTEL_SCA_ENABLED";

  static final String SKIP_TEMP_JARS_KEY = "elastic.otel.sca.skip_temp_jars";
  static final String SKIP_TEMP_JARS_ENV = "ELASTIC_OTEL_SCA_SKIP_TEMP_JARS";

  static final String JARS_PER_SECOND_KEY = "elastic.otel.sca.jars_per_second";
  static final String JARS_PER_SECOND_ENV = "ELASTIC_OTEL_SCA_JARS_PER_SECOND";

  static final String MAX_JARS_TOTAL_KEY = "elastic.otel.sca.max_jars_total";
  static final String MAX_JARS_TOTAL_ENV = "ELASTIC_OTEL_SCA_MAX_JARS_TOTAL";

  /** Skip -tests.jar, -test.jar, and -test-*.jar files. */
  static final String SKIP_TEST_JARS_KEY = "elastic.otel.sca.skip_test_jars";

  static final String SKIP_TEST_JARS_ENV = "ELASTIC_OTEL_SCA_SKIP_TEST_JARS";

  /**
   * How often (seconds) to re-scan known classloaders for newly added URLs. Set to 0 to disable
   * periodic re-harvest.
   */
  static final String REHARVEST_INTERVAL_KEY = "elastic.otel.sca.reharvest_interval_seconds";

  static final String REHARVEST_INTERVAL_ENV = "ELASTIC_OTEL_SCA_REHARVEST_INTERVAL_SECONDS";

  /** Whether to eagerly scan the JVM startup classpath before the ClassFileTransformer is set. */
  static final String SCAN_STARTUP_CLASSPATH_KEY = "elastic.otel.sca.scan_startup_classpath";

  static final String SCAN_STARTUP_CLASSPATH_ENV = "ELASTIC_OTEL_SCA_SCAN_STARTUP_CLASSPATH";

  /** Whether to follow {@code Class-Path} manifest entries one level deep. */
  static final String FOLLOW_MANIFEST_CLASSPATH_KEY = "elastic.otel.sca.follow_manifest_classpath";

  static final String FOLLOW_MANIFEST_CLASSPATH_ENV = "ELASTIC_OTEL_SCA_FOLLOW_MANIFEST_CLASSPATH";

  /** Whether to detect shaded/uber-JARs and emit one event per embedded library. */
  static final String DETECT_SHADED_JARS_KEY = "elastic.otel.sca.detect_shaded_jars";

  static final String DETECT_SHADED_JARS_ENV = "ELASTIC_OTEL_SCA_DETECT_SHADED_JARS";

  // ---- Defaults ------------------------------------------------------------

  static final boolean DEFAULT_ENABLED = true;
  static final boolean DEFAULT_SKIP_TEMP_JARS = true;
  static final int DEFAULT_JARS_PER_SECOND = 10;
  static final int DEFAULT_MAX_JARS_TOTAL = 5000;
  static final boolean DEFAULT_SKIP_TEST_JARS = true;
  static final int DEFAULT_REHARVEST_INTERVAL_SECONDS = 60;
  static final boolean DEFAULT_SCAN_STARTUP_CLASSPATH = true;
  static final boolean DEFAULT_FOLLOW_MANIFEST_CLASSPATH = true;
  static final boolean DEFAULT_DETECT_SHADED_JARS = true;

  // ---- Instance state ------------------------------------------------------

  private final boolean enabled;
  private final boolean skipTempJars;
  private final int jarsPerSecond;
  private final int maxJarsTotal;
  private final boolean skipTestJars;
  private final int reharvestIntervalSeconds;
  private final boolean scanStartupClasspath;
  private final boolean followManifestClasspath;
  private final boolean detectShadedJars;

  private SCAConfiguration(
      boolean enabled,
      boolean skipTempJars,
      int jarsPerSecond,
      int maxJarsTotal,
      boolean skipTestJars,
      int reharvestIntervalSeconds,
      boolean scanStartupClasspath,
      boolean followManifestClasspath,
      boolean detectShadedJars) {
    this.enabled = enabled;
    this.skipTempJars = skipTempJars;
    this.jarsPerSecond = jarsPerSecond;
    this.maxJarsTotal = maxJarsTotal;
    this.skipTestJars = skipTestJars;
    this.reharvestIntervalSeconds = reharvestIntervalSeconds;
    this.scanStartupClasspath = scanStartupClasspath;
    this.followManifestClasspath = followManifestClasspath;
    this.detectShadedJars = detectShadedJars;
  }

  /** Reads current configuration from system properties and environment variables. */
  static SCAConfiguration get() {
    return new SCAConfiguration(
        readBoolean(ENABLED_KEY, ENABLED_ENV, DEFAULT_ENABLED),
        readBoolean(SKIP_TEMP_JARS_KEY, SKIP_TEMP_JARS_ENV, DEFAULT_SKIP_TEMP_JARS),
        readInt(JARS_PER_SECOND_KEY, JARS_PER_SECOND_ENV, DEFAULT_JARS_PER_SECOND),
        readInt(MAX_JARS_TOTAL_KEY, MAX_JARS_TOTAL_ENV, DEFAULT_MAX_JARS_TOTAL),
        readBoolean(SKIP_TEST_JARS_KEY, SKIP_TEST_JARS_ENV, DEFAULT_SKIP_TEST_JARS),
        readIntNonNegative(
            REHARVEST_INTERVAL_KEY, REHARVEST_INTERVAL_ENV, DEFAULT_REHARVEST_INTERVAL_SECONDS),
        readBoolean(
            SCAN_STARTUP_CLASSPATH_KEY, SCAN_STARTUP_CLASSPATH_ENV, DEFAULT_SCAN_STARTUP_CLASSPATH),
        readBoolean(
            FOLLOW_MANIFEST_CLASSPATH_KEY,
            FOLLOW_MANIFEST_CLASSPATH_ENV,
            DEFAULT_FOLLOW_MANIFEST_CLASSPATH),
        readBoolean(DETECT_SHADED_JARS_KEY, DETECT_SHADED_JARS_ENV, DEFAULT_DETECT_SHADED_JARS));
  }

  // ---- Accessors -----------------------------------------------------------

  public boolean isEnabled() {
    return enabled;
  }

  public boolean isSkipTempJars() {
    return skipTempJars;
  }

  public int getJarsPerSecond() {
    return jarsPerSecond;
  }

  public int getMaxJarsTotal() {
    return maxJarsTotal;
  }

  public boolean isSkipTestJars() {
    return skipTestJars;
  }

  /** Returns the re-harvest interval in seconds. 0 means disabled. */
  public int getReharvestIntervalSeconds() {
    return reharvestIntervalSeconds;
  }

  public boolean isScanStartupClasspath() {
    return scanStartupClasspath;
  }

  public boolean isFollowManifestClasspath() {
    return followManifestClasspath;
  }

  public boolean isDetectShadedJars() {
    return detectShadedJars;
  }

  // ---- Readers -------------------------------------------------------------

  private static boolean readBoolean(String sysProp, String envVar, boolean defaultValue) {
    String value = System.getProperty(sysProp);
    if (value == null) {
      value = System.getenv(envVar);
    }
    if (value == null) {
      return defaultValue;
    }
    return "true".equalsIgnoreCase(value.trim());
  }

  /** Reads a positive integer; falls back to {@code defaultValue} for zero or negative values. */
  private static int readInt(String sysProp, String envVar, int defaultValue) {
    String value = System.getProperty(sysProp);
    if (value == null) {
      value = System.getenv(envVar);
    }
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      return parsed > 0 ? parsed : defaultValue;
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  /**
   * Reads a non-negative integer; falls back to {@code defaultValue} only for negative values. Zero
   * is a valid value (used to disable periodic re-harvest).
   */
  private static int readIntNonNegative(String sysProp, String envVar, int defaultValue) {
    String value = System.getProperty(sysProp);
    if (value == null) {
      value = System.getenv(envVar);
    }
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      return parsed >= 0 ? parsed : defaultValue;
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }
}
