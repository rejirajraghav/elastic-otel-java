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
 * registered in the OTel autoconfigure pipeline by {@link SCAExtension#customize} so they appear
 * in any config-dump tooling that inspects OTel properties.
 */
public final class SCAConfiguration {

  static final String ENABLED_KEY = "elastic.otel.sca.enabled";
  static final String ENABLED_ENV = "ELASTIC_OTEL_SCA_ENABLED";

  static final String SKIP_TEMP_JARS_KEY = "elastic.otel.sca.skip_temp_jars";
  static final String SKIP_TEMP_JARS_ENV = "ELASTIC_OTEL_SCA_SKIP_TEMP_JARS";

  static final String JARS_PER_SECOND_KEY = "elastic.otel.sca.jars_per_second";
  static final String JARS_PER_SECOND_ENV = "ELASTIC_OTEL_SCA_JARS_PER_SECOND";

  static final String MAX_JARS_TOTAL_KEY = "elastic.otel.sca.max_jars_total";
  static final String MAX_JARS_TOTAL_ENV = "ELASTIC_OTEL_SCA_MAX_JARS_TOTAL";

  static final boolean DEFAULT_ENABLED = true;
  static final boolean DEFAULT_SKIP_TEMP_JARS = true;
  static final int DEFAULT_JARS_PER_SECOND = 10;
  static final int DEFAULT_MAX_JARS_TOTAL = 5000;

  private final boolean enabled;
  private final boolean skipTempJars;
  private final int jarsPerSecond;
  private final int maxJarsTotal;

  private SCAConfiguration(boolean enabled, boolean skipTempJars, int jarsPerSecond, int maxJarsTotal) {
    this.enabled = enabled;
    this.skipTempJars = skipTempJars;
    this.jarsPerSecond = jarsPerSecond;
    this.maxJarsTotal = maxJarsTotal;
  }

  /** Reads current configuration from system properties and environment variables. */
  static SCAConfiguration get() {
    return new SCAConfiguration(
        readBoolean(ENABLED_KEY, ENABLED_ENV, DEFAULT_ENABLED),
        readBoolean(SKIP_TEMP_JARS_KEY, SKIP_TEMP_JARS_ENV, DEFAULT_SKIP_TEMP_JARS),
        readInt(JARS_PER_SECOND_KEY, JARS_PER_SECOND_ENV, DEFAULT_JARS_PER_SECOND),
        readInt(MAX_JARS_TOTAL_KEY, MAX_JARS_TOTAL_ENV, DEFAULT_MAX_JARS_TOTAL));
  }

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
}
