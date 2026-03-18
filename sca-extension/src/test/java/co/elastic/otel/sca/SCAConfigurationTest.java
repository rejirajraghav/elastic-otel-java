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

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SCAConfigurationTest {

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

  // ---- Default values (no sys props set) -----------------------------------

  @Test
  void defaultEnabledIsTrue() {
    assertThat(SCAConfiguration.get().isEnabled()).isTrue();
  }

  @Test
  void defaultJarsPerSecondIsTen() {
    assertThat(SCAConfiguration.get().getJarsPerSecond())
        .isEqualTo(SCAConfiguration.DEFAULT_JARS_PER_SECOND);
  }

  @Test
  void defaultMaxJarsTotalIs5000() {
    assertThat(SCAConfiguration.get().getMaxJarsTotal())
        .isEqualTo(SCAConfiguration.DEFAULT_MAX_JARS_TOTAL);
  }

  @Test
  void defaultSkipTempJarsIsTrue() {
    assertThat(SCAConfiguration.get().isSkipTempJars())
        .isEqualTo(SCAConfiguration.DEFAULT_SKIP_TEMP_JARS);
  }

  @Test
  void defaultSkipTestJarsIsTrue() {
    assertThat(SCAConfiguration.get().isSkipTestJars())
        .isEqualTo(SCAConfiguration.DEFAULT_SKIP_TEST_JARS);
  }

  @Test
  void defaultScanStartupClasspathIsTrue() {
    assertThat(SCAConfiguration.get().isScanStartupClasspath())
        .isEqualTo(SCAConfiguration.DEFAULT_SCAN_STARTUP_CLASSPATH);
  }

  @Test
  void defaultFollowManifestClasspathIsTrue() {
    assertThat(SCAConfiguration.get().isFollowManifestClasspath())
        .isEqualTo(SCAConfiguration.DEFAULT_FOLLOW_MANIFEST_CLASSPATH);
  }

  @Test
  void defaultDetectShadedJarsIsTrue() {
    assertThat(SCAConfiguration.get().isDetectShadedJars())
        .isEqualTo(SCAConfiguration.DEFAULT_DETECT_SHADED_JARS);
  }

  @Test
  void defaultReharvestIntervalIs60() {
    assertThat(SCAConfiguration.get().getReharvestIntervalSeconds())
        .isEqualTo(SCAConfiguration.DEFAULT_REHARVEST_INTERVAL_SECONDS);
  }

  // ---- System property overrides (all 9 keys) ------------------------------

  @Test
  void enabledFalseViaSysProp() {
    set(SCAConfiguration.ENABLED_KEY, "false");
    assertThat(SCAConfiguration.get().isEnabled()).isFalse();
  }

  @Test
  void jarsPerSecondOverriddenViaSysProp() {
    set(SCAConfiguration.JARS_PER_SECOND_KEY, "50");
    assertThat(SCAConfiguration.get().getJarsPerSecond()).isEqualTo(50);
  }

  @Test
  void maxJarsTotalOverriddenViaSysProp() {
    set(SCAConfiguration.MAX_JARS_TOTAL_KEY, "1000");
    assertThat(SCAConfiguration.get().getMaxJarsTotal()).isEqualTo(1000);
  }

  @Test
  void skipTempJarsFalseViaSysProp() {
    set(SCAConfiguration.SKIP_TEMP_JARS_KEY, "false");
    assertThat(SCAConfiguration.get().isSkipTempJars()).isFalse();
  }

  @Test
  void skipTestJarsFalseViaSysProp() {
    set(SCAConfiguration.SKIP_TEST_JARS_KEY, "false");
    assertThat(SCAConfiguration.get().isSkipTestJars()).isFalse();
  }

  @Test
  void scanStartupClasspathFalseViaSysProp() {
    set(SCAConfiguration.SCAN_STARTUP_CLASSPATH_KEY, "false");
    assertThat(SCAConfiguration.get().isScanStartupClasspath()).isFalse();
  }

  @Test
  void followManifestClasspathFalseViaSysProp() {
    set(SCAConfiguration.FOLLOW_MANIFEST_CLASSPATH_KEY, "false");
    assertThat(SCAConfiguration.get().isFollowManifestClasspath()).isFalse();
  }

  @Test
  void detectShadedJarsFalseViaSysProp() {
    set(SCAConfiguration.DETECT_SHADED_JARS_KEY, "false");
    assertThat(SCAConfiguration.get().isDetectShadedJars()).isFalse();
  }

  @Test
  void reharvestIntervalOverriddenViaSysProp() {
    set(SCAConfiguration.REHARVEST_INTERVAL_KEY, "120");
    assertThat(SCAConfiguration.get().getReharvestIntervalSeconds()).isEqualTo(120);
  }

  // ---- Special case: reharvest_interval_seconds uses readIntNonNegative ----

  @Test
  void reharvestIntervalZeroIsValidAndDisablesReharvest() {
    // 0 means "disabled" — must NOT fall back to default 60
    set(SCAConfiguration.REHARVEST_INTERVAL_KEY, "0");
    assertThat(SCAConfiguration.get().getReharvestIntervalSeconds()).isEqualTo(0);
  }

  @Test
  void reharvestIntervalNegativeFallsBackToDefault() {
    // negative is invalid → fallback
    set(SCAConfiguration.REHARVEST_INTERVAL_KEY, "-1");
    assertThat(SCAConfiguration.get().getReharvestIntervalSeconds())
        .isEqualTo(SCAConfiguration.DEFAULT_REHARVEST_INTERVAL_SECONDS);
  }

  // ---- Edge cases: invalid values and boundary conditions ------------------

  @Test
  void invalidJarsPerSecondStringFallsBackToDefault() {
    set(SCAConfiguration.JARS_PER_SECOND_KEY, "not-a-number");
    assertThat(SCAConfiguration.get().getJarsPerSecond())
        .isEqualTo(SCAConfiguration.DEFAULT_JARS_PER_SECOND);
  }

  @Test
  void zeroJarsPerSecondFallsBackToDefault() {
    // readInt() rejects zero — must be a positive integer
    set(SCAConfiguration.JARS_PER_SECOND_KEY, "0");
    assertThat(SCAConfiguration.get().getJarsPerSecond())
        .isEqualTo(SCAConfiguration.DEFAULT_JARS_PER_SECOND);
  }

  @Test
  void negativeJarsPerSecondFallsBackToDefault() {
    set(SCAConfiguration.JARS_PER_SECOND_KEY, "-5");
    assertThat(SCAConfiguration.get().getJarsPerSecond())
        .isEqualTo(SCAConfiguration.DEFAULT_JARS_PER_SECOND);
  }

  @Test
  void invalidMaxJarsTotalFallsBackToDefault() {
    set(SCAConfiguration.MAX_JARS_TOTAL_KEY, "abc");
    assertThat(SCAConfiguration.get().getMaxJarsTotal())
        .isEqualTo(SCAConfiguration.DEFAULT_MAX_JARS_TOTAL);
  }

  @Test
  void zeroMaxJarsTotalFallsBackToDefault() {
    set(SCAConfiguration.MAX_JARS_TOTAL_KEY, "0");
    assertThat(SCAConfiguration.get().getMaxJarsTotal())
        .isEqualTo(SCAConfiguration.DEFAULT_MAX_JARS_TOTAL);
  }

  @Test
  void booleanTrueIsCaseInsensitive() {
    set(SCAConfiguration.ENABLED_KEY, "TRUE");
    assertThat(SCAConfiguration.get().isEnabled()).isTrue();
  }

  @Test
  void booleanFalseIsCaseInsensitive() {
    set(SCAConfiguration.ENABLED_KEY, "FALSE");
    assertThat(SCAConfiguration.get().isEnabled()).isFalse();
  }

  @Test
  void booleanTrueWithWhitespace() {
    set(SCAConfiguration.ENABLED_KEY, "  true  ");
    assertThat(SCAConfiguration.get().isEnabled()).isTrue();
  }

  @Test
  void invalidBooleanStringTreatedAsFalse() {
    // "true".equalsIgnoreCase("yes") == false, so non-"true" strings read as false
    set(SCAConfiguration.ENABLED_KEY, "yes");
    assertThat(SCAConfiguration.get().isEnabled()).isFalse();
  }

  @Test
  void invalidReharvestIntervalStringFallsBackToDefault() {
    set(SCAConfiguration.REHARVEST_INTERVAL_KEY, "bad-value");
    assertThat(SCAConfiguration.get().getReharvestIntervalSeconds())
        .isEqualTo(SCAConfiguration.DEFAULT_REHARVEST_INTERVAL_SECONDS);
  }
}
