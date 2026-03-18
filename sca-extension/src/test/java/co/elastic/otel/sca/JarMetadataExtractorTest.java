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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JarMetadataExtractorTest {

  @TempDir File tempDir;

  // ---- pom.properties -------------------------------------------------------

  @Test
  void extractFromPomProperties() throws IOException {
    File jar =
        buildJar(
            "my-artifact-1.2.3.jar",
            jarOut -> addPomProperties(jarOut, "com.example", "my-artifact", "1.2.3"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "testloader");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.groupId).isEqualTo("com.example");
    assertThat(meta.name).isEqualTo("my-artifact");
    assertThat(meta.version).isEqualTo("1.2.3");
    assertThat(meta.purl).isEqualTo("pkg:maven/com.example/my-artifact@1.2.3");
    assertThat(meta.classloaderName).isEqualTo("testloader");
    assertThat(meta.shaded).isFalse();
  }

  @Test
  void pomPropertiesTakesPrecedenceOverManifest() throws IOException {
    File jar =
        buildJar(
            "artifact.jar",
            jarOut -> {
              addPomProperties(jarOut, "com.pom", "pom-artifact", "2.0");
              addManifest(jarOut, "Manifest-Artifact", "9.9.9", null);
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.groupId).isEqualTo("com.pom");
    assertThat(meta.name).isEqualTo("pom-artifact");
    assertThat(meta.version).isEqualTo("2.0");
  }

  // ---- Shaded / uber-JAR (multiple pom.properties) -------------------------

  @Test
  void shadedJarEmitsOneEventPerEmbeddedLibrary() throws IOException {
    File jar =
        buildJar(
            "my-uber-app.jar",
            jarOut -> {
              addPomProperties(jarOut, "com.example", "my-app", "1.0");
              addPomProperties(jarOut, "org.slf4j", "slf4j-api", "2.0.7");
              addPomProperties(jarOut, "com.google.guava", "guava", "32.1.3-jre");
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "loader");

    assertThat(metas).hasSize(3);
    assertThat(metas).extracting(m -> m.shaded).containsOnly(true);
    // All share the same physical path
    assertThat(metas).extracting(m -> m.jarPath).containsOnly(jar.getAbsolutePath());
    // All share the same SHA-256
    assertThat(metas).extracting(m -> m.sha256).doesNotContain("").allMatch(s -> s.length() == 64);
    // All share the same SHA-1
    assertThat(metas).extracting(m -> m.sha1).doesNotContain("").allMatch(s -> s.length() == 40);
    // Each entry has its own identity
    assertThat(metas)
        .extracting(m -> m.name)
        .containsExactlyInAnyOrder("my-app", "slf4j-api", "guava");
  }

  // ---- MANIFEST.MF ----------------------------------------------------------

  @Test
  void extractFromManifest() throws IOException {
    File jar =
        buildJar("manifest-only.jar", jarOut -> addManifest(jarOut, "My Library", "3.1.0", null));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.version).isEqualTo("3.1.0");
    // name falls back to Implementation-Title when no artifactId
    assertThat(meta.name).isEqualTo("My Library");
  }

  @Test
  void manifestSpecificationVersionUsedWhenImplementationVersionAbsent() throws IOException {
    File jar = buildJar("spec-version.jar", jarOut -> addManifest(jarOut, "SpecLib", null, "4.0"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).version).isEqualTo("4.0");
  }

  @Test
  void bundleSymbolicNameUsedAsGroupIdAndArtifactId() throws IOException {
    File jar =
        buildJar(
            "unbescape-1.1.6.RELEASE.jar",
            jarOut -> addBundleManifest(jarOut, "org.unbescape", "1.1.6.RELEASE", "Unbescape"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    // BSN "org.unbescape" → groupId=org.unbescape, artifactId=unbescape (last segment)
    assertThat(meta.groupId).isEqualTo("org.unbescape");
    assertThat(meta.name).isEqualTo("unbescape");
    assertThat(meta.version).isEqualTo("1.1.6.RELEASE");
    assertThat(meta.purl).isEqualTo("pkg:maven/org.unbescape/unbescape@1.1.6.RELEASE");
  }

  @Test
  void bundleVersionUsedWhenImplementationVersionAbsent() throws IOException {
    File jar =
        buildJar(
            "osgi-bundle-2.0.jar",
            jarOut -> addBundleManifest(jarOut, "com.example.bundle", "2.0.0", null));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).version).isEqualTo("2.0.0");
  }

  // ---- Gradle module metadata -----------------------------------------------

  @Test
  void extractFromGradleModuleMetadata() throws IOException {
    File jar =
        buildJar(
            "kotlinx-coroutines-core-1.7.3.jar",
            jarOut ->
                addGradleModuleMetadata(
                    jarOut, "org.jetbrains.kotlinx", "kotlinx-coroutines-core", "1.7.3"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.groupId).isEqualTo("org.jetbrains.kotlinx");
    assertThat(meta.name).isEqualTo("kotlinx-coroutines-core");
    assertThat(meta.version).isEqualTo("1.7.3");
    assertThat(meta.purl)
        .isEqualTo("pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core@1.7.3");
  }

  // ---- Filename fallback ----------------------------------------------------

  @Test
  void extractVersionFromFilename() throws IOException {
    File jar =
        buildJar(
            "guava-32.1.3-jre.jar",
            jarOut -> {
              /* no metadata */
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.name).isEqualTo("guava");
    assertThat(meta.version).isEqualTo("32.1.3-jre");
    assertThat(meta.purl).isEqualTo("pkg:maven/guava@32.1.3-jre");
  }

  @Test
  void springReleaseSuffixParsedFromFilename() throws IOException {
    File jar =
        buildJar(
            "spring-core-6.1.0.RELEASE.jar",
            jarOut -> {
              /* no metadata */
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.name).isEqualTo("spring-core");
    assertThat(meta.version).isEqualTo("6.1.0.RELEASE");
  }

  @Test
  void noVersionInFilename() throws IOException {
    File jar =
        buildJar(
            "tools.jar",
            jarOut -> {
              /* no metadata */
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.name).isEqualTo("tools");
    assertThat(meta.version).isEmpty();
  }

  // ---- pURL construction ----------------------------------------------------

  @Test
  void purlWithoutGroupId() {
    assertThat(JarMetadataExtractor.buildPurl("", "my-lib", "1.0"))
        .isEqualTo("pkg:maven/my-lib@1.0");
  }

  @Test
  void purlWithoutVersion() {
    assertThat(JarMetadataExtractor.buildPurl("org.example", "lib", ""))
        .isEqualTo("pkg:maven/org.example/lib");
  }

  @Test
  void purlEmptyWhenNoArtifactId() {
    assertThat(JarMetadataExtractor.buildPurl("org.example", "", "1.0")).isEmpty();
  }

  // ---- SHA-256 and SHA-1 ----------------------------------------------------

  @Test
  void sha256IsDeterministic() throws IOException {
    File jar =
        buildJar("stable.jar", jarOut -> addPomProperties(jarOut, "org.stable", "stable", "1.0"));

    String first = JarMetadataExtractor.computeSha256(jar);
    String second = JarMetadataExtractor.computeSha256(jar);

    assertThat(first).isNotEmpty().hasSize(64).isEqualTo(second);
  }

  @Test
  void sha256DiffersForDifferentContent() throws IOException {
    File jar1 = buildJar("a.jar", jarOut -> addPomProperties(jarOut, "g", "a", "1"));
    File jar2 = buildJar("b.jar", jarOut -> addPomProperties(jarOut, "g", "b", "2"));

    assertThat(JarMetadataExtractor.computeSha256(jar1))
        .isNotEqualTo(JarMetadataExtractor.computeSha256(jar2));
  }

  @Test
  void sha1IsComputedAlongsideSha256() throws IOException {
    File jar = buildJar("hashed.jar", jarOut -> addPomProperties(jarOut, "org.x", "x", "1.0"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.sha256).isNotEmpty().hasSize(64);
    assertThat(meta.sha1).isNotEmpty().hasSize(40);
  }

  @Test
  void checksumsComputedInSinglePassMatchIndividualComputations() throws IOException {
    File jar = buildJar("dual.jar", jarOut -> addPomProperties(jarOut, "org.y", "y", "2.0"));

    JarMetadataExtractor.Checksums checksums = JarMetadataExtractor.computeChecksums(jar);

    assertThat(checksums.sha256).isEqualTo(JarMetadataExtractor.computeSha256(jar));
    assertThat(checksums.sha1).isNotEmpty().hasSize(40);
  }

  // ---- Gradle module metadata JSON parsing ----------------------------------

  @Test
  void extractJsonFieldFindsTopLevelStringField() {
    String json =
        "{ \"formatVersion\": \"1.1\", \"group\": \"org.example\", \"module\": \"foo\", \"version\": \"1.0\" }";
    assertThat(JarMetadataExtractor.extractJsonField(json, "group")).isEqualTo("org.example");
    assertThat(JarMetadataExtractor.extractJsonField(json, "module")).isEqualTo("foo");
    assertThat(JarMetadataExtractor.extractJsonField(json, "version")).isEqualTo("1.0");
    assertThat(JarMetadataExtractor.extractJsonField(json, "missing")).isNull();
  }

  // ---- Version suffixes (Final, GA) ----------------------------------------

  @Test
  void hibernateFinalSuffixParsedFromFilename() throws IOException {
    File jar =
        buildJar(
            "hibernate-core-6.2.0.Final.jar",
            jarOut -> {
              /* no metadata */
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.name).isEqualTo("hibernate-core");
    assertThat(meta.version).isEqualTo("6.2.0.Final");
  }

  @Test
  void springGaSuffixParsedFromFilename() throws IOException {
    File jar =
        buildJar(
            "spring-core-6.1.0.GA.jar",
            jarOut -> {
              /* no metadata */
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    JarMetadata meta = metas.get(0);
    assertThat(meta.name).isEqualTo("spring-core");
    assertThat(meta.version).isEqualTo("6.1.0.GA");
  }

  // ---- Module type ---------------------------------------------------------

  @Test
  void regularJarHasModuleTypeJar() throws IOException {
    File jar =
        buildJar("single.jar", jarOut -> addPomProperties(jarOut, "org.single", "single", "1.0"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).moduleType).isEqualTo(JarMetadata.TYPE_JAR);
  }

  @Test
  void shadedJarEntriesHaveModuleTypeShadedEntry() throws IOException {
    File jar =
        buildJar(
            "uber.jar",
            jarOut -> {
              addPomProperties(jarOut, "com.a", "lib-a", "1.0");
              addPomProperties(jarOut, "com.b", "lib-b", "2.0");
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(2);
    assertThat(metas).extracting(m -> m.moduleType).containsOnly(JarMetadata.TYPE_SHADED_ENTRY);
  }

  // ---- License from Bundle-License manifest attribute ----------------------

  @Test
  void licenseDetectedFromBundleLicenseApache() throws IOException {
    File jar =
        buildJar(
            "apache-lib-1.0.jar",
            jarOut ->
                addBundleLicenseManifest(
                    jarOut, "https://www.apache.org/licenses/LICENSE-2.0.txt"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEqualTo("Apache-2.0");
  }

  @Test
  void licenseDetectedFromBundleLicenseMit() throws IOException {
    File jar = buildJar("mit-lib-1.0.jar", jarOut -> addBundleLicenseManifest(jarOut, "MIT"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEqualTo("MIT");
  }

  @Test
  void licenseDetectedFromLicenseFileContent() throws IOException {
    File jar =
        buildJar(
            "licensed-1.0.jar",
            jarOut -> {
              addPomProperties(jarOut, "org.licensed", "licensed", "1.0");
              addLicenseFile(
                  jarOut,
                  "META-INF/LICENSE",
                  "Apache License, Version 2.0\nwww.apache.org/licenses/LICENSE-2.0");
            });

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEqualTo("Apache-2.0");
  }

  @Test
  void licenseDetectedFromMitLicenseFile() throws IOException {
    File jar =
        buildJar(
            "mit-2.0.jar",
            jarOut ->
                addLicenseFile(
                    jarOut,
                    "META-INF/LICENSE.txt",
                    "MIT License\nPermission is hereby granted, free of charge"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEqualTo("MIT");
  }

  @Test
  void licenseDetectedFromSpdxIdentifierLine() throws IOException {
    File jar =
        buildJar(
            "spdx-1.0.jar",
            jarOut ->
                addLicenseFile(
                    jarOut, "META-INF/LICENSE", "SPDX-License-Identifier: GPL-3.0-or-later\n"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEqualTo("GPL-3.0-or-later");
  }

  @Test
  void noLicenseWhenNotDetectable() throws IOException {
    File jar =
        buildJar("unlicensed-1.0.jar", jarOut -> addPomProperties(jarOut, "org.u", "u", "1.0"));

    List<JarMetadata> metas = JarMetadataExtractor.extract(jar.getAbsolutePath(), "");

    assertThat(metas).hasSize(1);
    assertThat(metas.get(0).license).isEmpty();
  }

  // ---- normalizeLicense / detectSpdxIdentifier unit tests ------------------

  @Test
  void normalizeLicenseApacheUrl() {
    assertThat(JarMetadataExtractor.normalizeLicense("https://www.apache.org/licenses/license-2.0"))
        .isEqualTo("Apache-2.0");
  }

  @Test
  void normalizeLicenseMit() {
    assertThat(JarMetadataExtractor.normalizeLicense("MIT")).isEqualTo("MIT");
  }

  @Test
  void normalizeLicenseGpl3() {
    assertThat(JarMetadataExtractor.normalizeLicense("GPL-3.0")).isEqualTo("GPL-3.0");
  }

  @Test
  void normalizeLicenseReturnsEmptyForUnknown() {
    assertThat(JarMetadataExtractor.normalizeLicense("Some Custom License")).isEmpty();
  }

  @Test
  void detectSpdxIdentifierFromExplicitTag() {
    assertThat(JarMetadataExtractor.detectSpdxIdentifier("SPDX-License-Identifier: Apache-2.0\n"))
        .isEqualTo("Apache-2.0");
  }

  @Test
  void detectSpdxIdentifierFromApacheText() {
    assertThat(
            JarMetadataExtractor.detectSpdxIdentifier(
                "Apache License, Version 2.0\nwww.apache.org/licenses/LICENSE-2.0"))
        .isEqualTo("Apache-2.0");
  }

  @Test
  void detectSpdxIdentifierFromMitText() {
    assertThat(
            JarMetadataExtractor.detectSpdxIdentifier("MIT License\nPermission is hereby granted"))
        .isEqualTo("MIT");
  }

  @Test
  void detectSpdxIdentifierReturnsNullForUnrecognized() {
    assertThat(JarMetadataExtractor.detectSpdxIdentifier("Some random text")).isNull();
  }

  // ---- Missing file ---------------------------------------------------------

  @Test
  void returnsEmptyListForNonExistentFile() {
    List<JarMetadata> metas = JarMetadataExtractor.extract("/does/not/exist.jar", "");
    assertThat(metas).isEmpty();
  }

  // ---- Helpers --------------------------------------------------------------

  @FunctionalInterface
  interface JarPopulator {
    void populate(JarOutputStream jarOut) throws IOException;
  }

  private File buildJar(String name, JarPopulator populator) throws IOException {
    File jar = new File(tempDir, name);
    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar))) {
      populator.populate(jos);
    }
    return jar;
  }

  private static void addPomProperties(
      JarOutputStream jos, String groupId, String artifactId, String version) throws IOException {
    jos.putNextEntry(
        new JarEntry("META-INF/maven/" + groupId + "/" + artifactId + "/pom.properties"));
    Properties props = new Properties();
    props.setProperty("groupId", groupId);
    props.setProperty("artifactId", artifactId);
    props.setProperty("version", version);
    props.store(jos, null);
    jos.closeEntry();
  }

  private static void addManifest(
      JarOutputStream jos, String implTitle, String implVersion, String specVersion)
      throws IOException {
    Manifest mf = new Manifest();
    Attributes attrs = mf.getMainAttributes();
    attrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (implTitle != null) {
      attrs.put(Attributes.Name.IMPLEMENTATION_TITLE, implTitle);
    }
    if (implVersion != null) {
      attrs.put(Attributes.Name.IMPLEMENTATION_VERSION, implVersion);
    }
    if (specVersion != null) {
      attrs.put(Attributes.Name.SPECIFICATION_VERSION, specVersion);
    }
    jos.putNextEntry(new JarEntry(JarFile.MANIFEST_NAME));
    mf.write(jos);
    jos.closeEntry();
  }

  /** Adds a MANIFEST.MF with OSGi/Bundle attributes (Bundle-SymbolicName + Bundle-Version). */
  private static void addBundleManifest(
      JarOutputStream jos, String bsn, String bundleVersion, String bundleName) throws IOException {
    Manifest mf = new Manifest();
    Attributes attrs = mf.getMainAttributes();
    attrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
    attrs.putValue("Bundle-SymbolicName", bsn);
    attrs.putValue("Bundle-Version", bundleVersion);
    if (bundleName != null) {
      attrs.putValue("Bundle-Name", bundleName);
    }
    jos.putNextEntry(new JarEntry(JarFile.MANIFEST_NAME));
    mf.write(jos);
    jos.closeEntry();
  }

  /** Adds a MANIFEST.MF with only Bundle-License (no other meaningful attributes). */
  private static void addBundleLicenseManifest(JarOutputStream jos, String bundleLicense)
      throws IOException {
    Manifest mf = new Manifest();
    Attributes attrs = mf.getMainAttributes();
    attrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
    attrs.putValue("Bundle-License", bundleLicense);
    jos.putNextEntry(new JarEntry(JarFile.MANIFEST_NAME));
    mf.write(jos);
    jos.closeEntry();
  }

  /** Adds a license file at the given path with the provided content. */
  private static void addLicenseFile(JarOutputStream jos, String path, String content)
      throws IOException {
    jos.putNextEntry(new JarEntry(path));
    jos.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    jos.closeEntry();
  }

  /** Adds a Gradle module metadata JSON file under META-INF/gradle/. */
  private static void addGradleModuleMetadata(
      JarOutputStream jos, String group, String module, String version) throws IOException {
    jos.putNextEntry(new JarEntry("META-INF/gradle/" + module + ".module"));
    String json =
        "{\n"
            + "  \"formatVersion\": \"1.1\",\n"
            + "  \"component\": { \"group\": \""
            + group
            + "\", \"module\": \""
            + module
            + "\", \"version\": \""
            + version
            + "\" },\n"
            + "  \"group\": \""
            + group
            + "\",\n"
            + "  \"module\": \""
            + module
            + "\",\n"
            + "  \"version\": \""
            + version
            + "\"\n"
            + "}";
    jos.write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    jos.closeEntry();
  }
}
