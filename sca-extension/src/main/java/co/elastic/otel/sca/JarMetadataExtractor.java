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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts library metadata from a JAR file using five sources in priority order:
 *
 * <ol>
 *   <li>META-INF/maven/[groupId]/[artifactId]/pom.properties — most reliable for Maven artifacts.
 *       If multiple entries are found the JAR is classified as shaded and one {@link JarMetadata}
 *       is returned per embedded library.
 *   <li>META-INF/MANIFEST.MF — expanded field set: Implementation-*, Bundle-*,
 *       Automatic-Module-Name, Implementation-Vendor-Id
 *   <li>META-INF/gradle/*.module — Gradle module metadata JSON (group/module/version)
 *   <li>Filename pattern — name-version.jar best-effort parse
 *   <li>License detection — Bundle-License manifest attribute or META-INF/LICENSE* file content
 * </ol>
 */
public final class JarMetadataExtractor {

  private static final Logger logger = Logger.getLogger(JarMetadataExtractor.class.getName());

  /** Maximum bytes read from a license file to detect SPDX identifier. */
  private static final int LICENSE_READ_LIMIT = 8192;

  /** Known license file paths inside a JAR, checked in order. */
  private static final String[] LICENSE_FILE_PATHS = {
    "META-INF/LICENSE",
    "META-INF/LICENSE.txt",
    "META-INF/LICENSE.md",
    "META-INF/license.txt",
    "LICENSE",
    "LICENSE.txt"
  };

  /**
   * Matches {@code name-version.jar} patterns where version starts with a digit. Handles common
   * separators and classifier suffixes, e.g.:
   *
   * <ul>
   *   <li>guava-32.1.3-jre
   *   <li>unbescape-1.1.6.RELEASE
   *   <li>hibernate-core-6.2.0.Final
   *   <li>spring-core-6.1.0.GA
   *   <li>log4j-core-2.20.0
   * </ul>
   *
   * Classifier suffixes (-sources, -javadoc, -tests, -all, -shadow, -shaded, -uber) are stripped.
   */
  static final Pattern FILENAME_VERSION_PATTERN =
      Pattern.compile(
          "^(.+?)[-_](\\d[\\w.\\-]*?)(?:[-_](?:sources|javadoc|tests?|all|shadow|shaded|uber))?$");

  private JarMetadataExtractor() {}

  // ---- Public extraction API -----------------------------------------------

  /**
   * Extracts {@link JarMetadata} from the given filesystem JAR path.
   *
   * <p>Returns an empty list if the file does not exist. Returns multiple entries when the JAR is a
   * shaded/uber-JAR containing multiple embedded {@code pom.properties} files.
   *
   * @param jarPath absolute filesystem path to the JAR
   * @param classloaderName class name of the classloader that triggered the discovery
   * @return list of metadata entries; never null; empty on error or missing file
   */
  public static List<JarMetadata> extract(String jarPath, String classloaderName) {
    File file = new File(jarPath);
    if (!file.exists() || !file.isFile()) {
      return Collections.emptyList();
    }

    try (JarFile jar = new JarFile(file, /* verify= */ false)) {
      return extractFromJarFile(jar, jarPath, file, classloaderName);
    } catch (IOException e) {
      logger.log(Level.FINE, "SCA: cannot open JAR for metadata extraction: " + jarPath, e);
      return Collections.emptyList();
    }
  }

  /**
   * Extracts {@link JarMetadata} from a nested JAR identified by URL (e.g. Spring Boot's {@code
   * jar:file:///outer.jar!/BOOT-INF/lib/inner.jar} or the Spring Boot 3.2+ {@code
   * jar:nested:///outer.jar/!BOOT-INF/lib/inner.jar} scheme).
   *
   * <p>Falls back to filename-only parsing if the nested entry cannot be opened.
   *
   * @param jarUrl URL of the nested JAR
   * @param classloaderName classloader class name
   * @return single metadata entry, never null
   */
  public static JarMetadata extractFromUrl(URL jarUrl, String classloaderName) {
    String urlStr = jarUrl.toString();
    String outerPath = null;
    String innerEntry = null;

    // Parse outer/inner paths from jar: and jar:nested: URLs
    if (urlStr.startsWith("jar:nested:")) {
      // Spring Boot nested JAR URL formats:
      //   jar:nested:/path/outer.jar/!BOOT-INF/lib/inner.jar     (1 slash)
      //   jar:nested:///path/outer.jar/!BOOT-INF/lib/inner.jar   (3 slashes)
      //   jar:nested:/path/outer.jar/!BOOT-INF/lib/inner.jar!/   (trailing !/)
      int separator = urlStr.indexOf("/!");
      if (separator > 0) {
        // Strip "jar:nested:" prefix then normalize multiple leading slashes to one
        String rawOuter = urlStr.substring("jar:nested:".length(), separator);
        while (rawOuter.startsWith("//")) {
          rawOuter = rawOuter.substring(1);
        }
        outerPath = rawOuter;
        // Strip trailing "!/" or bare "!" that Spring Boot appends
        innerEntry = urlStr.substring(separator + 2);
        if (innerEntry.endsWith("!/")) {
          innerEntry = innerEntry.substring(0, innerEntry.length() - 2);
        } else if (innerEntry.endsWith("!")) {
          innerEntry = innerEntry.substring(0, innerEntry.length() - 1);
        }
      }
    } else if (urlStr.startsWith("jar:file:")) {
      // jar:file:///path/outer.jar!/BOOT-INF/lib/inner.jar[!/]
      int separator = urlStr.indexOf("!/", "jar:file://".length());
      if (separator > 0) {
        String outerUri = urlStr.substring("jar:".length(), separator);
        innerEntry = urlStr.substring(separator + 2);
        if (innerEntry.endsWith("!/")) {
          innerEntry = innerEntry.substring(0, innerEntry.length() - 2);
        }
        try {
          outerPath = new File(new java.net.URI(outerUri)).getAbsolutePath();
        } catch (Exception ignored) {
        }
      }
    }

    String jarFileName =
        (innerEntry != null) ? new File(innerEntry).getName() : extractJarFileName(urlStr);
    String baseName = baseNameOf(jarFileName);

    if (outerPath != null && innerEntry != null) {
      try {
        JarMetadata nested =
            extractFromNestedEntry(outerPath, innerEntry, urlStr, jarFileName, classloaderName);
        if (nested != null) {
          return nested;
        }
      } catch (Exception e) {
        logger.log(Level.FINE, "SCA: cannot read nested JAR entry " + urlStr, e);
      }
    }

    // Fallback: filename-only
    return filenameOnlyMetadata(baseName, urlStr, JarMetadata.TYPE_NESTED_JAR, classloaderName);
  }

  // ---- Core extraction -----------------------------------------------------

  private static List<JarMetadata> extractFromJarFile(
      JarFile jar, String jarPath, File physicalFile, String classloaderName) throws IOException {

    // Step 1: collect all pom.properties entries
    List<Properties> allPomProps = findAllPomProperties(jar);

    // Shaded/uber-JAR: multiple embedded libraries
    if (allPomProps.size() > 1) {
      Checksums checksums = computeChecksums(physicalFile);
      List<JarMetadata> result = new ArrayList<>(allPomProps.size());
      for (Properties props : allPomProps) {
        String groupId = trimToEmpty(props.getProperty("groupId"));
        String artifactId = trimToEmpty(props.getProperty("artifactId"));
        String version = trimToEmpty(props.getProperty("version"));
        if (artifactId.isEmpty()) {
          continue; // skip malformed entries
        }
        String purl = buildPurl(groupId, artifactId, version);
        // License is not read per-entry for shaded JARs — use outer JAR license if needed
        result.add(
            new JarMetadata(
                artifactId,
                version,
                groupId,
                purl,
                jarPath,
                checksums.sha256,
                checksums.sha1,
                classloaderName,
                /* shaded= */ true,
                /* license= */ "",
                JarMetadata.TYPE_SHADED_ENTRY));
      }
      if (!result.isEmpty()) {
        return result;
      }
    }

    // Normal JAR (0 or 1 pom.properties)
    String groupId = "";
    String artifactId = "";
    String version = "";
    String title = "";

    if (allPomProps.size() == 1) {
      Properties props = allPomProps.get(0);
      groupId = trimToEmpty(props.getProperty("groupId"));
      artifactId = trimToEmpty(props.getProperty("artifactId"));
      version = trimToEmpty(props.getProperty("version"));
    }

    // Step 2: MANIFEST.MF — expanded field extraction
    if (groupId.isEmpty() || version.isEmpty() || artifactId.isEmpty()) {
      Manifest manifest = jar.getManifest();
      if (manifest != null) {
        Attributes attrs = manifest.getMainAttributes();

        // Display name
        if (title.isEmpty()) {
          title =
              firstNonEmpty(
                  trimToEmpty(attrs.getValue("Bundle-Name")),
                  trimToEmpty(attrs.getValue("Implementation-Title")));
        }

        // Version: Implementation-Version > Bundle-Version > Specification-Version
        if (version.isEmpty()) {
          version =
              firstNonEmpty(
                  trimToEmpty(attrs.getValue("Implementation-Version")),
                  trimToEmpty(attrs.getValue("Bundle-Version")),
                  trimToEmpty(attrs.getValue("Specification-Version")));
        }

        // Bundle-SymbolicName as artifactId candidate and groupId hint
        if (artifactId.isEmpty()) {
          String bsn = trimToEmpty(attrs.getValue("Bundle-SymbolicName"));
          int semi = bsn.indexOf(';');
          if (semi >= 0) {
            bsn = bsn.substring(0, semi).trim();
          }
          if (!bsn.isEmpty() && bsn.contains(".")) {
            artifactId = bsn.substring(bsn.lastIndexOf('.') + 1);
            if (groupId.isEmpty() && looksLikeJavaPackage(bsn)) {
              groupId = bsn;
            }
          } else if (!bsn.isEmpty()) {
            artifactId = bsn;
          }
        }

        // Implementation-Vendor-Id as groupId when it looks like a Java package
        if (groupId.isEmpty()) {
          String vendorId = trimToEmpty(attrs.getValue("Implementation-Vendor-Id"));
          if (looksLikeJavaPackage(vendorId)) {
            groupId = vendorId;
          }
        }

        // Automatic-Module-Name: split at last dot for groupId/artifactId hints
        if (groupId.isEmpty()) {
          String moduleName = trimToEmpty(attrs.getValue("Automatic-Module-Name"));
          if (looksLikeJavaPackage(moduleName)) {
            int lastDot = moduleName.lastIndexOf('.');
            groupId = moduleName.substring(0, lastDot);
            if (artifactId.isEmpty()) {
              artifactId = moduleName.substring(lastDot + 1);
            }
          }
        }
      }
    }

    // Step 3: Gradle module metadata (META-INF/gradle/*.module)
    if (groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) {
      String[] gradleMeta = findGradleModuleMetadata(jar);
      if (gradleMeta != null) {
        if (groupId.isEmpty() && gradleMeta[0] != null) {
          groupId = gradleMeta[0];
        }
        if (artifactId.isEmpty() && gradleMeta[1] != null) {
          artifactId = gradleMeta[1];
        }
        if (version.isEmpty() && gradleMeta[2] != null) {
          version = gradleMeta[2];
        }
      }
    }

    // Step 4: Filename fallback
    String baseName = baseNameOf(physicalFile.getName());
    if (artifactId.isEmpty()) {
      Matcher m = FILENAME_VERSION_PATTERN.matcher(baseName);
      if (m.matches()) {
        artifactId = m.group(1);
        if (version.isEmpty()) {
          version = m.group(2);
        }
      }
    }

    // Name resolution: artifactId > MANIFEST title > filename base
    String name;
    if (!artifactId.isEmpty()) {
      name = artifactId;
    } else if (!title.isEmpty()) {
      name = title;
    } else {
      name = baseName;
    }

    if (groupId.isEmpty()) {
      logger.fine("SCA: no groupId found for " + physicalFile.getName() + ", pURL incomplete");
    }

    // Step 5: License detection
    String license = extractLicense(jar);

    Checksums checksums = computeChecksums(physicalFile);
    String purl = buildPurl(groupId, artifactId.isEmpty() ? name : artifactId, version);

    return Collections.singletonList(
        new JarMetadata(
            name,
            version,
            groupId,
            purl,
            jarPath,
            checksums.sha256,
            checksums.sha1,
            classloaderName,
            /* shaded= */ false,
            license,
            JarMetadata.TYPE_JAR));
  }

  // ---- Nested JAR extraction -----------------------------------------------

  private static JarMetadata extractFromNestedEntry(
      String outerPath,
      String innerEntry,
      String urlStr,
      String jarFileName,
      String classloaderName)
      throws IOException {
    File outerFile = new File(outerPath);
    if (!outerFile.exists()) {
      return null;
    }

    String groupId = "";
    String artifactId = "";
    String version = "";
    Checksums checksums;

    try (JarFile outer = new JarFile(outerFile, /* verify= */ false)) {
      JarEntry entry = outer.getJarEntry(innerEntry);
      if (entry == null) {
        return null;
      }

      // Compute hashes from inner JAR bytes (read once)
      try (InputStream hashStream = outer.getInputStream(entry)) {
        checksums = computeChecksumsFromStream(hashStream);
      }

      // Scan inner JAR entries for pom.properties and MANIFEST via JarInputStream
      try (InputStream is = outer.getInputStream(entry);
          JarInputStream jis = new JarInputStream(is)) {
        Manifest manifest = jis.getManifest();
        java.util.jar.JarEntry innerJarEntry;
        while ((innerJarEntry = jis.getNextJarEntry()) != null) {
          String entryName = innerJarEntry.getName();
          if (entryName.startsWith("META-INF/maven/") && entryName.endsWith("/pom.properties")) {
            Properties props = new Properties();
            props.load(jis);
            groupId = trimToEmpty(props.getProperty("groupId"));
            artifactId = trimToEmpty(props.getProperty("artifactId"));
            version = trimToEmpty(props.getProperty("version"));
            break;
          }
        }
        // Fallback to MANIFEST if pom.properties not found
        if (artifactId.isEmpty() && manifest != null) {
          Attributes attrs = manifest.getMainAttributes();
          version =
              firstNonEmpty(
                  trimToEmpty(attrs.getValue("Implementation-Version")),
                  trimToEmpty(attrs.getValue("Bundle-Version")));
          String bsn = trimToEmpty(attrs.getValue("Bundle-SymbolicName"));
          int semi = bsn.indexOf(';');
          if (semi >= 0) {
            bsn = bsn.substring(0, semi).trim();
          }
          if (!bsn.isEmpty() && bsn.contains(".")) {
            artifactId = bsn.substring(bsn.lastIndexOf('.') + 1);
            if (looksLikeJavaPackage(bsn)) {
              groupId = bsn;
            }
          } else if (!bsn.isEmpty()) {
            artifactId = bsn;
          }
        }
      }
    }

    String baseName = baseNameOf(jarFileName);
    if (artifactId.isEmpty()) {
      Matcher m = FILENAME_VERSION_PATTERN.matcher(baseName);
      if (m.matches()) {
        artifactId = m.group(1);
        if (version.isEmpty()) {
          version = m.group(2);
        }
      } else {
        artifactId = baseName;
      }
    }

    String name = artifactId.isEmpty() ? baseName : artifactId;
    String purl = buildPurl(groupId, name, version);
    return new JarMetadata(
        name,
        version,
        groupId,
        purl,
        urlStr,
        checksums.sha256,
        checksums.sha1,
        classloaderName,
        /* shaded= */ false,
        /* license= */ "",
        JarMetadata.TYPE_NESTED_JAR);
  }

  private static JarMetadata filenameOnlyMetadata(
      String baseName, String key, String moduleType, String classloaderName) {
    String name = baseName;
    String version = "";
    Matcher m = FILENAME_VERSION_PATTERN.matcher(baseName);
    if (m.matches()) {
      name = m.group(1);
      version = m.group(2);
    }
    String purl = buildPurl("", name, version);
    return new JarMetadata(
        name,
        version,
        "",
        purl,
        key,
        "",
        "",
        classloaderName,
        /* shaded= */ false,
        /* license= */ "",
        moduleType);
  }

  // ---- License detection ---------------------------------------------------

  /**
   * Detects the SPDX license identifier from a JAR file.
   *
   * <p>Checks (in order):
   *
   * <ol>
   *   <li>MANIFEST.MF {@code Bundle-License} attribute
   *   <li>Known license file paths (META-INF/LICENSE, META-INF/LICENSE.txt, etc.)
   * </ol>
   *
   * @return SPDX identifier string, or empty string if not determinable
   */
  static String extractLicense(JarFile jar) {
    // Source 1: MANIFEST.MF Bundle-License
    try {
      Manifest mf = jar.getManifest();
      if (mf != null) {
        String bundleLicense = trimToEmpty(mf.getMainAttributes().getValue("Bundle-License"));
        if (!bundleLicense.isEmpty()) {
          String normalized = normalizeLicense(bundleLicense);
          if (!normalized.isEmpty()) {
            return normalized;
          }
        }
      }
    } catch (IOException ignored) {
    }

    // Source 2: License file content
    for (String path : LICENSE_FILE_PATHS) {
      JarEntry entry = jar.getJarEntry(path);
      if (entry != null && !entry.isDirectory()) {
        String content = readEntryFirstBytes(jar, entry, LICENSE_READ_LIMIT);
        if (!content.isEmpty()) {
          String spdx = detectSpdxIdentifier(content);
          if (spdx != null) {
            return spdx;
          }
        }
      }
    }
    return "";
  }

  /**
   * Normalizes a raw {@code Bundle-License} value to an SPDX identifier. Handles URL-based values
   * (e.g. {@code https://www.apache.org/licenses/LICENSE-2.0.txt}) and plain text.
   */
  static String normalizeLicense(String raw) {
    if (raw == null || raw.isEmpty()) {
      return "";
    }
    String lower = raw.toLowerCase();
    if (lower.contains("apache") || lower.contains("www.apache.org/licenses/license-2")) {
      return "Apache-2.0";
    }
    if (lower.contains("mit") && !lower.contains("limited")) {
      return "MIT";
    }
    if (lower.contains("gpl-3") || (lower.contains("gpl") && lower.contains("3.0"))) {
      return "GPL-3.0";
    }
    if (lower.contains("gpl-2") || (lower.contains("gpl") && lower.contains("2.0"))) {
      return "GPL-2.0";
    }
    if (lower.contains("lgpl-3") || (lower.contains("lgpl") && lower.contains("3.0"))) {
      return "LGPL-3.0";
    }
    if (lower.contains("lgpl-2") || (lower.contains("lgpl") && lower.contains("2.1"))) {
      return "LGPL-2.1";
    }
    if (lower.contains("bsd-3") || lower.contains("bsd 3-clause")) {
      return "BSD-3-Clause";
    }
    if (lower.contains("bsd-2") || lower.contains("bsd 2-clause")) {
      return "BSD-2-Clause";
    }
    if (lower.contains("eclipse") && lower.contains("2.0")) {
      return "EPL-2.0";
    }
    if (lower.contains("eclipse")) {
      return "EPL-1.0";
    }
    if (lower.contains("mozilla") || lower.contains("mpl")) {
      return "MPL-2.0";
    }
    // If raw value already looks like an SPDX expression, return it as-is
    if (raw.matches("[A-Za-z0-9.\\-+]+")) {
      return raw.trim();
    }
    return "";
  }

  /**
   * Detects a SPDX license identifier from the first {@link #LICENSE_READ_LIMIT} bytes of a license
   * file.
   *
   * @return SPDX identifier, or {@code null} if not recognised
   */
  static String detectSpdxIdentifier(String content) {
    if (content == null || content.isEmpty()) {
      return null;
    }
    // Explicit SPDX identifier line takes highest priority
    int spdxIdx = content.indexOf("SPDX-License-Identifier:");
    if (spdxIdx >= 0) {
      int start = spdxIdx + "SPDX-License-Identifier:".length();
      // Skip whitespace
      while (start < content.length() && content.charAt(start) == ' ') {
        start++;
      }
      int end = content.indexOf('\n', start);
      if (end < 0) {
        end = content.length();
      }
      String id = content.substring(start, end).trim();
      if (!id.isEmpty()) {
        return id;
      }
    }

    // Common license text fingerprints
    if (content.contains("Apache License, Version 2.0")
        || content.contains("www.apache.org/licenses/LICENSE-2.0")) {
      return "Apache-2.0";
    }
    if (content.contains("MIT License") || content.contains("Permission is hereby granted")) {
      return "MIT";
    }
    if (content.contains("GNU General Public License")) {
      if (content.contains("version 3") || content.contains("Version 3")) {
        return "GPL-3.0";
      }
      if (content.contains("version 2") || content.contains("Version 2")) {
        return "GPL-2.0";
      }
      return "GPL";
    }
    if (content.contains("GNU Lesser General Public")) {
      if (content.contains("version 3") || content.contains("Version 3")) {
        return "LGPL-3.0";
      }
      return "LGPL-2.1";
    }
    if (content.contains("BSD 3-Clause") || content.contains("Redistribution and use in source")) {
      return "BSD-3-Clause";
    }
    if (content.contains("BSD 2-Clause")) {
      return "BSD-2-Clause";
    }
    if (content.contains("Eclipse Public License") && content.contains("2.0")) {
      return "EPL-2.0";
    }
    if (content.contains("Eclipse Public License")) {
      return "EPL-1.0";
    }
    if (content.contains("Mozilla Public License")) {
      return "MPL-2.0";
    }
    return null;
  }

  /** Reads at most {@code maxBytes} bytes from a JAR entry, returns UTF-8 string. */
  private static String readEntryFirstBytes(JarFile jar, JarEntry entry, int maxBytes) {
    try (InputStream is = jar.getInputStream(entry)) {
      byte[] buf = new byte[maxBytes];
      int totalRead = 0;
      int n;
      while (totalRead < maxBytes && (n = is.read(buf, totalRead, maxBytes - totalRead)) != -1) {
        totalRead += n;
      }
      return new String(buf, 0, totalRead, java.nio.charset.StandardCharsets.UTF_8);
    } catch (IOException e) {
      return "";
    }
  }

  // ---- pom.properties -------------------------------------------------------

  /**
   * Finds and loads ALL {@code pom.properties} entries under {@code META-INF/maven/} in the JAR.
   *
   * <p>When the returned list contains more than one entry the JAR is a shaded/uber-JAR.
   *
   * @return list of loaded {@link Properties}; never null; empty if none found
   */
  static List<Properties> findAllPomProperties(JarFile jar) throws IOException {
    List<Properties> results = new ArrayList<>();
    Enumeration<JarEntry> entries = jar.entries();
    while (entries.hasMoreElements()) {
      JarEntry entry = entries.nextElement();
      if (entry.isDirectory()) {
        continue;
      }
      String name = entry.getName();
      if (name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties")) {
        Properties props = new Properties();
        try (InputStream in = jar.getInputStream(entry)) {
          props.load(in);
        }
        if (!trimToEmpty(props.getProperty("artifactId")).isEmpty()) {
          results.add(props);
        }
      }
    }
    return results;
  }

  // ---- Gradle module metadata -----------------------------------------------

  /**
   * Scans for a Gradle module metadata file ({@code META-INF/gradle/*.module}) and extracts the
   * {@code group}, {@code module}, and {@code version} fields using simple string parsing.
   *
   * @return String[]{group, module, version} with null for missing fields; or null if not found
   */
  static String[] findGradleModuleMetadata(JarFile jar) {
    Enumeration<JarEntry> entries = jar.entries();
    while (entries.hasMoreElements()) {
      JarEntry entry = entries.nextElement();
      if (entry.isDirectory()) {
        continue;
      }
      String name = entry.getName();
      if (name.startsWith("META-INF/gradle/") && name.endsWith(".module")) {
        try (InputStream is = jar.getInputStream(entry)) {
          String content = readStreamToString(is);
          String group = extractJsonField(content, "group");
          String module = extractJsonField(content, "module");
          String version = extractJsonField(content, "version");
          if (group != null || module != null || version != null) {
            return new String[] {group, module, version};
          }
        } catch (IOException ignored) {
        }
      }
    }
    return null;
  }

  /**
   * Extracts a top-level string field value from a JSON document using simple string scanning.
   * Handles only flat string fields — no nested objects or arrays.
   */
  static String extractJsonField(String json, String field) {
    String search = "\"" + field + "\"";
    int idx = json.indexOf(search);
    if (idx < 0) {
      return null;
    }
    idx = json.indexOf(':', idx + search.length());
    if (idx < 0) {
      return null;
    }
    idx++;
    // Skip whitespace
    while (idx < json.length() && json.charAt(idx) == ' ') {
      idx++;
    }
    // Must be a quoted string value
    if (idx >= json.length() || json.charAt(idx) != '"') {
      return null;
    }
    idx++; // skip opening quote
    int end = json.indexOf('"', idx);
    if (end <= idx) {
      return null;
    }
    return json.substring(idx, end);
  }

  // ---- pURL construction ----------------------------------------------------

  /**
   * Builds a Package URL string in {@code pkg:maven/{groupId}/{artifactId}@{version}} format.
   * Returns an empty string when {@code artifactId} is empty.
   */
  static String buildPurl(String groupId, String artifactId, String version) {
    if (artifactId.isEmpty()) {
      return "";
    }
    StringBuilder sb = new StringBuilder("pkg:maven/");
    if (!groupId.isEmpty()) {
      sb.append(groupId).append('/');
    }
    sb.append(artifactId);
    if (!version.isEmpty()) {
      sb.append('@').append(version);
    }
    return sb.toString();
  }

  // ---- Checksum computation -------------------------------------------------

  /** Holds SHA-256 and SHA-1 hex digests computed in a single file read pass. */
  static final class Checksums {
    final String sha256;
    final String sha1;

    Checksums(String sha256, String sha1) {
      this.sha256 = sha256;
      this.sha1 = sha1;
    }
  }

  /** Computes SHA-256 and SHA-1 checksums of the given file in a single read pass. */
  static Checksums computeChecksums(File file) {
    try (FileInputStream fis = new FileInputStream(file)) {
      return computeChecksumsFromStream(fis);
    } catch (IOException e) {
      logger.log(Level.FINE, "SCA: could not read JAR for checksums: " + file.getPath(), e);
      return new Checksums("", "");
    }
  }

  /** Computes SHA-256 and SHA-1 from an input stream in a single pass. */
  static Checksums computeChecksumsFromStream(InputStream is) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
      byte[] buf = new byte[8192];
      int n;
      while ((n = is.read(buf)) != -1) {
        sha256.update(buf, 0, n);
        sha1.update(buf, 0, n);
      }
      return new Checksums(toHex(sha256.digest()), toHex(sha1.digest()));
    } catch (NoSuchAlgorithmException e) {
      logger.log(Level.WARNING, "SCA: required digest algorithm unavailable", e);
      return new Checksums("", "");
    } catch (IOException e) {
      return new Checksums("", "");
    }
  }

  /**
   * Computes the hex-encoded SHA-256 digest of the given file. Retained for backward compatibility
   * with tests.
   */
  static String computeSha256(File file) {
    return computeChecksums(file).sha256;
  }

  // ---- Utilities -----------------------------------------------------------

  /** Strips the {@code .jar} suffix from a filename. */
  static String baseNameOf(String fileName) {
    if (fileName.endsWith(".jar")) {
      return fileName.substring(0, fileName.length() - 4);
    }
    return fileName;
  }

  /** Extracts the last path segment (filename) from a URL string. */
  private static String extractJarFileName(String urlStr) {
    int q = urlStr.indexOf('?');
    if (q > 0) {
      urlStr = urlStr.substring(0, q);
    }
    if (urlStr.endsWith("!/")) {
      urlStr = urlStr.substring(0, urlStr.length() - 2);
    }
    int slash = urlStr.lastIndexOf('/');
    return slash >= 0 ? urlStr.substring(slash + 1) : urlStr;
  }

  /**
   * Returns true when the string looks like a Java package name: lowercase segments separated by
   * dots, at least two segments, no spaces.
   */
  private static boolean looksLikeJavaPackage(String s) {
    if (s == null || s.isEmpty() || !s.contains(".")) {
      return false;
    }
    return s.matches("[a-z][a-z0-9]*(\\.[a-z][a-z0-9]*)+");
  }

  /** Returns the first non-empty value from the provided candidates. */
  private static String firstNonEmpty(String... values) {
    for (String v : values) {
      if (v != null && !v.isEmpty()) {
        return v;
      }
    }
    return "";
  }

  private static String trimToEmpty(String s) {
    return s == null ? "" : s.trim();
  }

  /** Reads all bytes from an InputStream into a UTF-8 String (Java 8 compatible). */
  private static String readStreamToString(InputStream is) throws IOException {
    StringBuilder sb = new StringBuilder();
    byte[] buf = new byte[4096];
    int n;
    while ((n = is.read(buf)) != -1) {
      sb.append(new String(buf, 0, n, java.nio.charset.StandardCharsets.UTF_8));
    }
    return sb.toString();
  }

  private static String toHex(byte[] digest) {
    StringBuilder hex = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      hex.append(String.format("%02x", b));
    }
    return hex.toString();
  }
}
