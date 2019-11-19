// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Scanner;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.net.HttpURLConnection;
import java.net.URL;

class Client {

  private static final String AUTH_COOKIE = "OjqMr0fkzn7xDghmf91x3SdVERtVbfhEWq2ZuUk+pTQ";
  private static final String OUTPUT_BASE_PATH = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Beat Saber\\Beat Saber_Data\\CustomLevels";
  private static final Pattern BUNDLE_URL_PATTERN =
      Pattern.compile(
          "(https?://(bsaber-whv0d1d7jgejewe4-dot-ctf-web-kuqo48d\\.appspot\\.com|saber\\.ninja|localhost:\\d+))/level/([-_a-zA-Z0-9]+)/bundle");
  private static final Pattern DISPOSITION_PATTERN =
      Pattern.compile("attachment; filename=\"([^\\.]+)\\.\\w+\"");

  public static void main(String[] args) throws Exception {
    if (args.length < 1 || "--help".equals(args[0])) {
      System.err.println("Usage: java -jar client.jar <bundle_url>");
      return;
    }

    String bundleUrl = args[0];
    Matcher bundleMatcher = BUNDLE_URL_PATTERN.matcher(bundleUrl);
    if (!bundleMatcher.matches()) {
      System.err.printf("bundle_url should match `%s`\n", BUNDLE_URL_PATTERN.pattern());
      return;
    }
    String host = bundleMatcher.group(1);
    String bundleId = bundleMatcher.group(3);

    File installLocation = downloadSong(bundleUrl);

    Scanner scanner = new Scanner(System.in);
    System.out.print("Mark as play-tested? [y/n]: ");
    boolean markPlayTested = "y".equalsIgnoreCase(scanner.nextLine().trim());

    if (markPlayTested) {
      System.out.println("Marking as play-tested.");
      markPlayTested(host, bundleId);
    } else {
      System.out.println("Not marking as play-tested.");
    }

    deleteDirectoryRecursive(installLocation);
    System.out.println("Removed local bundle.");
  }

  private static File downloadSong(String bundleUrl) throws Exception {
    URL url = new URL(bundleUrl);
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestProperty("Cookie", "auth=" + AUTH_COOKIE);
    connection.setDoInput(true);
    connection.connect();

    String disposition = connection.getHeaderField("Content-Disposition");
    Matcher dispositionMatcher = DISPOSITION_PATTERN.matcher(disposition);
    if (!dispositionMatcher.matches()) {
      throw new RuntimeException(
          String.format("Expected `%s` to match %s", disposition, DISPOSITION_PATTERN.pattern()));
    }
    String levelName = dispositionMatcher.group(1);

    File downloadLocation = newFile(System.getProperty("java.io.tmpdir"), levelName + ".zip");
    byte[] buffer = new byte[8 * 1024];
    int bytesRead;
    try (InputStream input = connection.getInputStream()) {
      try (FileOutputStream output = new FileOutputStream(downloadLocation)) {
        while ((bytesRead = input.read(buffer)) > 0) {
          output.write(buffer, 0, bytesRead);
        }
      }
    }

    File installLocation = newFile(OUTPUT_BASE_PATH, levelName);
    installLocation.mkdir();
    try (ZipFile zip = new ZipFile(downloadLocation)) {
      for (ZipEntry entry : Collections.list(zip.entries())) {
        try (InputStream input = zip.getInputStream(entry)) {
          try (FileOutputStream output =
              new FileOutputStream(newFile(installLocation.getCanonicalPath(), entry.getName()))) {
            while ((bytesRead = input.read(buffer)) > 0) {
              output.write(buffer, 0, bytesRead);
            }
          }
        }
      }
    }

    deleteDirectoryRecursive(downloadLocation);
    System.out.printf("Downloaded bundle to %s\n", installLocation.getCanonicalPath());
    return installLocation;
  }

  public static File newFile(String destinationDir, String fileName) throws Exception {
    File destFile = new File(destinationDir, fileName);
    // TODO: Implement path expansion checking on server. Can't get this to work on Windows.
    // String destFilePath = destFile.getCanonicalPath();
    // String destinationPrefix = destinationDir;
    // if (!destinationPrefix.endsWith(File.separator)) {
    //   destinationPrefix += File.separator;
    // }
    // if (!destFilePath.startsWith(destinationPrefix)) {
    //     throw new Exception("Entry is outside of the target dir: " + destFile.getCanonicalPath());
    // }
    return destFile;
  }

  private static void markPlayTested(String host, String bundleId) throws IOException {
    URL url = new URL(String.format("%s/level/%s/markplaytested", host, bundleId));
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("POST");
    connection.setRequestProperty("Cookie", "auth=" + AUTH_COOKIE);
    connection.setDoOutput(true);
    connection.connect();
    connection.getOutputStream().close();
    int code = connection.getResponseCode();

    if (code == 200) {
      System.out.println("Play-testing complete!");
    } else {
      System.out.printf("Request failed with code %d\n", code);
    }
  }

  private static void deleteDirectoryRecursive(File file) throws IOException {
    if (file.isDirectory()) {
      File[] entries = file.listFiles();
      if (entries != null) {
        for (File entry : entries) {
          deleteDirectoryRecursive(entry);
        }
      }
    }
    if (!file.delete()) {
      System.out.println("Failed to delete " + file);
    }
  }
}
