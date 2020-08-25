// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.ads.sdk.dynamic;

import org.apache.commons.io.IOUtils;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Base64;

import com.ads.sdk.common.IAdFactory;
import com.ads.sdk.common.Logger;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.CodeSigner;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import dalvik.system.DexClassLoader;

public class Loader {

    private static final String ASSET_APK_NAME = "ads-impl.apk";

    private static final String CERT_PKCS7_BASE64 = "" +
            "MIIC6AYJKoZIhvcNAQcCoIIC2TCCAtUCAQExADALBgkqhkiG9w0BBwGgggK9MIICuTCCAaGgAwIB" +
            "AgIEEVjZpzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJVUzAeFw0yMDA1MTYwMTIzMjlaFw00" +
            "NTA1MTAwMTIzMjlaMA0xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC" +
            "AQEAmaQMLr9fYBTElkq2Z7pPX9X1f5CYGdRVpuC3W/AIu9ec1WYXvJavFnSk5R9h8boKlqds6TQG" +
            "nTu0NTbrXlMGN/XBy0qsqP7Kj2L7mv3k57YP35qc+gmSJZI3zqbYwpaTlP+cH6RLtKgOPnTw9WhZ" +
            "/X+ohz3iv7b5Zt6NolPTATsDn0SiF5bWaOLQ/sEahDPoHIjWt9+Sy0p5z8QOHJY58iB0Fzls1Bdg" +
            "CFHtpAVf6VmoDEHvEsljJhq8/tqO62mhheHxaf93IJAD0Wyj0oUXDnBN+BiHw9bUqaQTuNchu7Fy" +
            "e3+WyR1SY1KA5vWzxkgR8zaNICsbZI7mvK5gS0AoWwIDAQABoyEwHzAdBgNVHQ4EFgQUAPOd0nsv" +
            "Vuw3TWifPOa75CxXO3cwDQYJKoZIhvcNAQELBQADggEBACCa/uAeLiB+d+L65jWJpHALJXfyoUqm" +
            "O7KUfme15/4KbxzFvk1+b3pIcycaWgjA+UtLR94lt6mXSh07mfp2IY71TO96mUwrF8tFA/xSskpN" +
            "rI3ogOdKV4PNn7GpkBM7xpI/XRp9vwloyJCfDgmVehq57n/hwTr9Ib1qqbRQSBO/qSNn9wxUmAdi" +
            "irDjPM0FijAKuYBN70CLLEJZ+ry/arS+piqCJoU0US4w0jv6OCE8eVZj5rxdLkty4hcS3oFcXsgE" +
            "LQSKzVNl6uXor1rm3B5eN4/HouvHY45gMKvlZ3n7Gz1ZJ5sxSSBmpe7Ew8aOOcbjfC3gHbVU4Bvp" +
            "phAzeaQxAA==";

    private static final CertPath GOLDEN_CERT_PATH = certPathFromBase64(CERT_PKCS7_BASE64);

    private static CertPath certPathFromBase64(String certBase64) {
        try {
            return CertificateFactory.getInstance("X.509").generateCertPath(new ByteArrayInputStream(Base64.decode(CERT_PKCS7_BASE64, 0)), "PKCS7");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean validateJarFile(Context context, File file) {
        try {
            JarFile jar = new JarFile(file, true);
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                // Just validate the .DEX files. This is all that is truely needed, but could also
                // provide a red herring.
                if (entry.getName().toUpperCase().endsWith(".DEX")) {
                    // Have to completely read the input stream before we can verify it...
                    IOUtils.copy(jar.getInputStream(entry), new OutputStream() {
                        @Override
                        public void write(int b) {
                        }
                    });
                    CodeSigner[] signers = entry.getCodeSigners();
                    if (signers == null) {
                        Logger.e("Found an unsigned dex file: " + entry.getName());
                        return false;
                    }
                    boolean ok = false;
                    for (CodeSigner signer : signers) {
                        if (GOLDEN_CERT_PATH.equals(signer.getSignerCertPath())) {
                            ok = true;
                        }
                    }
                    if (!ok) {
                        Logger.e("APK is not signed with valid cert");
                        return false;
                    }
                }
            }
            return true;
        } catch (RuntimeException | IOException e) {
            Logger.e("Something fishy with the APK, best replace it", e);
        }
        return false;
    }

    private static File getJarDirectory(Context context) {
        File dexPath = context.getDir("ads", Context.MODE_PRIVATE);
        return dexPath;
    }

    private static File getJarFile(Context context) {
        AssetManager assets = context.getAssets();
        File jarFile = new File(getJarDirectory(context), ASSET_APK_NAME);
        if (!jarFile.exists() || !validateJarFile(context, jarFile)) {
            Logger.i("Detected updated to impl, updating!!!");
            try {
                InputStream inputStream = assets.open(ASSET_APK_NAME);
                FileOutputStream outputStream = new FileOutputStream(jarFile);
                IOUtils.copy(inputStream, outputStream);
                jarFile.setReadable(true, false);
                jarFile.setExecutable(true, false);
            } catch (IOException e) {
                Logger.e("Unable to copy jar file!!!", e);
            }
        } else {
            Logger.i("Impl up to date, good to go!");
        }
        return jarFile;
    }

    public static Loader create(Context context) {
        File jarFile = getJarFile(context);
        return new Loader(new DexClassLoader(jarFile.toString(), context.getCodeCacheDir().toString(), null, Context.class.getClassLoader()));
    }

    private final ClassLoader classLoader;

    private Loader(ClassLoader classLoader) {
        this.classLoader = classLoader;
    }

    public IAdFactory newAdFactory() {
        return IAdFactory.Stub.asInterface(load("com.ads.sdk.impl.AdFactoryImpl"));
    }

    private <T> T load(String className) {
        try {
            return (T) classLoader.loadClass(className).newInstance();
        } catch (Throwable e) {
            Logger.e("Cannot load class: " + className, e);
            return null;
        }
    }
}
