// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: Sajjad "JJ" Arshad (sajjadium)

package com.google.ctf.pwn.tridroid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import java.util.Base64;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebMessage;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MainActivity extends AppCompatActivity {
    private static final String SET_NAME_INTENT = "com.google.ctf.pwn.tridroid.SET_NAME";
    private static final String SET_FLAG_INTENT = "com.google.ctf.pwn.tridroid.SET_FLAG";

    static {
        System.loadLibrary("tridroid");
    }

    private BroadcastReceiver broadcastReceiver;
    private SecretKey secretKey;
    private String flag = "";
    private TextView textView;
    private EditText editText;
    private WebView webView;

    private static String hex(byte[] bytes) {
        StringBuilder hexed = new StringBuilder();
        for (byte b : bytes) {
            hexed.append(String.format("%02x", b));
        }
        return hexed.toString();
    }

    private static byte[] unhex(String hexed) {
        byte[] bytes = new byte[hexed.length() / 2];
        for (int i = 0; i < hexed.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hexed.substring(i, i + 2), 16);
        }
        return bytes;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = findViewById(R.id.textView);
        editText = findViewById(R.id.editText);
        webView = findViewById(R.id.webView);

        generateSecretKey();
        createPasswordFile();

        editText.addTextChangedListener(new TextWatcher() {
            public void afterTextChanged(Editable s) {
                webView.postWebMessage(new WebMessage(editText.getText().toString()), Uri.parse("*"));
            }

            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }
        });

        broadcastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (intent.getAction().equals(SET_NAME_INTENT)) {
                    editText.setText(new String(Base64.getDecoder().decode(intent.getStringExtra("data")), UTF_8));
                } else if (intent.getAction().equals(SET_FLAG_INTENT)) {
                    flag = new String(Base64.getDecoder().decode(intent.getStringExtra("data").trim()), UTF_8).trim();
                }
            }
        };

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(SET_NAME_INTENT);
        intentFilter.addAction(SET_FLAG_INTENT);
        registerReceiver(broadcastReceiver, intentFilter);

        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.getSettings().setAllowFileAccessFromFileURLs(true);
        webView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);

        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient());
        webView.addJavascriptInterface(this, "bridge");

        webView.loadUrl("file:///android_asset/index.html");
    }

    @JavascriptInterface
    public String manageStack(String password, String operation, String data) {
        try (FileInputStream fis = getApplication().openFileInput("password.txt")) {
            if (password.equals(new BufferedReader(new InputStreamReader(fis)).readLine())) {
                return hex(manageStack(operation, unhex(data)));
            }
        } catch (Exception e) {
            Log.e("gCTF", "Reading password file has failed ...", e);
        }

        return "";
    }

    public native byte[] manageStack(String operation, byte[] data);

    private void generateSecretKey() {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(new String(Base64.getDecoder().decode("VHJpYW5nbGUgb2YgQW5kcm9pZA=="), UTF_8).toCharArray(), new byte[32], 65536, 256);
            secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (Exception e) {
            Log.e("TriDroid", "Generating AES key has failed ...", e);
        }
    }

    public void showFlag() {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
            byte[] encryptedFlag = cipher.doFinal(flag.getBytes(UTF_8));
            Log.d("TriDroid", "Flag: " + new String(Base64.getEncoder().encode(encryptedFlag), UTF_8));
        } catch (Exception e) {
            Log.e("TriDroid", "Showing flag has failed ...", e);
        }
    }

    private void createPasswordFile() {
        try (FileOutputStream fos = getApplication().openFileOutput("password.txt", Context.MODE_PRIVATE)) {
            fos.write(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.e("TriDroid", "Generating password file has failed ...", e);
        }
    }
}
