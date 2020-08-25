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

package com.example.app;

import androidx.appcompat.app.AppCompatActivity;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;

import com.ads.sdk.BannerAd;

public class MainActivity extends AppCompatActivity {

    private static final String ACTION_LOAD_AD = "com.example.app.LOAD_AD";
    private static final String ACTION_SET_FIELDS = "com.example.app.SET_FIELDS";

    private BroadcastReceiver loadReceiver;
    private BroadcastReceiver setFieldsReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final BannerAd ad = findViewById(R.id.banner_ad);
        loadReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
            Uri uri = intent.getData();
            if (uri != null) {
                ad.loadAd(uri.toString());
            }
            }
        };
        IntentFilter loadAdFilter = new IntentFilter();
        loadAdFilter.addAction(ACTION_LOAD_AD);
        loadAdFilter.addDataScheme("https");
        loadAdFilter.addDataScheme("http");
        registerReceiver(loadReceiver, loadAdFilter);

        final TextView usernameField = findViewById(R.id.username);
        final TextView passwordField = findViewById(R.id.password);
        setFieldsReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
            String username = intent.getStringExtra("user");
            String password = intent.getStringExtra("pass");
            usernameField.setText(username);
            passwordField.setText(password);
            }
        };
        IntentFilter setFieldsFilter = new IntentFilter();
        setFieldsFilter.addAction(ACTION_SET_FIELDS);
        registerReceiver(setFieldsReceiver, setFieldsFilter);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        this.unregisterReceiver(loadReceiver);
        this.unregisterReceiver(setFieldsReceiver);
    }
}
