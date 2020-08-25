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

package com.ads.sdk.common;

import android.util.Log;

public class Logger {
    private final static String TAG = "ExampleApp";

    public static void i(String message) {
        Log.i(TAG, message);
    }

    public static void i(String message, Throwable t) {
        Log.i(TAG, message, t);
    }

    public static void w(String message) {
        Log.w(TAG, message);
    }

    public static void w(String message, Throwable t) {
        Log.w(TAG, message, t);
    }

    public static void e(String message) {
        Log.e(TAG, message);
    }

    public static void e(String message, Throwable t) {
        Log.e(TAG, message, t);
    }
}
