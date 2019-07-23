// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.ctf.game;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-checker' library on application startup.
    static {
        System.loadLibrary("rary");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        /*
        // Example of a call to a native method
        byte[] key = new byte[]{9, 0, 0, 8, 0, 7, 2, 0, 0, 11, 0, 15, 13, 0, 10, 0, 6, 0, 0, 5, 14, 0, 0, 4, 0, 3, 0, 0, 12, 0, 1, 0};
        byte[] payload = new byte[] {120, -100, -19, -108, 97, 110, -61, 48, 8, -123, -81, 68, -91, 93, 35, 33, 78, -18, 97, 12, -8, -2, 26, -58, 110, -89, 104, -53, -102, 127, 105, 85, 62, -71, -22, -85, -79, -31, 65, -94, -34, 110, 65, 16, 4, -63, -121, 1, -81, 77, -72, -65, -114, 112, 127, 29, -31, -2, 58, -62, -3, 117, -124, -5, -21, 56, -31, 126, -46, -84, -107, -85, -14, -92, 8, 120, -65, 40, 69, -77, -128, -84, 32, -10, -61, -30, 83, 26, -127, 35, 109, 55, -59, 15, -73, -53, 0, -53, 125, -77, -105, 72, -88, -6, 48, 37, 80, 82, 91, -29, -120, 25, -80, -75, 11, 81, 58, -21, 94, -4, -77, 102, 40, -106, 9, -83, 80, -37, -100, 69, -118, 72, -106, -102, 101, 36, -91, 92, 122, -119, 3, -67, -52, -51, 125, -41, 107, 38, 75, 101, -90, -68, -121, -39, -78, 110, 56, -101, 69, -10, 78, -20, -36, -76, -116, -66, 10, -93, 23, 27, 77, 62, 66, -108, 79, -70, 79, -112, -5, -44, -38, -28, -79, -113, 31, 65, 42, 72, 3, -121, -5, -86, 50, 70, 123, -96, 17, -78, -23, -22, 14, -59, 83, -7, -73, -25, 66, -58, -90, -68, -77, -2, -116, -112, -14, -42, 19, -76, -125, -110, 72, -10, 33, 60, 59, 123, -80, 71, -54, -64, 46, -108, 81, -103, -76, 9, 82, 32, 106, 1, 85, -10, -72, -67, 92, -16, -97, -42, -90, -55, -75, -25, 32, -101, -96, 122, 46, -127, -66, -31, -79, -51, -14, 122, -14, 22, -93, -54, 94, -43, -42, 62, -60, -89, -35, -17, -64, -33, 91, 63, -81, -21, 115, -3, 7, 52, -13, 113, 1, 57, 14, -63, 7, -4, -25, -68, 42, 95, 79, -35, 7, 65, 16, 4, 65, 16, 4, 65, 16, 4, -63, -37, -15, 13, -125, -25, -51, 52};
        byte[] cipher = new Checker().encrypt(key, payload);
        StringBuilder sb = new StringBuilder();
        for (byte b : cipher) {
            sb.append(String.format("%d, ", b));
        }
        Log.d("dada", sb.toString());
        */
    }
}
