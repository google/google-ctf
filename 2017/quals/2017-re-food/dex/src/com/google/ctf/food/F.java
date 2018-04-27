// Copyright 2018 Google LLC
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



package com.google.ctf.food;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.widget.Toast;

public class F extends BroadcastReceiver {

    private Activity a;
    private byte[] k;
    private int c;

    private static byte[] flag = new byte[] {
            -19, 116, 58, 108, -1, 33, 9, 61, -61, -37, 108, -123, 3, 35, 97, -10, -15, 15, -85,
            -66, -31, -65, 17, 79, 31, 25, -39, 95, 93, 1, -110, -103, -118, -38, -57, -58, -51, -79
    };

    public F(Activity activity) {
        this.a = activity;

        k = new byte[8];
        for (int i = 0; i < 8; ++i) {
            k[i] = 0;
        }
        c = 0;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        int id = intent.getExtras().getInt("id");

        k[c] = (byte) id;

        cc();

        c++;
        if (c == 8) {
            c = 0;
            k = new byte[8];
            for (int i = 0; i < 8; ++i) {
                k[i] = 0;
            }
        }
    }

    public void cc() {
        byte[] x = new byte[] {26, 27, 30, 4, 21, 2, 18, 7};

        for (int i = 0; i < 8; ++i) {
            x[i] ^= k[i];
        }

        if (new String(x).compareTo("\023\021\023\03\04\03\01\05") == 0) {
            Toast.makeText(a.getApplicationContext(), new String(ℝ.ℂ(flag, k)),
                    Toast.LENGTH_LONG).show();
        }
    }
}
