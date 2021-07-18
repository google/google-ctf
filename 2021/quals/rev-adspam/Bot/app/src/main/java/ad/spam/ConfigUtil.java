// Copyright 2021 Google LLC
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

package ad.spam;

import android.content.Context;
import android.content.SharedPreferences;


public class ConfigUtil {
    public static String prefName = NativeAdapter.transform(new byte[] {
            0x20, 0x2a, 0x3c, 0x02, 0x0a, 0x23, 0x7a, 0x35, 0x27, 0x21, 0x3f, 0x55});
    public static String keyLastUpdate = NativeAdapter.transform(new byte[]{
            0x0f, 0x27, 0x26, 0x13, 0x31, 0x27, 0x5d, 0x3b, 0x3d, 0x22});
    public static String keyIsAdmin = NativeAdapter.transform(new byte[]{
            0x0a, 0x35, 0x14, 0x03, 0x09, 0x3e, 0x57});

    private Context context;

    public ConfigUtil(Context context) {
        this.context = context;
    }
    public void storeLastUpdate(long lastUpdate) {
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putLong(keyLastUpdate, lastUpdate);
        editor.apply();
    }

    public Long getLastUpdate() {
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        return pref.getLong(keyLastUpdate, 0);
    }

    public void setAdmin() {
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = pref.edit();
        editor.putBoolean(keyIsAdmin, true);
        editor.apply();
    }

    public boolean isAdmin() {
        SharedPreferences pref = context.getSharedPreferences(prefName, Context.MODE_PRIVATE);
        return pref.getBoolean(keyIsAdmin, false);
    }
}
