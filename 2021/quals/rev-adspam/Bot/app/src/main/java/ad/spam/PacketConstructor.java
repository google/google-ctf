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
import android.os.Build;
import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;


public class PacketConstructor {

    private static class LicenseInfo {
        public String raw;
        public String name;
        public String number;
        public int isAdmin;

        public LicenseInfo(String raw, String name, String number, int isAdmin) {
            this.raw = raw;
            this.name = name;
            this.number = number;
            this.isAdmin = isAdmin;
        }
    }

    private static final String PARAM_OS_VERSION =  NativeAdapter.transform(
            new byte[]{0x0c, 0x35, 0x0a, 0x11, 0x01, 0x25, 0x4a, 0x33, 0x26, 0x29});
    private static final String PARAM_API_LEVEL = NativeAdapter.transform(
            new byte[]{0x02, 0x36, 0x3c, 0x38, 0x08, 0x32, 0x4f, 0x3f, 0x25});
    private static final String PARAM_DEVICE = NativeAdapter.transform(
            new byte[]{0x07, 0x23, 0x23, 0x0e, 0x07, 0x32});
    private static final String PARAM_NAME =
            NativeAdapter.transform(new byte[]{0x0d, 0x27, 0x38, 0x02});
    private static final String PARAM_IS_ADMIN =
            NativeAdapter.transform(new byte[]{0x0a, 0x35, 0x0a, 0x06, 0x00, 0x3a, 0x50, 0x34});
    private static final String PARAM_DEVICE_INFO =
            NativeAdapter.transform(new byte[]{
                    0x07, 0x23, 0x23, 0x0e, 0x07, 0x32, 0x66, 0x33, 0x27, 0x21, 0x39});
    private static final String PARAM_LICENSE =
            NativeAdapter.transform(new byte[]{0x0f, 0x2f, 0x36, 0x02, 0x0a, 0x24, 0x5c});

    private final Context context;

    public PacketConstructor(Context context) {
        this.context = context;
    }

    private JSONObject getDeviceInfo() {
        JSONObject deviceInfo = new JSONObject();
        try {
            deviceInfo.put(PARAM_OS_VERSION, System.getProperty("os.version"));
            deviceInfo.put(PARAM_API_LEVEL, Build.VERSION.SDK_INT);
            deviceInfo.put(PARAM_DEVICE, android.os.Build.DEVICE);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return deviceInfo;
    }

    private byte[] parseValue(byte[] data, int ptr) {
        int len = data[ptr];
        ptr += 1;
        return Arrays.copyOfRange(data, ptr, ptr + len);
    }

    public LicenseInfo readLicense() throws IOException {
        InputStream inputStream = context.getResources().openRawResource(R.raw.lic);
        InputStreamReader sReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(sReader);

        StringBuilder builder = new StringBuilder();
        ByteArrayOutputStream licenseStream = new ByteArrayOutputStream();
        String line;
        while((line = bufferedReader.readLine()) != null) {
            byte[] word = NativeAdapter.declicstr(Base64.decode(line, Base64.DEFAULT));
            licenseStream.write(word);
            builder.append(line);
            builder.append("::");
        }
        byte[] fullLicense = licenseStream.toByteArray();
        String name = new String(parseValue(fullLicense, 0));
        int ptr = name.length() + 1;
        String number =
                new String(parseValue(fullLicense, ptr));
        ptr += number.length() + 1;
        int admin = Integer.parseInt(new String(parseValue(fullLicense, ptr)));
        return new LicenseInfo(builder.toString(), name, number, admin);
    }

    public JSONObject composePacket() throws IOException {
        JSONObject packet = new JSONObject();

        LicenseInfo licenseInfo = readLicense();
        try {
            packet.put(PARAM_NAME, licenseInfo.name);
            packet.put(PARAM_IS_ADMIN, licenseInfo.isAdmin);
            packet.put(PARAM_DEVICE_INFO, getDeviceInfo());
            packet.put(PARAM_LICENSE, licenseInfo.raw);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return packet;
    }
}
