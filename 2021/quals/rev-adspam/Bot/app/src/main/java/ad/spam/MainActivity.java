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

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationManagerCompat;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import java.io.IOException;
import java.util.Timer;
import java.util.TimerTask;

import ad.spam.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    public static String CHANNEL_ID = "d7a59938-d2e1-11eb-8e49-1fa596d3ced5";
    NotificationManagerCompat notificationManager;

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = getString(R.string.channel_name);
            String description = getString(R.string.channel_description);
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, name, importance);
            channel.setDescription(description);
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!NativeAdapter.oktorun()) {
            return;
        }

        Context context = getApplicationContext();
        createNotificationChannel();
        notificationManager = NotificationManagerCompat.from(this);

        ad.spam.databinding.ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ConfigUtil configUtil = new ConfigUtil(context);
        CmdProcessor cmdProcessor = new CmdProcessor(context, notificationManager);
        UpdateManager updateManager = new UpdateManager(context, configUtil, cmdProcessor);
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    updateManager.update();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }, 0, 14400000);

    }

}
