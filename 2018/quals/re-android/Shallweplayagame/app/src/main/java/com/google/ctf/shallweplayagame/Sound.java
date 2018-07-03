/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.ctf.shallweplayagame;

import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Handler;

public class Sound {
    static final ToneGenerator generator
            = new ToneGenerator(AudioManager.STREAM_MUSIC, 100);

    static void Blip() {
        final Handler handler = new Handler();
        handler.post(new Runnable() {
            @Override
            public void run() {
                generator.startTone(ToneGenerator.TONE_PROP_BEEP, 100);
            }
        });
    }

    static void Fail() {
        final Handler handler = new Handler();
        handler.post(new Runnable() {
            @Override
            public void run() {
                generator.startTone(ToneGenerator.TONE_CDMA_CALL_SIGNAL_ISDN_PING_RING, 100);
            }
        });
    }
}
