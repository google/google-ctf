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
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.util.TypedValue;
import android.view.SoundEffectConstants;
import android.view.View;
import android.widget.Button;
import android.widget.GridLayout;

public class S {

    public static String I = "FLAG_FACTORY";
    public static Activity a;

    public S(final Activity a) {
        S.a = a;

        Context c = a.getApplicationContext();
        GridLayout l = (GridLayout) a.findViewById(R.id.foodLayout);

        String[] ll = new String[] {
                "\uD83C\uDF55", "\uD83C\uDF6C", "\uD83C\uDF5E", "\uD83C\uDF4E",
                "\uD83C\uDF45", "\uD83C\uDF59", "\uD83C\uDF5D", "\uD83C\uDF53",
                "\uD83C\uDF48", "\uD83C\uDF49", "\uD83C\uDF30", "\uD83C\uDF57",
                "\uD83C\uDF64", "\uD83C\uDF66", "\uD83C\uDF47", "\uD83C\uDF4C",
                "\uD83C\uDF63", "\uD83C\uDF44", "\uD83C\uDF4A", "\uD83C\uDF52",
                "\uD83C\uDF60", "\uD83C\uDF4D", "\uD83C\uDF46", "\uD83C\uDF5F",
                "\uD83C\uDF54", "\uD83C\uDF5C", "\uD83C\uDF69", "\uD83C\uDF5A",
                "\uD83C\uDF68", "\uD83C\uDF3E", "\uD83C\uDF3D", "\uD83C\uDF56",
        };

        for (int i = 0; i < 32; ++i) {
            Button b = new Button(c);

            GridLayout.LayoutParams p = new GridLayout.LayoutParams();
            p.width = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                    60, a.getResources().getDisplayMetrics());
            p.height = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP,
                    60, a.getResources().getDisplayMetrics());

            final int id = i;

            b.setLayoutParams(p);
            b.setText(ll[i]);
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    v.playSoundEffect(SoundEffectConstants.CLICK);

                    Intent i = new Intent(I);
                    i.putExtra("id", id);
                    a.sendBroadcast(i);
                }
            });

            l.addView(b);
        }

        IntentFilter f = new IntentFilter();
        f.addAction(I);
        a.registerReceiver(new F(a), f);
    }
}
