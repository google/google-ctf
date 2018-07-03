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

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Typeface;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;

import java.util.Queue;

public class Cell extends RelativeLayout {

    enum Value {EMPTY, X, O, DEATH}

    static final String LABEL_EMPTY = " ";
    static final String LABEL_O = "O";
    static final String LABEL_X = "X";
    static final String LABEL_DEATH = new String(Character.toChars(0x2622));

    Context context;
    Queue<AnimatorSet> animQueue;
    public Value value;
    TextView text;

    public Cell(Context context, Queue<AnimatorSet> animQueue) {
        super(context);
        this.context = context;
        this.animQueue = animQueue;
        this.value = Value.EMPTY;

        initializeLayout();
        initializeTextView();
    }

    private int dpValue(int px) {
        Resources r = context.getResources();
        return (int) TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, px, r.getDisplayMetrics());
    }

    private void initializeLayout() {
        int vPadding = dpValue(5);
        int hPadding = dpValue(5);
        this.setPadding(vPadding, hPadding, vPadding, hPadding);

        int size = dpValue(100);
        LayoutParams params = new LayoutParams(size, size);

        int margin = dpValue(5);
        params.setMargins(margin, margin, margin, margin);

        this.setLayoutParams(params);
        this.setBackground(context.getResources().getDrawable(R.drawable.background));
    }

    private void initializeTextView() {
        text = new TextView(context);
        text.setTypeface(Typeface.MONOSPACE);
        text.setTextColor(Color.WHITE);
        text.setTextSize(dpValue(20));

        RelativeLayout.LayoutParams params = new LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        params.addRule(RelativeLayout.CENTER_IN_PARENT);
        text.setLayoutParams(params);
        text.setGravity(Gravity.CENTER_HORIZONTAL);

        text.setText(LABEL_EMPTY);
        this.addView(text);
    }

    public void setValue(Value v, int speed) {
        value = v;
        String label;
        if (v == Value.EMPTY) {
            label = LABEL_EMPTY;
        } else if (v == Value.X) {
            label = LABEL_X;
        } else if (v == Value.O) {
            label = LABEL_O;
        } else {
            label = LABEL_DEATH;
        }
        animQueue.add(makeAnimation(label, speed));
    }

    public void setValue(Value v) {
        setValue(v, 100);
    }

    private AnimatorSet makeAnimation(final String label, int speed) {
        AnimatorSet set = new AnimatorSet();

        ValueAnimator.AnimatorUpdateListener updateListener
                = new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator valueAnimator) {
                Float newValue = (Float) valueAnimator.getAnimatedValue();
                text.setScaleX(newValue);
                text.setScaleY(newValue);
            }
        };

        ValueAnimator disappear = ValueAnimator.ofFloat(1f, 0f);
        disappear.setDuration(speed);
        disappear.addUpdateListener(updateListener);
        disappear.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
                text.setText(label);

                // Hacky Hack
                if (label.equals(LABEL_DEATH)) {
                    Sound.Fail();
                } else if (label.equals(LABEL_EMPTY)) {
                    Sound.Blip();
                }
            }
        });

        ValueAnimator appear = ValueAnimator.ofFloat(0f, 1f);
        appear.setDuration(speed);
        appear.addUpdateListener(updateListener);

        set.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
                AnimatorSet animSet = animQueue.poll();
                if (animSet != null) {
                    animSet.start();
                }
            }
        });

        set.play(appear).after(disappear);
        return set;
    }

    public boolean isAvailable() {
        return value == Value.EMPTY;
    }
}
