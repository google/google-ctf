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

import android.animation.AnimatorSet;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Random;

public class GameActivity extends AppCompatActivity implements View.OnClickListener {
    static final int GRID_SIZE = 3;
    static final int SPEED_FAST = 25;

    Cell cells[][];
    Queue<AnimatorSet> animQueue;
    Object random;
    int round;
    boolean gameIsOver;
    byte seed[];

    // For testing
    /*
    static final int TOTAL_ROUNDS = 3;
    byte flag[] = new byte[] {41, -70, 69, 47, -19, 119, -7, -102, 46, 58, -7, -33, 7, -82, -67, 12,
            -75, -99, 13, -106, 64, -4, 99, -29, -53, 53, 9, 79, -18, 99, 23, -113};
    */

    // For release
    static final int TOTAL_ROUNDS = 1000000;
    byte flag[] = new byte[] {-61, 15, 25, -115, -46, -11, 65, -3, 34, 93, -39, 98, 123, 17, 42,
            -121, 60, 40, -60, -112, 77, 111, 34, 14, -31, -4, -7, 66, 116, 108, 114, -122};

    public GameActivity() {
        cells = new Cell[3][3];
        animQueue = new LinkedList<>();

        // Easter egg
        long S1 = 0x54686520L;
        long S2 = 0x6f6e6c79L;
        long S3 = 0x2077696eL;
        long S4 = 0x6e696e67L;
        long S5 = 0x206d6f76L;
        long S6 = 0x65206973L;
        long S7 = 0x206e6f74L;
        long S8 = 0x20746f20L;
        long S9 = 0x706c6179L;

        // random = new Random(
        random = N._(N._RANDOM, N._CTOR_RANDOM,
                S1 + S2 + S3 + S4 + S5 + S6 + S7 + S8 + S9);  // 10898162276

        seed = new byte[32];
        // random.nextBytes(seed);
        N._(N._RANDOM, N._NEXT_BYTES, random, seed);

        /*
        String seedStr = "";
        for (int i = 0; i < 32; ++i) {
            seedStr += (seed[i] & 0xFF) + ", ";
        }
        Log.d("seed", seedStr);
        */

        round = 0;
        gameIsOver = false;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_game);

        LinearLayout gridLayout = findViewById(R.id.rows);
        for (int i = 0; i < GRID_SIZE; ++i) {
            LinearLayout rowLayout = new LinearLayout(getApplicationContext());
            for (int j = 0; j < GRID_SIZE; ++j) {
                Cell cell = new Cell(getApplicationContext(), animQueue);
                rowLayout.addView(cell);

                cells[j][i] = cell;
                cell.setOnClickListener(this);
            }
            gridLayout.addView(rowLayout);
        }
    }

    void animate() {
        AnimatorSet anim = animQueue.poll();
        if (anim != null) {
            anim.start();
        }
    }

    List<Cell> getAvailableCells() {
        List<Cell> availableCells = new ArrayList<>();
        for (int i = 0; i < GRID_SIZE; ++i) {
            for (int j = 0; j < GRID_SIZE; ++j) {
                if (cells[j][i].isAvailable()) {
                    availableCells.add(cells[j][i]);
                }
            }
        }
        return availableCells;
    }

    Cell pickCell(List<Cell> available) {
        int index = ((Random) random).nextInt(available.size());
        return available.get(index);
    }

    boolean checkWinner(Cell.Value player) {
        int rowCount[] = new int[]{0, 0, 0};
        int colCount[] = new int[]{0, 0, 0};
        int diagCount[] = new int[]{0, 0};
        for (int i = 0; i < GRID_SIZE; ++i) {
            for (int j = 0; j < GRID_SIZE; ++j) {
                Cell cell = cells[j][i];
                if (cell.value == player) {
                    rowCount[i]++;
                    colCount[j]++;

                    if (i == j) {
                        diagCount[0]++;
                    }
                    if (i + j == GRID_SIZE - 1) {
                        diagCount[1]++;
                    }
                }
            }
        }
        for (int count : rowCount) {
            if (count >= GRID_SIZE) { return true; }
        }
        for (int count : colCount) {
            if (count >= GRID_SIZE) { return true; }
        }
        for (int count : diagCount) {
            if (count >= GRID_SIZE) { return true; }
        }
        return false;
    }

    void getFlag() {
        // Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        Object cipher = N._(N._CIPHER, N._GET_INSTANCE, N._AES_ECB_NOPADDING);

        // SecretKeySpec keySpec = new SecretKeySpec(seed, "AES");
        Object keySpec = N._(N._SECRET_KEY_SPEC, N._CTOR_SECRETKEYSPEC, seed, N._AES);

        // cipher.init(Cipher.DECRYPT_MODE, keySpec);
        N._(N._CIPHER, N._INIT, cipher, 2, keySpec);

        // byte[] decrypted = cipher.doFinal(flag);
        byte[] decrypted = (byte[]) N._(N._CIPHER, N._DO_FINAL, cipher, flag);

        TextView scoreText = findViewById(R.id.score);
        scoreText.setText(new String(decrypted));

        gameOver();
    }

    void nextRound() {
        for (int i = 0; i < GRID_SIZE; ++i) {
            for (int j = 0; j < GRID_SIZE; ++j) {
                Cell cell = cells[j][i];
                cell.setValue(Cell.Value.EMPTY, SPEED_FAST);
            }
        }
        animate();

        round++;

        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        Object md = N._(N._MESSAGE_DIGEST, N._GET_INSTANCE2, N._SHA256);

        // md.update(seed);
        N._(N._MESSAGE_DIGEST, N._UPDATE, md, seed);

        // seed = md.digest();
        seed = (byte[]) N._(N._MESSAGE_DIGEST, N._DIGEST, md);

        if (round == TOTAL_ROUNDS) {
            getFlag();
        } else {
            TextView scoreText = findViewById(R.id.score);
            scoreText.setText(String.format("%d / %d", round, TOTAL_ROUNDS));
        }
    }

    void gameOver() {
        for (int i = 0; i < GRID_SIZE; ++i) {
            for (int j = 0; j < GRID_SIZE; ++j) {
                Cell cell = cells[j][i];
                cell.setValue(Cell.Value.DEATH);
            }
        }
        round = 0;
        gameIsOver = true;
        animate();
    }

    @Override
    public void onClick(View view) {
        if (gameIsOver) {
            return;
        }
        if (!animQueue.isEmpty()) {
            return;
        }

        Cell cell = (Cell) view;
        if (!cell.isAvailable()) {
            Sound.Fail();
            return;
        }

        Sound.Blip();

        cell.setValue(Cell.Value.X);
        if (checkWinner(Cell.Value.X)) {
            nextRound();
            return;
        }

        List<Cell> available = getAvailableCells();
        if (available.isEmpty()) {
            nextRound();
            return;
        }

        Cell cpuCell = pickCell(available);
        cpuCell.setValue(Cell.Value.O);
        if (checkWinner(Cell.Value.O)) {
            gameOver();
            return;
        }

        animate();
    }
}
