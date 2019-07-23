// Copyright 2019 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.ctf.game;

import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.Input;
import com.badlogic.gdx.InputAdapter;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

import java.util.ArrayList;
import java.util.List;

class UI extends InputAdapter {

    private static final int UI_COLS = 4, UI_ROWS = 2;
    private static final int PADDING = 16;

    private Button leftButton, rightButton, jumpButton, actionButton;
    private List<Button> buttons;
    private List<Button> eggButtons;
    private boolean eggMenuShown;
    private int activeEggHolder;
    private Map map;

    UI(Map map) {
        this.map = map;

        Texture texture = new Texture(Gdx.files.internal("ui.png"));
        int buttonWidth = texture.getWidth() / UI_COLS;
        int buttonHeight = texture.getHeight() / UI_ROWS;
        TextureRegion[][] textures = TextureRegion.split(texture, buttonWidth, buttonHeight);

        int W = Gdx.graphics.getWidth();
        int H = Gdx.graphics.getHeight();

        buttons = new ArrayList<Button>();
        leftButton = new Button(textures[1][1], PADDING, PADDING, buttonWidth);
        buttons.add(leftButton);
        rightButton = new Button(textures[1][0],
                buttonWidth + PADDING * 2, PADDING, buttonWidth);
        buttons.add(rightButton);
        jumpButton = new Button(textures[1][2],
                W - PADDING - buttonWidth, PADDING, buttonWidth);
        buttons.add(jumpButton);
        actionButton = new Button(textures[1][3],
                W - PADDING - buttonWidth, buttonHeight + PADDING * 2, buttonWidth);
        buttons.add(actionButton);

        eggButtons = new ArrayList<Button>();

        for (int i = 0; i < Map.EGG_TILES.length; ++i) {
            int x = (i % 4) * buttonWidth;
            int y = (i / 4) * buttonHeight;
            List<TextureRegion> eggButtonTextures = new ArrayList<TextureRegion>();
            eggButtonTextures.add(textures[0][0]);
            eggButtonTextures.add(map.getTexture(Map.EGG_TILES[i]));
            eggButtons.add(new Button(eggButtonTextures,
                    W / 2 - buttonWidth * 2 + x,
                    H / 2 - buttonHeight * 2 + y, buttonWidth, i));
        }

        eggMenuShown = false;
        activeEggHolder = 0;
    }

    void render(Batch batch) {
        for (Button b : buttons) {
            b.render(batch);
        }

        if (eggMenuShown) {
            for (Button b : eggButtons) {
                b.render(batch);
            }
        }
    }

    void processTouches() {
        for (Button b : buttons) {
            b.touched = false;
        }
        for (Button b : eggButtons) {
            b.touched = false;
        }
        // 20 is the maximum number of touch points.
        for (int i = 0; i < 20; i++) {
            if (Gdx.input.isTouched(i)) {
                int x = Gdx.input.getX(i);
                int y = Gdx.graphics.getHeight() - Gdx.input.getY(i);

                if (!eggMenuShown) {
                    for (Button b : buttons) {
                        b.processTouch(x, y);
                    }
                } else {
                    for (Button b : eggButtons) {
                        b.processTouch(x, y);
                    }
                }
            }
        }
    }

    void processEggMenu() {
        if (!eggMenuShown) {
            return;
        }
        for (Button b : eggButtons) {
            if (b.touched) {
                map.assignEgg(activeEggHolder, b.id);
                hideEggMenu();
                return;
            }
        }
    }

    boolean leftPressed() {
        return !eggMenuShown && (Gdx.input.isKeyPressed(Input.Keys.LEFT) || leftButton.touched);
    }

    boolean rightPressed() {
        return !eggMenuShown && (Gdx.input.isKeyPressed(Input.Keys.RIGHT) || rightButton.touched);
    }

    boolean jumpPressed() {
        return !eggMenuShown &&
                (Gdx.input.isKeyJustPressed(Input.Keys.SPACE) || jumpButton.touched);
    }

    boolean actionPressed() {
        return Gdx.input.isKeyJustPressed(Input.Keys.X) || actionButton.touched;
    }

    void showEggMenu(int holderId) {
        eggMenuShown = true;
        activeEggHolder = holderId;
    }

    private void hideEggMenu() {
        eggMenuShown = false;
    }
}
