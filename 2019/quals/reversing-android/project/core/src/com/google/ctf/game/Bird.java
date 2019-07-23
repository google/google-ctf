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
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Animation;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;
import com.badlogic.gdx.math.Vector2;

class Bird extends Body {
    private static final int FRAME_COLS = 8, FRAME_ROWS = 1;
    private Animation<TextureRegion> walkAnimation;
    private TextureRegion[] walkFrames;

    Bird(Vector2 position) {
        super(position);

        Texture spriteSheet = new Texture(Gdx.files.internal("bird.png"));
        int width = spriteSheet.getWidth() / FRAME_COLS;
        int height = spriteSheet.getHeight() / FRAME_ROWS;
        // Set fake height
        this.setSize(new Vector2(width, height / 2));

        TextureRegion[][] textureRegions = TextureRegion.split(spriteSheet, width, height);
        walkFrames = new TextureRegion[5];
        System.arraycopy(textureRegions[0], 0, walkFrames, 0, walkFrames.length);
        walkAnimation = new Animation<TextureRegion>(0.075f, walkFrames);
    }

    void render(Batch batch, float time) {
        float dt = time;
        if (!this.moving) {
            dt = 0f;
        }

        TextureRegion currentFrame;
        if (this.jumping) {
            currentFrame = walkFrames[2];
        } else {
            currentFrame = walkAnimation.getKeyFrame(dt, true);
        }

        currentFrame.flip(!this.facingRight, false);
        batch.draw(currentFrame, position.x, position.y);
        if (!this.facingRight) {
            currentFrame.flip(true, false);
        }
    }
}
