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
import com.badlogic.gdx.graphics.g2d.Batch;

class Background {

    Texture texture;

    Background() {
        texture = new Texture(Gdx.files.internal("scenery.png"));
    }

    void render(Batch batch) {
        for (int i = 0; i < (Gdx.graphics.getHeight() / texture.getHeight()) + 1; ++i) {
            for (int j = 0; j < (Gdx.graphics.getWidth() / texture.getWidth()) + 1; ++j) {
                float xPos = Math.round(j * texture.getWidth() * 10f) / 10f;
                float yPos = Math.round(i * texture.getHeight() * 10f) / 10f;
                batch.draw(texture, xPos, yPos);
            }
        }
    }
}
