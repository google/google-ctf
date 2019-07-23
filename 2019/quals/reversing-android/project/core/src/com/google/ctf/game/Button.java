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

import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

import java.util.ArrayList;
import java.util.List;

class Button {

    private int x;
    private int y;
    private int size;
    private List<TextureRegion> textures;
    boolean touched;
    int id;

    Button(TextureRegion texture, int x, int y, int size) {
        this.textures = new ArrayList<TextureRegion>();
        this.textures.add(texture);
        this.x = x;
        this.y = y;
        this.size = size;
        this.touched = false;
    }

    Button(List<TextureRegion> textures, int x, int y, int size, int id) {
        this.textures = textures;
        this.x = x;
        this.y = y;
        this.size = size;
        this.touched = false;
        this.id = id;
    }

    void render(Batch batch) {
        for (TextureRegion texture : textures) {
            batch.draw(texture, x, y);
        }
    }

    void processTouch(int screenX, int screenY) {
        if (screenX >= x && screenX <= x + size) {
            if (screenY >= y && screenY <= y + size) {
                touched = true;
            }
        }
    }
}
