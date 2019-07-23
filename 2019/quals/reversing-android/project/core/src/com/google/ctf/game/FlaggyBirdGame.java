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

import com.badlogic.gdx.ApplicationAdapter;
import com.badlogic.gdx.Gdx;
import com.badlogic.gdx.graphics.GL20;
import com.badlogic.gdx.graphics.OrthographicCamera;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.SpriteBatch;
import com.badlogic.gdx.math.Vector2;

import java.io.IOException;

public class FlaggyBirdGame extends ApplicationAdapter {

    static {
        System.loadLibrary("rary");
    }

    private static final float CAMERA_SIZE = 2600f;
    private static final float CAMERA_OFFSET = 300f;

    private Background background;
    private Batch batch;
    private Bird bird;
    private Map map;
    private OrthographicCamera camera;
    private OrthographicCamera uiCamera;
    private Physics physics;
    private UI ui;

    private float time = 0f;
    private float timeAcc = 0f;

    ToasterInterface toaster;

    public FlaggyBirdGame(ToasterInterface toaster) {
        this.toaster = toaster;
    }

    @Override
    public void create () {
        batch = new SpriteBatch();
        batch.enableBlending();

        background = new Background();
        try {
            map = new Map(toaster);
        } catch (IOException e) {
            e.printStackTrace();
            Gdx.app.exit();
        }
        ui = new UI(map);
        bird = new Bird(new Vector2(11f * Map.TILE_SIZE, 20 * Map.TILE_SIZE));
        physics = new Physics(bird, map, ui);

        float w = Gdx.graphics.getWidth();
        float h = Gdx.graphics.getHeight();
        camera = new OrthographicCamera(CAMERA_SIZE, CAMERA_SIZE * (h / w));
        uiCamera = new OrthographicCamera(Gdx.graphics.getWidth(), Gdx.graphics.getHeight());
        uiCamera.position.x = w / 2;
        uiCamera.position.y = h / 2;
        uiCamera.update();
    }

    @Override
    public void render () {
        float dt = Gdx.graphics.getRawDeltaTime();
        time += dt;
        timeAcc += dt;
        float timeStep = 1 / 60f;
        while (timeAcc >= timeStep) {
            ui.processTouches();
            ui.processEggMenu();
            physics.simulate();
            timeAcc -= timeStep;
        }

        camera.position.set(bird.position, 0f);
        camera.position.y += CAMERA_OFFSET;
        camera.update();

        Gdx.gl.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        Gdx.gl.glClear(GL20.GL_COLOR_BUFFER_BIT |
                GL20.GL_DEPTH_BUFFER_BIT |
                (Gdx.graphics.getBufferFormat().coverageSampling ?
                        GL20.GL_COVERAGE_BUFFER_BIT_NV : 0));

        batch.begin();

        batch.setProjectionMatrix(uiCamera.combined);
        background.render(batch);

        batch.setProjectionMatrix(camera.combined);
        map.render(batch, bird);
        bird.render(batch, time);

        batch.setProjectionMatrix(uiCamera.combined);
        ui.render(batch);

        batch.end();
    }

    @Override
    public void dispose () {
        batch.dispose();
    }

    @Override
    public void resize(int width, int height) {
        camera.viewportWidth = CAMERA_SIZE;
        uiCamera.viewportWidth = CAMERA_SIZE;
        camera.viewportHeight = CAMERA_SIZE * height / width;
        uiCamera.viewportHeight = CAMERA_SIZE * height / width;
    }
}
