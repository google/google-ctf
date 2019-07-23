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


class Physics {

    private static final float GRAVITY = .9f;
    // private static final float JUMP_STRENGTH = -36f;
     private static final float JUMP_STRENGTH = -28f;
    private static final float MOVEMENT_SPEED = 10f;

    private Map map;
    private UI ui;
    private Bird bird;

    Physics(Bird bird, Map map, UI ui) {
        this.map = map;
        this.ui = ui;
        this.bird = bird;
    }

    private void simulateBody(Body body) {
        body.g += GRAVITY;
        body.position.y -= body.g;

        int yTop = (int) (body.position.y + body.size.y) / map.tileHeight;
        int yMid = (int) (body.position.y + body.size.y / 2) / map.tileHeight;
        int yBottom = (int) body.position.y / map.tileHeight;
        int xLeft = (int) body.position.x / map.tileWidth;
        int xMid = (int) (body.position.x + body.size.x / 2) / map.tileWidth;
        int xRight = (int) (body.position.x + body.size.x) / map.tileWidth;

        boolean bottomCollision = (
                (map.tiles[yBottom][xLeft] == Map.Tile.GROUND
                    && map.tiles[yBottom][xMid] == Map.Tile.GROUND)
                || (map.tiles[yBottom][xRight] == Map.Tile.GROUND
                    && map.tiles[yBottom][xMid] == Map.Tile.GROUND));
        boolean topCollision = (
                (map.tiles[yTop][xLeft] == Map.Tile.GROUND
                        && map.tiles[yTop][xMid] == Map.Tile.GROUND)
                        || (map.tiles[yTop][xRight] == Map.Tile.GROUND
                        && map.tiles[yTop][xMid] == Map.Tile.GROUND));
        boolean leftCollision = map.tiles[yMid][xLeft] == Map.Tile.GROUND;
        boolean rightCollision = map.tiles[yMid][xRight] == Map.Tile.GROUND;

        if (topCollision) {
            body.position.y = map.tileHeight * (yTop - 1);
            body.g = 0f;
        } else if (bottomCollision) {
            body.position.y = map.tileHeight * (yBottom + 1);
            body.g = 0f;
            body.jumping = false;
        }

        if (ui.leftPressed()) {
            if (!leftCollision) {
                body.position.x -= MOVEMENT_SPEED;
                body.facingRight = false;
                body.moving = true;
            }
        } else if (ui.rightPressed()) {
            if (!rightCollision) {
                body.position.x += MOVEMENT_SPEED;
                body.facingRight = true;
                body.moving = true;
            }
        } else {
            body.moving = false;
        }
        if (ui.jumpPressed()) {
            if (!body.jumping) {
                body.g = JUMP_STRENGTH;
                body.jumping = true;
            }
        }
    }

    void simulate() {
        simulateBody(bird);

        if (ui.actionPressed()) {
            int yMid = (int) (bird.position.y + bird.size.y / 2) / map.tileHeight;
            int xLeft = (int) bird.position.x / map.tileWidth;
            int xMid = (int) (bird.position.x + bird.size.x / 2) / map.tileWidth;
            int xRight = (int) (bird.position.x + bird.size.x) / map.tileWidth;

            if (map.tiles[yMid][xLeft] == Map.Tile.COMPUTER
                    || map.tiles[yMid][xMid] == Map.Tile.COMPUTER
                    || map.tiles[yMid][xRight] == Map.Tile.COMPUTER) {
                map.checkKey();
                return;
            }

            if (map.tiles[yMid][xLeft] == Map.Tile.PORTAL
                    || map.tiles[yMid][xMid] == Map.Tile.PORTAL
                    || map.tiles[yMid][xRight] == Map.Tile.PORTAL) {
                map.nextLevel(bird);
                return;
            }

                int holderX;
            if (map.tiles[yMid][xLeft] == Map.Tile.EGG_HOLDER) {
                holderX = xLeft;
            } else if (map.tiles[yMid][xMid] == Map.Tile.EGG_HOLDER) {
                holderX = xMid;
            } else if (map.tiles[yMid][xRight] == Map.Tile.EGG_HOLDER) {
                holderX = xRight;
            } else {
                return;
            }
            int holderId = map.tileToHolder[yMid][holderX];
            ui.showEggMenu(holderId);
        }
    }
}
