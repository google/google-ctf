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
import com.badlogic.gdx.files.FileHandle;
import com.badlogic.gdx.graphics.Texture;
import com.badlogic.gdx.graphics.g2d.Batch;
import com.badlogic.gdx.graphics.g2d.TextureRegion;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;

class Map {
    private static final int FRAME_COLS = 16, FRAME_ROWS = 8;
    static final int TILE_SIZE = 128;
    static final int MAX_EGGS = 15;

    /*
    * Diagonal tile map:
    *
    *   lLaA
    *  k    b
    * J      c
    * j      C
    * I      d
    * i      D
    *  h    e
    *   GgFf
    * */

    enum Tile {
        AIR,
        GROUND,
        DIAGONAL_A,
        DIAGONAL_AA,
        DIAGONAL_B,
        DIAGONAL_C,
        DIAGONAL_CC,
        DIAGONAL_D,
        DIAGONAL_DD,
        DIAGONAL_E,
        DIAGONAL_F,
        DIAGONAL_FF,
        DIAGONAL_G,
        DIAGONAL_GG,
        DIAGONAL_H,
        DIAGONAL_I,
        DIAGONAL_II,
        DIAGONAL_J,
        DIAGONAL_JJ,
        DIAGONAL_K,
        DIAGONAL_L,
        DIAGONAL_LL,
        COMPUTER,
        EGG_HOLDER,
        EGG_0,
        EGG_1,
        EGG_2,
        EGG_3,
        EGG_4,
        EGG_5,
        EGG_6,
        EGG_7,
        EGG_8,
        EGG_9,
        EGG_10,
        EGG_11,
        EGG_12,
        EGG_13,
        EGG_14,
        EGG_15,
        BACKGROUND,
        PORTAL,
        FLAG_0,
        FLAG_1,
        FLAG_2,
        FLAG_3,
        FLAG_4,
        FLAG_5,
        FLAG_6,
        FLAG_7,
        FLAG_8,
        FLAG_9,
        FLAG_10,
        FLAG_11,
        FLAG_12,
        FLAG_13,
        FLAG_14,
        FLAG_15,
    }

    static final Tile[] EGG_TILES = new Tile[] {
        Tile.EGG_0, Tile.EGG_1, Tile.EGG_2, Tile.EGG_3,
        Tile.EGG_4, Tile.EGG_5, Tile.EGG_6, Tile.EGG_7,
        Tile.EGG_8, Tile.EGG_9, Tile.EGG_10, Tile.EGG_11,
        Tile.EGG_12, Tile.EGG_13, Tile.EGG_14, Tile.EGG_15};
    static final Tile[] FLAG_TILES = new Tile[] {
            Tile.FLAG_0, Tile.FLAG_1, Tile.FLAG_2, Tile.FLAG_3,
            Tile.FLAG_4, Tile.FLAG_5, Tile.FLAG_6, Tile.FLAG_7,
            Tile.FLAG_8, Tile.FLAG_9, Tile.FLAG_10, Tile.FLAG_11,
            Tile.FLAG_12, Tile.FLAG_13, Tile.FLAG_14, Tile.FLAG_15};


    // private int width = 98;
    private int width = 190;
    private int height = 46;

    private TextureRegion[][] textures;

    Tile[][] tiles;
    // Maps egg holder IDs to tile coordinates
    private int[][] holderToTile;
    // (Inefficiently) maps tiles to holder IDs.
    int[][] tileToHolder;
    // Eggs ordered by their holder IDs (0 - 31).
    private Tile[] eggs;
    private List<Integer> activeEggs;

    int tileWidth, tileHeight;
    private int eggHolderCount;
    private int levelNumber;

    ToasterInterface toaster;

    Map(ToasterInterface toaster) throws IOException {
        this.toaster = toaster;

        Texture texture = new Texture(Gdx.files.internal("tileset.png"));

        tileWidth = texture.getWidth() / FRAME_COLS;
        tileHeight = texture.getHeight() / FRAME_ROWS;
        textures = TextureRegion.split(texture, tileWidth, tileHeight);
        eggHolderCount = 0;

        levelNumber = 1;
        loadLevel(levelNumber);
    }

    private void loadLevel(int id) throws IOException {
        FileHandle levelFile = Gdx.files.internal(String.format("level%d.bin", id));
        byte[] levelData = levelFile.readBytes();
        loadLevelBinary(levelData);
    }

    private void loadLevelBinary(byte[] levelData) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(levelData);
        InflaterInputStream iis = new InflaterInputStream(bis);

        byte[] tileBuffer = new byte[width * height];
        if (iis.read(tileBuffer) != width * height) {
            throw new IOException();
        }

        tiles = new Tile[height][];
        tileToHolder = new int[height][];
        holderToTile = new int[32][];
        for (int i = 0; i < height; ++i) {
            tiles[i] = new Tile[width];
            tileToHolder[i] = new int[width];
            for (int j = 0; j < width; ++j) {
                tileToHolder[i][j] = -1;
            }
        }

        eggHolderCount = 0;
        for (int i = 0; i < height; ++i) {
            for (int j = 0; j < width; ++j) {
                Tile tile = getTile(tileBuffer[i * width + j]);
                tiles[height - i - 1][j] = tile;
                if (tile == Tile.EGG_HOLDER) {
                    tileToHolder[height - i - 1][j] = eggHolderCount;
                    holderToTile[eggHolderCount] = new int[] {j, height - i - 1};
                    eggHolderCount++;
                }

            }
        }

        eggs = new Tile[eggHolderCount];
        for (int i = 0; i < eggs.length; ++i) {
            eggs[i] = Tile.EGG_0;
        }
        activeEggs = new ArrayList<Integer>();
    }

    void nextLevel(Bird bird) {
        levelNumber++;
        try {
            loadLevel(levelNumber);
        } catch (IOException ignored) {
        }

        // TODO(never): Allow setting starting position based on map.
        bird.position.x = 11f * TILE_SIZE;
        bird.position.y = 20f * TILE_SIZE;
    }

    void render(Batch batch, Body bird) {
        int tileX = (int) bird.position.x / tileWidth;
        int tileY = (int) bird.position.y / tileHeight;
        for (int i = Math.max(tileY - 12, 0); i < Math.min(tileY + 12, height); ++i) {
            for (int j = Math.max(tileX - 16, 0); j < Math.min(tileX + 16, width); ++j) {
                TextureRegion texture = getTexture(tiles[i][j]);
                if (texture == null) {
                    continue;
                }
                float xPos = Math.round(j * TILE_SIZE * 10f) / 10f;
                float yPos = Math.round(i * TILE_SIZE * 10f) / 10f;

                if (tileToHolder[i][j] != -1) {
                    TextureRegion eggTexture = getTexture(eggs[tileToHolder[i][j]]);
                    if (eggTexture == null) {
                        continue;
                    }
                    batch.draw(eggTexture, xPos, yPos);
                }
                batch.draw(texture, xPos, yPos);
            }
        }
    }

    void assignEgg(int holderId, int eggId) {
        eggs[holderId] = EGG_TILES[eggId];

        int indexToRemove = -1;
        for (int i = 0; i < activeEggs.size(); ++i) {
            if (activeEggs.get(i) == holderId) {
                if (eggId != 0) {
                    // Update, do nothing
                    return;
                } else {
                    // Remove deleted egg from active list
                    indexToRemove = i;
                }
            }
        }
        if (indexToRemove != -1) {
            activeEggs.remove(indexToRemove);
        }
        if (eggId == 0) {
            return;
        }
        activeEggs.add(holderId);
        if (activeEggs.size() > MAX_EGGS) {
            int oldHolderId = activeEggs.remove(0);
            eggs[oldHolderId] = Tile.EGG_0;
        }
    }

    void checkKey() {
        byte[] key = new byte[32];
        for (int i = 0; i < eggs.length; ++i) {
            for (int j = 0; j < EGG_TILES.length; ++j) {
                if (eggs[i] == EGG_TILES[j]) {
                    key[i] = (byte) j;
                }
            }
        }
        byte[] flagLevel = new Checker().checkKey(key);
        if (flagLevel != null) {
            try {
                levelNumber = 0;
                loadLevelBinary(flagLevel);
            } catch (IOException ignored) {
            }
        } else {
            toaster.toast("Close, but no cigar.");
        }
    }

    private Tile getTile(byte tileId) {
        switch (tileId) {
            case '1':
                return Tile.GROUND;
            case '2':
                return Tile.EGG_HOLDER;
            case '3':
                return Tile.COMPUTER;
            case 'x':
                return Tile.BACKGROUND;
            case '4':
                return Tile.PORTAL;
            case 'a':
                return Tile.DIAGONAL_A;
            case 'A':
                return Tile.DIAGONAL_AA;
            case 'b':
                return Tile.DIAGONAL_B;
            case 'c':
                return Tile.DIAGONAL_C;
            case 'C':
                return Tile.DIAGONAL_CC;
            case 'd':
                return Tile.DIAGONAL_D;
            case 'D':
                return Tile.DIAGONAL_DD;
            case 'e':
                return Tile.DIAGONAL_E;
            case 'f':
                return Tile.DIAGONAL_F;
            case 'F':
                return Tile.DIAGONAL_FF;
            case 'g':
                return Tile.DIAGONAL_G;
            case 'G':
                return Tile.DIAGONAL_GG;
            case 'h':
                return Tile.DIAGONAL_H;
            case 'i':
                return Tile.DIAGONAL_I;
            case 'I':
                return Tile.DIAGONAL_II;
            case 'j':
                return Tile.DIAGONAL_J;
            case 'J':
                return Tile.DIAGONAL_JJ;
            case 'k':
                return Tile.DIAGONAL_K;
            case 'l':
                return Tile.DIAGONAL_L;
            case 'L':
                return Tile.DIAGONAL_LL;
            case 'm':
                return Tile.FLAG_0;
            case 'M':
                return Tile.FLAG_1;
            case 'n':
                return Tile.FLAG_2;
            case 'N':
                return Tile.FLAG_3;
            case 'o':
                return Tile.FLAG_4;
            case 'O':
                return Tile.FLAG_5;
            case 'p':
                return Tile.FLAG_6;
            case 'P':
                return Tile.FLAG_7;
            case 'q':
                return Tile.FLAG_8;
            case 'Q':
                return Tile.FLAG_9;
            case 'r':
                return Tile.FLAG_10;
            case 'R':
                return Tile.FLAG_11;
            case 's':
                return Tile.FLAG_12;
            case 'S':
                return Tile.FLAG_13;
            case 't':
                return Tile.FLAG_14;
            case 'T':
                return Tile.FLAG_15;
            case '0':
            default:
                break;
        }
        return Tile.AIR;
    }

    TextureRegion getTexture(Tile tile) {
        switch (tile) {
            case AIR:
                return null;
            case COMPUTER:
                return textures[5][1];
            case EGG_HOLDER:
                return textures[4][1];
            case BACKGROUND:
                return textures[7][1];
            case PORTAL:
                return textures[3][1];
            case DIAGONAL_A:
                return textures[0][4];
            case DIAGONAL_AA:
                return textures[0][5];
            case DIAGONAL_B:
                return textures[1][6];
            case DIAGONAL_C:
                return textures[2][7];
            case DIAGONAL_CC:
                return textures[3][7];
            case DIAGONAL_D:
                return textures[4][7];
            case DIAGONAL_DD:
                return textures[5][7];
            case DIAGONAL_E:
                return textures[6][6];
            case DIAGONAL_F:
                return textures[7][5];
            case DIAGONAL_FF:
                return textures[7][4];
            case DIAGONAL_G:
                return textures[7][3];
            case DIAGONAL_GG:
                return textures[7][2];
            case DIAGONAL_H:
                return textures[6][1];
            case DIAGONAL_I:
                return textures[5][0];
            case DIAGONAL_II:
                return textures[4][0];
            case DIAGONAL_J:
                return textures[3][0];
            case DIAGONAL_JJ:
                return textures[2][0];
            case DIAGONAL_K:
                return textures[1][1];
            case DIAGONAL_L:
                return textures[0][2];
            case DIAGONAL_LL:
                return textures[0][3];
            case EGG_0:
                return textures[2][2];
            case EGG_1:
                return textures[2][3];
            case EGG_2:
                return textures[2][4];
            case EGG_3:
                return textures[2][5];
            case EGG_4:
                return textures[3][2];
            case EGG_5:
                return textures[3][3];
            case EGG_6:
                return textures[3][4];
            case EGG_7:
                return textures[3][5];
            case EGG_8:
                return textures[4][2];
            case EGG_9:
                return textures[4][3];
            case EGG_10:
                return textures[4][4];
            case EGG_11:
                return textures[4][5];
            case EGG_12:
                return textures[5][2];
            case EGG_13:
                return textures[5][3];
            case EGG_14:
                return textures[5][4];
            case EGG_15:
                return textures[5][5];
            case FLAG_0:
                return textures[4][8];
            case FLAG_1:
                return textures[4][9];
            case FLAG_2:
                return textures[4][10];
            case FLAG_3:
                return textures[4][11];
            case FLAG_4:
                return textures[5][8];
            case FLAG_5:
                return textures[5][9];
            case FLAG_6:
                return textures[5][10];
            case FLAG_7:
                return textures[5][11];
            case FLAG_8:
                return textures[6][8];
            case FLAG_9:
                return textures[6][9];
            case FLAG_10:
                return textures[6][10];
            case FLAG_11:
                return textures[6][11];
            case FLAG_12:
                return textures[7][8];
            case FLAG_13:
                return textures[7][9];
            case FLAG_14:
                return textures[7][10];
            case FLAG_15:
                return textures[7][11];
            case GROUND:
            default:
                break;
        }
        return textures[0][0];
    }
}
