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

package com.example.balid.sandbox;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.DeflaterOutputStream;

public class MapCompressor {
    public static void main(String[] args) throws Exception {

        int width = 244;
        int height = 46;

        byte[] rawData = new byte[width * height];

        FileInputStream fis = new FileInputStream(new File("/tmp/level.txt"));
        int read = fis.read(rawData);
        if (read != width * height) {
            System.out.println("Fail " + read);
        }
        fis.close();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DeflaterOutputStream dos = new DeflaterOutputStream(baos);
        dos.write(rawData);
        dos.flush();
        dos.close();

        FileOutputStream fos = new FileOutputStream(new File("/tmp/level.bin"));
        fos.write(baos.toByteArray());
        fos.flush();
        fos.close();
    }
}
