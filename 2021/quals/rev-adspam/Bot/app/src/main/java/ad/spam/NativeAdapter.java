// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ad.spam;

public class NativeAdapter {

    static {
        System.loadLibrary("native-lib");
    }

    public static native String transform(byte[] bytes);
    public static native boolean oktorun();
    public static native byte[] encrypt(byte[] data);
    public static native byte[] decrypt(byte[] data);
    public static native byte[] declicstr(byte[] data);
}
