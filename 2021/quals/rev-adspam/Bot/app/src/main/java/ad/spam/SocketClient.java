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

import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SocketClient {
    private final String TAG = "SocketClient";
    private final int BUFFER_SIZE = 4096;
    BufferedReader in;
    PrintWriter out;

    public SocketClient(String ip, String port) throws IOException {
        Socket socket = new Socket(ip, Integer.parseInt(port));
        OutputStream outputStream = socket.getOutputStream();

        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(outputStream, true);
    }

    private String recvUntil(String token) throws IOException {
        char[] buffer = new char[BUFFER_SIZE];
        StringBuilder data = new StringBuilder();
        while(!String.valueOf(buffer).contains(token)) {
            int n = in.read(buffer);
            if (n == 0) {
                break;
            }
            data.append(String.valueOf(buffer));
        }
        Log.d(TAG, data.toString().trim());
        return data.toString();
    }

    public String talkToServer(String data) throws IOException {
        if (in.readLine().contains("== proof-of-work: enabled ==")) {
            String srvData = recvUntil("Solution? ");
            Pattern pattern = Pattern.compile("solve (s\\..+)$", Pattern.MULTILINE);
            Matcher matcher = pattern.matcher(srvData);
            if (matcher.find()) {
                String challenge = matcher.group(1);
                if (challenge != null) {
                    String solution = new PowSolver().solveChallenge(challenge);
                    out.println(solution);
                } else {
                    Log.e(TAG, "Couldn't extract proof-of-work string.");
                    return null;
                }
            } else {
                Log.e(TAG, "Couldn't parse proof-of-work challenge.");
                return null;
            }
            if (!in.readLine().equals("Correct")) {
                Log.e(TAG, "Couldn't solve proof-of-work.");
                return null;
            }
        }
        out.println(data);
        String response = in.readLine();
        in.close();
        out.close();
        return response;
    }
}
