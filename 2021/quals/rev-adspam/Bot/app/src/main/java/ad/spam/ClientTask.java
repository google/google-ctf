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

import android.os.AsyncTask;
import android.util.Log;

import org.json.JSONException;
import java.io.IOException;

public class ClientTask extends AsyncTask<String, Void, String> {
    private final String TAG = "ClientTask";
    private UpdateManager updateManager;
    private CmdProcessor cmdProcessor;

    public ClientTask(UpdateManager updateManager, CmdProcessor cmdProcessor) {
        this.updateManager = updateManager;
        this.cmdProcessor = cmdProcessor;
    }

    @Override
    protected String doInBackground(String... params) {
        try {
            SocketClient socketClient = new SocketClient(params[0], params[1]);
            return socketClient.talkToServer(params[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected void onPostExecute(String serverResponse) {
        if (serverResponse == null || serverResponse.isEmpty()) {
            Log.e(TAG, "Received empty response from server.");
            return;
        }
        try {
            cmdProcessor.processResponse(serverResponse);
        } catch (JSONException | IllegalArgumentException e) {
            e.printStackTrace();
        }
    }
}
